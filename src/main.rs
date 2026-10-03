#[macro_use] extern crate log;

mod device;
mod visualizer;
mod decoder;
mod console;
mod settings;
mod schema;

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::io::{BufWriter, Write};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use anyhow::{bail, Context, Result};
use ys_sniffer::{Config, GamePacket};
use crate::visualizer::{GameData, SocketSender, Visualizer};

pub static START_TIME: LazyLock<SystemTime> = LazyLock::new(|| SystemTime::now());

/// Where decoded packets are written, one JSON object per line (`--log <file>`).
static PACKET_LOG: OnceLock<Mutex<BufWriter<File>>> = OnceLock::new();

const USAGE: &str = "Usage: sniffer-tool [--device <index|name|description>] [--log <file.jsonl>] \
[--ports <22101-22102,...>] [--save <file.pcap>] [--replay <file.pcap>] [--key <private_key.pem>]... [--session-key <key.bin>]...";

/// Command line options.
#[derive(Default)]
struct Options {
    /// Picks the capture device without prompting.
    device: Option<String>,
    /// Writes every decoded packet to this file.
    log: Option<String>,
    /// The game server's UDP ports, e.g. `22101-22102` or `22101,22102`.
    ports: Option<String>,
    /// Writes the raw capture to this file.
    save: Option<String>,
    /// Reads packets from this capture file instead of a device.
    replay: Option<String>,
    /// Extra RSA private keys for the login handshake.
    keys: Vec<String>,
    /// Candidate session keys (4096 raw bytes each).
    session_keys: Vec<String>,
}

impl Options {
    fn parse() -> Result<Self> {
        let mut options = Options::default();
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            let mut value = || args.next().with_context(|| format!("Missing value for '{arg}'.\n{USAGE}"));
            match arg.as_str() {
                "--device" | "-d" => options.device = Some(value()?),
                "--log" | "-l" => options.log = Some(value()?),
                "--ports" | "-p" => options.ports = Some(value()?),
                "--save" | "-s" => options.save = Some(value()?),
                "--replay" | "-r" => options.replay = Some(value()?),
                "--key" | "-k" => options.keys.push(value()?),
                "--session-key" => options.session_keys.push(value()?),
                "--help" | "-h" => {
                    println!("{USAGE}");
                    std::process::exit(0);
                },
                _ => bail!("Unknown argument '{arg}'.\n{USAGE}")
            }
        }

        // Keys dropped into `keys/` are picked up as well:
        // `*.pem` as RSA private keys, `*.bin` as session keys.
        if let Ok(entries) = std::fs::read_dir("keys") {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path.to_string_lossy().into_owned();
                match path.extension().and_then(|extension| extension.to_str()) {
                    Some("pem") => options.keys.push(name),
                    Some("bin") => options.session_keys.push(name),
                    _ => {}
                }
            }
        }

        Ok(options)
    }

    /// Builds the sniffer configuration.
    fn config(&self, device_name: Option<String>) -> Result<Config> {
        let mut config = Config {
            device_name,
            capture_file: self.replay.clone(),
            save_file: self.save.clone(),
            private_keys: self.keys.clone(),
            session_keys: self.session_keys.clone(),
            ..Default::default()
        };

        if let Some(ports) = &self.ports {
            let mut server_port = Vec::new();
            let mut filter = Vec::new();

            for part in ports.split(',').map(str::trim).filter(|part| !part.is_empty()) {
                let (start, end) = part.split_once('-').unwrap_or((part, part));
                let (start, end): (u16, u16) = (start.trim().parse()?, end.trim().parse()?);
                if start > end {
                    bail!("Invalid port range '{part}'.");
                }

                server_port.extend(start..=end);
                filter.push(format!("portrange {start}-{end}"));
            }
            if server_port.is_empty() {
                bail!("No ports given.");
            }

            config.filter = Some(format!("udp and ({})", filter.join(" or ")));
            config.server_port = server_port;
        }

        Ok(config)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger.
    if !std::env::var("RUST_LOG").is_ok() {
        unsafe { std::env::set_var("RUST_LOG", "info") }
    }
    pretty_env_logger::init();

    let options = Options::parse()?;

    // Select a network device, unless replaying a capture.
    let device_name = match options.replay {
        Some(_) => None,
        None => Some(device::select(options.device.as_deref())?)
    };

    // Open the packet log.
    if let Some(path) = &options.log {
        let file = File::create(path).with_context(|| format!("Failed to create '{path}'"))?;
        _ = PACKET_LOG.set(Mutex::new(BufWriter::new(file)));
        info!("Writing decoded packets to '{path}'.");
    }

    // Load definitions.
    decoder::load_definitions()?;

    // Start the packet sniffer.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let config = options.config(device_name)?;
    info!("Capture filter: {}", config.filter.as_deref().unwrap_or("none"));
    if let Some(path) = &config.save_file {
        info!("Saving the raw capture to '{path}'.");
    }
    if !config.private_keys.is_empty() {
        info!("Using {} extra private key(s).", config.private_keys.len());
    }
    if !config.session_keys.is_empty() {
        info!("Using {} candidate session key(s).", config.session_keys.len());
    }
    let Ok(hook) = ys_sniffer::sniff_async(config, tx) else {
        bail!("Failed to start packet sniffer");
    };
    info!("Waiting for game packets...");

    // Start the visualizer server.
    // A replay can do without it (e.g. while a live sniffer holds the port).
    Visualizer::load_settings().await;
    let visualizer = match Visualizer::new().await {
        Ok(visualizer) => Some(visualizer),
        Err(error) if options.replay.is_some() => {
            warn!("Visualizer unavailable ({error}); replaying without it.");
            None
        },
        Err(error) => return Err(error)
    };

    // Spawn processing task for receiving packets.
    let receiver = match &visualizer {
        Some(visualizer) => visualizer.tx.clone(),
        None => {
            let (tx, mut rx) = mpsc::channel(128);
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            std::sync::Arc::new(tx)
        }
    };
    let processing = tokio::spawn(async move {
        let receiver = receiver.clone();
        while let Some(packet) = rx.recv().await {
            _ = handle(packet, &receiver).await;
        }
    });

    // Spawn websocket task for handling connections.
    if let Some(visualizer) = visualizer {
        visualizer.run().await?;
    }

    // A replay ends with its file: the channel closes once the sniffer is done.
    if options.replay.is_some() {
        processing.await?;
        info!("Replay finished.");
        return Ok(());
    }

    // Pick up session keys written to `keys/` while running (e.g. by `tools/keyscan.py`).
    tokio::spawn(watch_session_keys(options.session_keys.clone()));

    // Wait for shutdown.
    console::start()?;
    tokio::signal::ctrl_c().await?;

    // Shutdown the application.
    info!("Stopping sniffer...");
    _ = hook.send(());

    Ok(())
}

/// Hands every new `keys/*.bin` file to the sniffer as a candidate session key.
async fn watch_session_keys(known: Vec<String>) {
    let mut seen: HashMap<PathBuf, SystemTime> = known.into_iter()
        .filter_map(|path| {
            let modified = std::fs::metadata(&path).and_then(|meta| meta.modified()).ok()?;
            Some((PathBuf::from(path), modified))
        })
        .collect();

    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let Ok(entries) = std::fs::read_dir("keys") else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "bin") {
                continue;
            }
            let Ok(modified) = entry.metadata().and_then(|meta| meta.modified()) else {
                continue;
            };
            if seen.get(&path) == Some(&modified) {
                continue;
            }
            seen.insert(path.clone(), modified);

            match std::fs::read(&path).map_err(anyhow::Error::from)
                .and_then(|key| ys_sniffer::add_session_key(&key)) {
                Ok(()) => info!("Added session key '{}'.", path.display()),
                Err(error) => warn!("Failed to add session key '{}': {}", path.display(), error)
            }
        }
    }
}

/// Handles game packets.
/// Forwards them to a websocket after decoding.
async fn handle(packet: GamePacket, tx: &SocketSender) -> Result<()> {
    // Decode the packet with the given protobuf definitions.
    let (packet_name, data) = decoder::decode(packet.id, &packet.data);

    // Send the packet to the visualizer client(s).
    let packet = GameData::from_existing(packet, packet_name, data);
    if let Some(log) = PACKET_LOG.get() {
        write_log(log, &packet);
    }
    tx.send(packet).await?;

    Ok(())
}

/// Appends a packet to the packet log.
fn write_log(log: &Mutex<BufWriter<File>>, packet: &GameData) {
    let data = serde_json::from_str::<serde_json::Value>(&packet.data)
        .unwrap_or_else(|_| serde_json::Value::String(packet.data.clone()));
    let line = serde_json::json!({
        "time": packet.time,
        "source": packet.source,
        "id": packet.packet_id,
        "name": packet.packet_name,
        "length": packet.length,
        "data": data,
    });

    let mut log = log.lock().unwrap();
    if let Err(error) = writeln!(log, "{line}").and_then(|_| log.flush()) {
        warn!("Failed to write packet log: {}", error);
    }
}
