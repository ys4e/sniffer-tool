#[macro_use] extern crate log;

mod device;
mod visualizer;
mod decoder;
mod console;
mod settings;

use std::sync::LazyLock;
use std::time::SystemTime;
use tokio::sync::mpsc;
use anyhow::{bail, Result};
use ys_sniffer::{Config, GamePacket};
use crate::visualizer::{GameData, SocketSender, Visualizer};

pub static START_TIME: LazyLock<SystemTime> = LazyLock::new(|| SystemTime::now());

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger.
    if !std::env::var("RUST_LOG").is_ok() {
        unsafe { std::env::set_var("RUST_LOG", "info") }
    }
    pretty_env_logger::init();

    // Select a network device.
    let device_name = device::select()?;

    // Load definitions.
    decoder::load_definitions()?;

    // Start the packet sniffer.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let Ok(hook) = ys_sniffer::sniff_async(Config {
        device_name: Some(device_name),
        ..Default::default()
    }, tx) else {
        bail!("Failed to start packet sniffer");
    };
    info!("Waiting for game packets...");

    // Start the visualizer server.
    Visualizer::load_settings().await;
    let visualizer = Visualizer::new().await?;

    // Spawn processing task for receiving packets.
    let receiver = visualizer.tx.clone();
    tokio::spawn(async move {
        let receiver = receiver.clone();
        while let Some(packet) = rx.recv().await {
            _ = handle(packet, &receiver).await;
        }
    });

    // Spawn websocket task for handling connections.
    visualizer.run().await?;

    // Wait for shutdown.
    console::start()?;
    tokio::signal::ctrl_c().await?;

    // Shutdown the application.
    info!("Stopping sniffer...");
    _ = hook.send(());

    Ok(())
}

/// Handles game packets.
/// Forwards them to a websocket after decoding.
async fn handle(packet: GamePacket, tx: &SocketSender) -> Result<()> {
    // Decode the packet with the given protobuf definitions.
    let (packet_name, data) = decoder::decode(packet.id, &packet.data);

    // Send the packet to the visualizer client(s).
    let packet = GameData::from_existing(packet, packet_name, data);
    tx.send(packet).await?;

    Ok(())
}
