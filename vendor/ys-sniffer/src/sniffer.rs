use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use crossbeam_channel::Receiver;
use pcap::{Activated, Capture, Device, Linktype, Packet};
use anyhow::{anyhow, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, error, info, trace, warn};
use bytes::BufMut;
use lazy_static::lazy_static;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use kcp::Kcp;
use protoshark::Value;
use crate::{cryptography, utils, Config, GamePacket, PacketSource};
use crate::cryptography::{Random, MT19937_64};

const CONNECT_CMD: u32 = 0xFF;
const CONV_CMD: u32 = 0x145;
const DISCONNECT_CMD: u32 = 0x194;

const KEYS: &str = include_str!("../resources/dispatch_keys.txt");
const RSA_KEY: &str = include_str!("../resources/private_key.pem");

lazy_static! {
    /// Load the hardcoded dispatch keys into memory.
    static ref DISPATCH_KEYS: HashMap<u16, Key> = {
        let mut keys = HashMap::new();
        for key in KEYS.lines() {
            let parts = key.split(": ").collect::<Vec<&str>>();
            let (first_byte, key) = match parts.as_slice() {
                [f, s] => (f, s),
                _ => panic!("Invalid key format.")
            };

            let first_byte = first_byte.parse::<u16>().unwrap();
            let mut key_bytes = [0u8; 4096];

            let mut i = 0;
            for byte in (0..key.len() - 1).step_by(2) {
                key_bytes[i] = u8::from_str_radix(&key[byte..byte + 2], 16).unwrap();
                i += 1;
            }

            keys.insert(first_byte, Key::from(&key_bytes));
        }

        keys
    };

    /// Load the RSA private key into memory.
    static ref RSA_PRIVATE_KEY: RsaPrivateKey = RsaPrivateKey::from_pkcs1_pem(RSA_KEY).unwrap();
}

/// Session keys handed over while the sniffer runs (see `add_session_key`).
static NEW_SESSION_KEYS: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

/// How many undecryptable messages are kept for when a session key turns up.
const MAX_PENDING: usize = 100_000;

/// Queues a candidate session key for the processor.
pub fn add_session_key(key: &[u8]) -> Result<()> {
    if key.len() != 4096 {
        return Err(anyhow!("A session key is 4096 bytes, not {}.", key.len()));
    }
    NEW_SESSION_KEYS.lock().unwrap().push(key.to_vec());
    Ok(())
}

/// Loads candidate session keys from files.
fn load_session_keys(paths: &[String]) -> Vec<Key> {
    let mut keys = Vec::new();
    for path in paths {
        match std::fs::read(path) {
            Ok(bytes) if bytes.len() == 4096 => keys.push(Key::from(&bytes)),
            Ok(bytes) => warn!("Ignoring '{}': a session key is 4096 bytes, not {}.", path, bytes.len()),
            Err(error) => warn!("Failed to read the session key '{}': {}", path, error)
        }
    }
    keys
}

/// Loads the RSA private keys to try on the login handshake: the configured ones, then the bundled one.
fn load_private_keys(paths: &[String]) -> Vec<RsaPrivateKey> {
    let mut keys = Vec::new();
    for path in paths {
        let key = utils::read_file(Path::new(path))
            .map_err(|error| anyhow!("{error}"))
            .and_then(|pem| RsaPrivateKey::from_pkcs1_pem(&pem)
                .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&pem))
                .map_err(|error| anyhow!("{error}")));

        match key {
            Ok(key) => keys.push(key),
            Err(error) => warn!("Failed to load the private key '{}': {}", path, error)
        }
    }

    keys.push(RSA_PRIVATE_KEY.clone());
    keys
}

pub trait PacketSender {
    /// Invoked when a packet should be sent.
    fn send(&self, data: GamePacket);
}

/// Runs the actual packet sniffer.
pub fn run(
    config: Config,
    hook: Receiver<()>,
    tx: impl PacketSender + 'static
) -> Result<()> {
    // Create game packet processor.
    let mut processor = Processor::new(&config, tx);

    // Read from a capture file, if one is given.
    if let Some(path) = &config.capture_file {
        trace!("Reading packets from '{}'.", path);
        let capture = Capture::from_file(path)?;
        return capture_loop(&config, &hook, &mut processor, capture);
    }

    // Resolve the device by name.
    let device = if let Some(name) = &config.device_name {
        Device::list()?.into_iter().find(|d| d.name.eq(name))
    } else {
        Device::list()?.first().cloned()
    };

    // Check if the device was found.
    let device = match device {
        Some(device) => device,
        None => {
            return Err(anyhow!("No device (specified or unspecified) found."))
        }
    };

    trace!(
        "Using device {} ({}) for capturing.",
        match device.desc {
            Some(ref desc) => desc,
            None => "No description"
        },
        device.name
    );

    // Initialize the capture device.
    let capture = Capture::from_device(device)?
        .promisc(true)
        .timeout(1)
        .open()?;

    capture_loop(&config, &hook, &mut processor, capture)
}

/// Feeds every captured packet to the processor until shutdown (or the end of a capture file).
fn capture_loop<T: Activated + ?Sized>(
    config: &Config,
    hook: &Receiver<()>,
    processor: &mut Processor,
    mut capture: Capture<T>
) -> Result<()> {
    // Apply a filter to the capture device.
    if let Some(filter) = &config.filter {
        trace!("Using capture filter: '{}'", filter);
        _ = capture.filter(filter.as_str(), true);
    }

    // Save the raw packets, if requested.
    let mut savefile = match &config.save_file {
        Some(path) => Some(capture.savefile(path)?),
        None => None
    };

    // The data link determines how the IP packet is framed.
    let link = capture.get_datalink();

    // Run capture loop.
    while hook.try_recv().is_err() {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(savefile) = &mut savefile {
                    savefile.write(&packet);
                    _ = savefile.flush();
                }
                parse_packet(config, processor, packet, link);
            },
            Err(pcap::Error::NoMorePackets) => break,
            Err(_) => {}
        }
    }

    Ok(())
}

/// Packet parsing function from raw packet data.
fn parse_packet(
    config: &Config,
    processor: &mut Processor,
    packet: Packet,
    link: Linktype
) {
    // Extract the UDP payload and source port from the packet.
    let Some((data, port)) = udp_payload(packet.data, link) else {
        trace!("Skipped a packet that is not UDP over IPv4/IPv6.");
        return;
    };
    let data = data.to_vec();

    // Check the packet's source.
    let source = PacketSource::from(config, port);
    trace!("Received packet of length {} from {:?} ({}).", data.len(), source, port);

    // Pre-process the packet.
    if data.len() == 20 {
        // This is a handshake packet; we should probably interpret it.
        let opcode = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match opcode {
            CONNECT_CMD => {
                trace!("Connect handshake operation received from {:?}.", source);
            },
            CONV_CMD => {
                let conv = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                let token = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

                processor.initialize(conv, token);

                trace!("Received conversation ID from server: ({}, {})", conv, token);
            },
            DISCONNECT_CMD => {
                trace!("Disconnect handshake operation received from {:?}.", source);
            },
            _ => debug!("Unknown handshake operation received: {:x?}", opcode)
        }
    } else {
        // This is a game packet; forward it to the processor.
        processor.receive(&data, source);
    }
}

/// Extracts the UDP payload and the source port from a captured frame.
///
/// Handles Ethernet (with VLAN tags), BSD loopback and raw IP framing,
/// carrying either IPv4 or IPv6.
fn udp_payload(frame: &[u8], link: Linktype) -> Option<(&[u8], u16)> {
    // Strip the link-layer header.
    let ip = match link {
        Linktype::ETHERNET => {
            let mut offset = 12;
            let mut ether_type = u16::from_be_bytes(frame.get(offset..offset + 2)?.try_into().ok()?);
            // Skip 802.1Q / 802.1ad tags.
            while ether_type == 0x8100 || ether_type == 0x88A8 {
                offset += 4;
                ether_type = u16::from_be_bytes(frame.get(offset..offset + 2)?.try_into().ok()?);
            }
            frame.get(offset + 2..)?
        },
        Linktype::NULL | Linktype::LOOP => frame.get(4..)?,
        Linktype::LINUX_SLL => frame.get(16..)?,
        _ => frame
    };

    // Strip the IP header.
    let udp = match ip.first()? >> 4 {
        4 => {
            if *ip.get(9)? != 17 {
                return None;
            }
            ip.get(((ip[0] & 0x0F) as usize) * 4..)?
        },
        6 => {
            let mut next_header = *ip.get(6)?;
            let mut offset = 40;
            // Skip hop-by-hop, routing and destination options headers.
            while matches!(next_header, 0 | 43 | 60) {
                next_header = *ip.get(offset)?;
                offset += (*ip.get(offset + 1)? as usize + 1) * 8;
            }
            if next_header != 17 {
                return None;
            }
            ip.get(offset..)?
        },
        _ => return None
    };

    // Strip the UDP header, and any link-layer padding after the payload.
    let port = u16::from_be_bytes(udp.get(0..2)?.try_into().ok()?);
    let length = u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?) as usize;
    let payload = udp.get(8..length.clamp(8, udp.len()))?;

    Some((payload, port))
}

/// Utility function to create a new KCP instance.
///
/// `conv`: The KCP conversation ID. \
/// `token`: The KCP token.
fn new_kcp(conv: u32, token: u32) -> Kcp<Writer> {
    let mut kcp = Kcp::new(conv, token, Writer);
    kcp.set_header_len(kcp::MAX_KCP_OVERHEAD);
    kcp.set_nodelay(true, 10, 2, false);
    kcp.set_wndsize(256, 256);

    kcp
}

/// Represents a 4096-bit encryption key.
#[derive(Clone)]
struct Key(Vec<u8>);

impl Key {
    /// Creates a new instance of the `Key`.
    pub fn new(seed: u64) -> Self {
        let mut generator = MT19937_64::default();
        generator.seed(seed);

        let seed = generator.next_ulong();
        generator.seed(seed);

        let _ = generator.next_ulong(); // Skip the first number.

        // Generate the key.
        let mut bytes = vec![];
        for _ in (0..4096).step_by(8) {
            bytes.put_u64(generator.next_ulong());
        }

        Key(bytes)
    }

    /// Creates a new instance of the `Key`.
    /// Uses an existing key.
    pub fn from(key: &[u8]) -> Self {
        Key(key.to_vec())
    }

    /// Performs an XOR cipher on the data.
    /// data: The data to encrypt/decrypt.
    pub fn xor(&self, data: &mut [u8]) {
        cryptography::xor(data, &self.0);
    }

    /// Whether this key turns the data into a well-framed packet.
    pub fn decrypts(&self, data: &[u8]) -> bool {
        let (len, key) = (data.len(), &self.0);
        len >= 4
            && data[0] ^ key[0] == 0x45 && data[1] ^ key[1 % key.len()] == 0x67
            && data[len - 2] ^ key[(len - 2) % key.len()] == 0x89
            && data[len - 1] ^ key[(len - 1) % key.len()] == 0xAB
    }

    /// Compares this key to the pre-computed values.
    /// known: The known prefix and suffix of the key.
    /// data: The test data to compare against.
    pub fn compare(&self, known: ([u8; 2], [u8; 2]), data: &[u8]) -> bool {
        let (prefix, suffix) = known;

        let data_len = data.len();
        let key_len = self.0.len();

        let prefix_valid = self.0[0] == prefix[0] && self.0[1] == prefix[1];
        let suffix_valid =
            self.0[(data_len - 2) % key_len] == suffix[0] &&
                self.0[(data_len - 1) % key_len] == suffix[1];

        prefix_valid && suffix_valid
    }
}

/// Represents the type of key in use during encryption.
enum PacketKey {
    None,

    /// The 'dispatch' key can be sourced from the API that handles region selection.
    ///
    /// In our case, we use a hardcoded list of them to prevent the need for an API.
    Dispatch(Key),

    /// The session key is derived from a seed.
    /// The seed itself is a secret that is derived from a client and server seed.
    ///
    /// See the 'Diffie–Hellman key exchange' for a similar concept.
    Session(Key)
}

/// UDP packet processor for the game.
///
/// Packets inputted are decoded with the KCP protocol.
/// The remaining traffic is decrypted using a brute-force technique.
///
/// # Example
///
/// ```rust,no_run
/// use ys_sniffer::{Config, PacketSource, Processor};
///
/// let config = Config::default();
/// let (tx, rx) = crossbeam_channel::unbounded();
/// let mut processor = Processor::new(&config, tx);
///
/// // Initialize & add data.
/// processor.initialize(0, 0);
/// processor.receive(&[0x00], PacketSource::Client);
///
/// // Listen for packets.
/// let packet = rx.recv().unwrap();
/// ```
pub struct Processor {
    packet_consumer: Box<dyn PacketSender>,
    known_seeds: &'static Path,

    key: PacketKey,
    handshake: Option<(u64, u64)>,
    private_keys: Vec<RsaPrivateKey>,
    session_keys: Vec<Key>,
    pending: Vec<(Vec<u8>, PacketSource)>,

    client: Kcp<Writer>,
    server: Kcp<Writer>
}

impl Processor {
    /// Creates a new instance of the `Processor`.
    pub fn new(config: &Config, tx: impl PacketSender + 'static) -> Self {
        let seeds_path = config.known_seeds.clone();
        let seeds_path = Box::leak(seeds_path.into_boxed_str());

        Processor {
            packet_consumer: Box::new(tx),
            known_seeds: Path::new(seeds_path),
            key: PacketKey::None,
            handshake: None,
            private_keys: load_private_keys(&config.private_keys),
            session_keys: load_session_keys(&config.session_keys),
            pending: Vec::new(),
            client: Kcp::default(),
            server: Kcp::default()
        }
    }

    /// (re-)Initializes the processor.
    pub fn initialize(&mut self, conv: u32, token: u32) {
        self.client = new_kcp(conv, token);
        self.server = new_kcp(conv, token);
    }

    /// Event handler for when a packet is received.
    pub fn receive(&mut self, data: &[u8], side: PacketSource) {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u32;

        if side.is_client() {
            _ = self.client.update(time);
            _ = self.client.input(data);
        } else {
            _ = self.server.update(time);
            _ = self.server.input(data);
        }

        // Process packets for both sides.
        self.process(PacketSource::Client);
        self.process(PacketSource::Server);
    }

    /// Processes every packet that is ready on one side.
    fn process(&mut self, side: PacketSource) {
        // A new session key may unlock the messages held back so far.
        if self.take_new_session_keys() {
            self.retry_pending();
        }

        loop {
            let kcp = if side.is_client() { &mut self.client } else { &mut self.server };

            // Check if any data is available.
            let Ok(size) = kcp.peeksize() else {
                return;
            };

            // Allocate a buffer for the data.
            let mut buffer = vec![0; size];
            if kcp.recv(&mut buffer).is_err() {
                return;
            }

            // Debugging aid: `YS_DUMP_DIR` dumps every reassembled (still encrypted) message.
            if let Ok(dir) = std::env::var("YS_DUMP_DIR") {
                static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
                let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                _ = std::fs::write(format!("{dir}/{n:05}_{side:?}.bin"), &buffer);
            }

            self.handle_message(buffer, side);
        }
    }

    /// Decodes one reassembled message and passes it on.
    ///
    /// A message no key decrypts yet is held back until a session key turns up.
    fn handle_message(&mut self, buffer: Vec<u8>, side: PacketSource) {
        match self.decode_packet(buffer.clone(), side) {
            Ok(packet) => {
                // Pass the packet to the preprocessor briefly.
                self.preprocess(&packet);

                _ = self.packet_consumer.send(packet);
            },
            Err(error) => {
                debug!("Held back a {:?} packet: {}", side, error);
                if self.pending.len() < MAX_PENDING {
                    if self.pending.is_empty() {
                        warn!("No key decrypts the session's packets yet; holding them back until a session key is added.");
                    }
                    self.pending.push((buffer, side));
                }
            }
        }
    }

    /// Moves session keys added at runtime into the candidates. Returns whether there were any.
    fn take_new_session_keys(&mut self) -> bool {
        let keys = std::mem::take(&mut *NEW_SESSION_KEYS.lock().unwrap());
        let added = !keys.is_empty();
        for key in keys {
            self.session_keys.push(Key::from(&key));
        }
        added
    }

    /// Retries the held back messages, in their original order.
    fn retry_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        if pending.is_empty() {
            return;
        }

        let count = pending.len();
        for (buffer, side) in pending {
            self.handle_message(buffer, side);
        }
        debug!("Retried {} held back messages; {} remain.", count, self.pending.len());
    }

    /// This method is used to check if the packet is an encryption handshake packet.
    ///
    /// If it is, we store its data for use in the future.
    fn preprocess(&mut self, packet: &GamePacket) {
        // Check if the encryption key has been found.
        if self.handshake.is_some() {
            return;
        }

        // Decode the packet's data.
        let data = match protoshark::decode(&packet.data) {
            Ok(data) => data,
            Err(error) => {
                trace!("Undecodable packet data: {}", BASE64_STANDARD.encode(&packet.data));
                if packet.source.is_server() {
                    warn!(
                        "Packet {} from the server is not plain protobuf ({}). If it is the login \
                         response, its body carries an extra encryption layer, so the session key \
                         cannot be recovered from the handshake; provide it as a session key instead.",
                        packet.id, error
                    );
                }
                return;
            }
        };

        // Search for `bytes` fields.
        for (_, value) in data {
            match value {
                Value::String(string) => {
                    // Check if the string is valid Base64.
                    let Ok(bytes) = BASE64_STANDARD.decode(&string) else {
                        continue;
                    };

                    // Only the server's seed is encrypted to the client's key.
                    // It is an RSA block: 128, 256 or 512 bytes.
                    if packet.source.is_client() || !matches!(bytes.len(), 128 | 256 | 512) {
                        continue;
                    }

                    // Try to RSA-decrypt the data.
                    let decrypted = self.private_keys.iter()
                        .find_map(|key| key.decrypt(Pkcs1v15Encrypt, &bytes).ok());
                    let Some(decrypted) = decrypted.filter(|seed| seed.len() >= 8) else {
                        warn!(
                            "Packet {} carries a {}-byte RSA block that no private key decrypts; \
                             add the client's key with `private_keys` to recover the session key.",
                            packet.id, bytes.len()
                        );
                        continue;
                    };
                    debug!("Handshake found in packet {}.", packet.id);

                    // In the case that both of these succeed, we can assume this is the handshake packet.
                    // First, we need to determine when the packet was sent.
                    let Ok(header) = protoshark::decode(&packet.header) else {
                        error!("Failed to decode packet header: invalid format");
                        return;
                    };

                    // Get the `sent_ms` field.
                    // This is always field 6 if decoded properly.
                    let Some(Value::VarInt(sent_time)) = header.get(6) else {
                        error!("Failed to decode packet header: `sent_ms` field not found");
                        return;
                    };
                    let Some(sent_time) = sent_time.as_u64() else {
                        error!("Failed to decode packet header: `sent_ms` field not a u64");
                        return;
                    };

                    // Parse the server seed from binary.
                    let server_seed = u64::from_be_bytes(decrypted[0..8].try_into().unwrap());

                    // Store the handshake data.
                    self.handshake = Some((sent_time, server_seed));
                },
                _ => {}
            }
        }
    }

    /// Decrypts the packet.
    pub fn decode_packet(&mut self, data: Vec<u8>, side: PacketSource) -> Result<GamePacket> {
        if data.len() < 12 {
            return Err(anyhow!("Packet too short: {} bytes.", data.len()));
        }
        let data = self.decrypt_packet(data)?;

        // Parse the packet.
        let id = u16::from_be_bytes([data[2], data[3]]);
        let header_size = u16::from_be_bytes([data[4], data[5]]) as usize;
        let data_size = u32::from_be_bytes([data[6], data[7], data[8], data[9]]) as usize;
        if 10 + header_size + data_size + 2 != data.len() {
            return Err(anyhow!("Packet {} has inconsistent lengths.", id));
        }

        let header = data[10..10 + header_size].to_vec();
        let data = data[10 + header_size..data.len() - 2].to_vec();

        Ok(GamePacket {
            id,
            header,
            data,
            source: side
        })
    }

    /// Attempts to decrypt the packet.
    ///
    /// Tries, in order: the key in use, the candidate session keys,
    /// the dispatch key named by the first bytes, and a session key brute-forced from the handshake.
    fn decrypt_packet(&mut self, mut data: Vec<u8>) -> Result<Vec<u8>> {
        // The key in use.
        if let PacketKey::Session(key) | PacketKey::Dispatch(key) = &self.key {
            if key.decrypts(&data) {
                key.xor(&mut data);
                return Ok(data);
            }
        }

        // A candidate session key.
        if let Some(key) = self.session_keys.iter().find(|key| key.decrypts(&data)).cloned() {
            if !matches!(self.key, PacketKey::Session(_)) {
                info!("Switched to a provided session key.");
            }
            key.xor(&mut data);
            self.key = PacketKey::Session(key);
            return Ok(data);
        }

        // The dispatch key, picked by the first bytes.
        let index = u16::from_be_bytes([data[0] ^ 0x45, data[1] ^ 0x67]);
        if let Some(key) = DISPATCH_KEYS.get(&index).filter(|key| key.decrypts(&data)).cloned() {
            if !matches!(self.key, PacketKey::Dispatch(_)) {
                debug!("Using dispatch key {}.", index);
            }
            key.xor(&mut data);
            self.key = PacketKey::Dispatch(key);
            return Ok(data);
        }

        // Brute-force the session key from the handshake.
        let Some((sent_time, seed)) = self.handshake else {
            return Err(anyhow!("No key decrypts the packet, and the handshake was not recovered."));
        };
        let Some(seed) = bruteforce(&self.known_seeds, sent_time, seed, &data) else {
            return Err(anyhow!("Unable to find the encryption key seed."));
        };

        let key = Key::new(seed);
        if !key.decrypts(&data) {
            return Err(anyhow!("The brute-forced key does not decrypt the packet."));
        }
        trace!("Encryption key found for session! Seed: {}", seed);
        key.xor(&mut data);
        self.session_keys.push(key.clone());
        self.key = PacketKey::Session(key);
        Ok(data)
    }
}

/// Attempts to bruteforce the encryption key's seed.
fn bruteforce(
    seeds_file: &Path,
    sent_time: u64, server_seed: u64,
    data: &[u8]
) -> Option<u64> {
    // Load already known seeds from the disk.
    let mut file_content = "".to_string();
    if seeds_file.exists() {
        file_content = utils::read_file(seeds_file).unwrap();
        for line in file_content.lines() {
            if let Ok(seed) = line.parse::<i64>() {
                // If the seed is a valid i64, we can try it.
                if let Some(seed) = try_seed(seed, server_seed, 10000, data) {
                    return Some(seed);
                }
            }
        }

        // Trim any trailing whitespace.
        file_content = file_content.trim().to_string();
    }

    // Generate new seeds.
    for i in 0..3000i64 {
        let offset = if i % 2 == 0 { i / 2 } else { -(i - 1) / 2 };
        let time = sent_time as i64 + offset; // This will act as the seed.

        if let Some(key) = try_seed(time, server_seed, 5, data) {
            // If a seed is found, we should save it.
            // (we don't actually save the seed, rather we save the time which acts similarly to the seed)
            let content = match seeds_file.exists() {
                true => format!("{}\n{}", file_content, time),
                false => time.to_string()
            };
            utils::write_file(seeds_file, content).unwrap();

            return Some(key);
        }
    }

    None
}

/// Attempts to bruteforce the encryption key's seed.
fn try_seed(
    client_guess: i64,
    server_seed: u64,
    depth: i32,
    test: &[u8]
) -> Option<u64> {
    // Calculate the known prefix and suffix of the key.
    let prefix = [test[0] ^ 0x45, test[1] ^ 0x67];
    let suffix = [
        test[test.len() - 2] ^ 0x89,
        test[test.len() - 1] ^ 0xAB,
    ];

    // Attempt to generate the key.
    let mut generator = Random::seeded(client_guess as i32);
    for _ in 0..depth {
        let client_seed = generator.next_safe_uint64();

        let seed = client_seed ^ server_seed;
        let key = Key::new(seed);

        if key.compare((prefix, suffix), test) {
            return Some(seed);
        }
    }

    None
}

#[derive(Default)]
pub struct Writer;

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}