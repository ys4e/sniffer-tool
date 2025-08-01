use std::collections::HashMap;
use std::fs::File;
use anyhow::Result;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use prost_reflect::{DescriptorPool, DynamicMessage};

type Descriptors = Mutex<DescriptorPool>;
static DEFS: LazyLock<Descriptors> = LazyLock::new(|| Mutex::new(DescriptorPool::new()));

type PacketIds = Mutex<HashMap<u16, String>>;
static IDS: LazyLock<PacketIds> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Attempts to load the `all.proto` file from the file system.
///
/// If no such file exists, the sniffer runs without definitions.
pub fn load_definitions() -> Result<()> {
    let definitions = Path::new("all.proto");
    if !definitions.exists() {
        warn!("No protobuf definitions found; using field decode mode...");
        return Ok(());
    }

    let ids = Path::new("protocol_definition.json");
    if !ids.exists() {
        warn!("No packet IDs found; using field decode mode...");
        return Ok(());
    }

    // Load the protobuf definitions.
    let descriptors = match protox::compile([definitions], ["."]) {
        Ok(descriptors) => descriptors,
        Err(e) => {
            error!("Failed to compile protobuf definitions: {}", e);
            std::process::exit(1);
        }
    };
    let pool = DescriptorPool::from_file_descriptor_set(descriptors)?;
    info!("Loaded {} definitions.", pool.all_messages().len());

    // Store the descriptors in the global state.
    *DEFS.lock().unwrap() = pool;

    // Load, reverse, and set the packet IDs.
    let ids: HashMap<String, u16> = serde_json::from_reader(File::open(ids)?)?;
    info!("Loaded {} packet IDs.", ids.len());

    let mut reversed = IDS.lock().unwrap();
    reversed.clear();
    for (name, id) in ids {
        reversed.insert(id, name);
    }

    Ok(())
}

/// Decodes the packet with the given ID and data.
pub fn decode(packet_id: u16, data: &[u8]) -> (String, String) {
    // Find the name of the message.
    let ids = IDS.lock().unwrap();

    match ids.get(&packet_id) {
        None => decode_dynamic(packet_id, data),
        Some(packet_name) => {
            // Lookup the descriptor for the message.
            let descriptors = DEFS.lock().unwrap();

            let fqdn = format!(".{}", packet_name);
            let Some(message) = descriptors.get_message_by_name(&fqdn) else {
                return decode_dynamic(packet_id, data);
            };

            // Decode the packet data using the descriptor.
            let decoded = DynamicMessage::decode(message, data)
                .expect("failed to parse packet data");
            let data = serde_json::to_string(&decoded)
                .expect("failed to serialize packet");

            (packet_name.clone(), data)
        }
    }
}

/// Dynamically decodes the packet data using protoshark.
fn decode_dynamic(packet_id: u16, data: &[u8]) -> (String, String) {
    // Dynamically decode the packet.
    let decoded = protoshark::decode(data)
        .expect("failed to parse packet data");
    let data = serde_json::to_string(&decoded)
        .expect("failed to serialize packet");

    (packet_id.to_string(), data)
}

/// Provides a name or ID to represent the packet.
/// 
/// If the packet is known in 'IDS', it returns the name.
/// If not, it returns the ID as a string.
pub fn name_or_id<S: AsRef<str>>(packet: S) -> Option<String> {
    let packet = packet.as_ref();
    let ids = IDS.lock().unwrap();

    if let Ok(id) = packet.parse::<u16>() {
        if let Some(name) = ids.get(&id) {
            return Some(name.clone());
        }
    } else if ids.values().any(|name| name == packet) {
        return Some(packet.to_string());
    }
    
    None
}