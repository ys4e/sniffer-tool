use std::collections::HashMap;
use std::fs::File;
use anyhow::Result;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use prost_reflect::{DescriptorPool, DynamicMessage, Kind, MapKey, SerializeOptions, Value};
use serde_json::{Map, Value as Json};
use crate::schema;

type Descriptors = Mutex<DescriptorPool>;
static DEFS: LazyLock<Descriptors> = LazyLock::new(|| Mutex::new(DescriptorPool::new()));

/// Packet ID -> candidate message names.
///
/// Dumped protocols can assign one ID to several messages
/// (e.g. the request and the response share an ID), so every candidate is kept.
type PacketIds = Mutex<HashMap<u16, Vec<String>>>;
static IDS: LazyLock<PacketIds> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Attempts to load the `all.proto` file from the file system.
///
/// Packet IDs are read from `protocol_definition.json` when it exists,
/// otherwise from the `// cmdId = <id>` comments of the protobuf definitions.
///
/// If no such file exists, the sniffer runs without definitions.
pub fn load_definitions() -> Result<()> {
    let definitions = Path::new("all.proto");
    if !definitions.exists() {
        warn!("No protobuf definitions found; using field decode mode...");
        return Ok(());
    }

    // Load the protobuf definitions.
    let pool = match schema::compile(definitions, Path::new(".")) {
        Ok(pool) => pool,
        Err(e) => {
            error!("Failed to compile protobuf definitions: {:?}", e);
            std::process::exit(1);
        }
    };
    info!("Loaded {} definitions.", pool.all_messages().len());

    // Store the descriptors in the global state.
    *DEFS.lock().unwrap() = pool;

    // Load the packet IDs.
    let ids_file = Path::new("protocol_definition.json");
    let ids: Vec<(String, u16)> = if ids_file.exists() {
        let ids: HashMap<String, u16> = serde_json::from_reader(File::open(ids_file)?)?;
        ids.into_iter().collect()
    } else {
        let ids = ids_from_comments(&std::fs::read_to_string(definitions)?);
        if ids.is_empty() {
            warn!("No packet IDs found; using field decode mode...");
        }
        ids
    };
    info!("Loaded {} packet IDs.", ids.len());

    // Reverse and set the packet IDs.
    let mut reversed = IDS.lock().unwrap();
    reversed.clear();
    for (name, id) in ids {
        reversed.entry(id).or_default().push(name);
    }
    for names in reversed.values_mut() {
        names.sort();
    }

    let shared = reversed.values().filter(|names| names.len() > 1).count();
    if shared > 0 {
        info!("{} packet IDs are shared by several messages; they are resolved per packet.", shared);
    }

    Ok(())
}

/// Reads packet IDs from `// cmdId = <id>` comments.
///
/// The comment belongs to the next `message` declaration (the `dump.proto` format).
fn ids_from_comments(source: &str) -> Vec<(String, u16)> {
    let mut ids = Vec::new();
    let mut pending = None;

    for line in source.lines() {
        let line = line.trim();
        if let Some(id) = line.strip_prefix("// cmdId = ") {
            pending = id.trim().parse::<u16>().ok();
        } else if let Some(rest) = line.strip_prefix("message ") {
            if let (Some(id), Some(name)) = (pending.take(), rest.split_whitespace().next()) {
                ids.push((name.trim_end_matches('{').to_string(), id));
            }
        } else if !line.starts_with("//") && !line.is_empty() {
            pending = None;
        }
    }

    ids
}

/// Decodes the packet with the given ID and data.
pub fn decode(packet_id: u16, data: &[u8]) -> (String, String) {
    let ids = IDS.lock().unwrap();
    let Some(names) = ids.get(&packet_id) else {
        return decode_dynamic(packet_id, data);
    };

    let descriptors = DEFS.lock().unwrap();

    // Decode with every candidate; the first one that leaves nothing unknown wins.
    let mut fallback = None;
    for name in names {
        let Some(message) = descriptors.get_message_by_name(name) else {
            continue;
        };
        let Ok(decoded) = DynamicMessage::decode(message, data) else {
            continue;
        };

        let unknown = count_unknown(&decoded);
        if unknown == 0 {
            return (name.clone(), to_json(&decoded).to_string());
        }
        if fallback.as_ref().is_none_or(|(_, _, best)| unknown < *best) {
            fallback = Some((name, decoded, unknown));
        }
    }

    match fallback {
        Some((name, decoded, _)) => (name.clone(), to_json(&decoded).to_string()),
        None => decode_dynamic(packet_id, data),
    }
}

/// Dynamically decodes the packet data using protoshark.
fn decode_dynamic(packet_id: u16, data: &[u8]) -> (String, String) {
    let data = match protoshark::decode(data) {
        Ok(decoded) => serde_json::to_string(&decoded)
            .expect("failed to serialize packet"),
        Err(_) => Json::String(base64_encode(data)).to_string(),
    };

    (packet_id.to_string(), data)
}

/// Counts the fields (at any depth) that the definitions do not describe.
fn count_unknown(message: &DynamicMessage) -> usize {
    let mut count = message.unknown_fields().count();
    for (_, value) in message.fields() {
        count += match value {
            Value::Message(nested) => count_unknown(nested),
            Value::List(list) => list.iter()
                .filter_map(Value::as_message)
                .map(count_unknown)
                .sum(),
            Value::Map(map) => map.values()
                .filter_map(Value::as_message)
                .map(count_unknown)
                .sum(),
            _ => 0,
        };
    }

    count
}

/// Serializes a message to JSON.
///
/// Fields the definitions do not describe are kept, decoded without a schema,
/// under the key `#<field number>`.
fn to_json(message: &DynamicMessage) -> Json {
    let options = SerializeOptions::new().use_proto_field_name(true);
    let mut json = message
        .serialize_with_options(serde_json::value::Serializer, &options)
        .expect("failed to serialize packet");

    add_unknown(message, &mut json);
    json
}

/// Recursively adds the unknown fields of a message to its JSON form.
fn add_unknown(message: &DynamicMessage, json: &mut Json) {
    let Json::Object(object) = json else {
        return;
    };

    for (field, value) in message.fields() {
        let Kind::Message(_) = field.kind() else {
            continue;
        };
        let Some(entry) = object.get_mut(field.name()) else {
            continue;
        };

        match (value, entry) {
            (Value::Message(nested), entry) => add_unknown(nested, entry),
            (Value::List(list), Json::Array(entries)) => {
                for (nested, entry) in list.iter().zip(entries.iter_mut()) {
                    if let Value::Message(nested) = nested {
                        add_unknown(nested, entry);
                    }
                }
            },
            (Value::Map(map), Json::Object(entries)) => {
                for (key, nested) in map {
                    let Value::Message(nested) = nested else {
                        continue;
                    };
                    if let Some(entry) = entries.get_mut(&map_key(key)) {
                        add_unknown(nested, entry);
                    }
                }
            },
            _ => {}
        }
    }

    let mut unknown = Map::new();
    for field in message.unknown_fields() {
        let mut encoded = Vec::new();
        field.encode(&mut encoded);
        let decoded = match protoshark::decode(&encoded) {
            Ok(decoded) => serde_json::to_value(&decoded).unwrap_or(Json::Null),
            Err(_) => Json::String(base64_encode(&encoded)),
        };

        // `protoshark` yields `{ "<number>": value }` for a single field.
        let value = match decoded {
            Json::Object(mut fields) => fields
                .remove(&field.number().to_string())
                .unwrap_or(Json::Object(fields)),
            other => other,
        };

        let key = format!("#{}", field.number());
        match unknown.get_mut(&key) {
            // Repeated unknown fields are collected into an array.
            Some(Json::Array(values)) => values.push(value),
            Some(existing) => *existing = Json::Array(vec![existing.take(), value]),
            None => { unknown.insert(key, value); }
        }
    }
    object.extend(unknown);
}

/// The JSON object key `prost-reflect` uses for a map key.
fn map_key(key: &MapKey) -> String {
    match key {
        MapKey::Bool(value) => value.to_string(),
        MapKey::I32(value) => value.to_string(),
        MapKey::I64(value) => value.to_string(),
        MapKey::U32(value) => value.to_string(),
        MapKey::U64(value) => value.to_string(),
        MapKey::String(value) => value.clone(),
    }
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::prelude::BASE64_STANDARD.encode(data)
}

/// Provides a name or ID to represent the packet.
///
/// If the packet is known in 'IDS', it returns the name.
/// If not, it returns the ID as a string.
pub fn name_or_id<S: AsRef<str>>(packet: S) -> Option<String> {
    let packet = packet.as_ref();
    let ids = IDS.lock().unwrap();

    if let Ok(id) = packet.parse::<u16>() {
        if let Some(names) = ids.get(&id) {
            return names.first().cloned();
        }
    } else if ids.values().flatten().any(|name| name == packet) {
        return Some(packet.to_string());
    }

    None
}
