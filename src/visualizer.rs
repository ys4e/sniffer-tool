use anyhow::Result;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};
use futures_util::SinkExt;
use serde::Serialize;
use serde_repr::Serialize_repr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use ys_sniffer::GamePacket;
use crate::settings::{DisplayType, UserConfig};
use crate::START_TIME;

type List = Mutex<Vec<String>>;

pub static SHOW: LazyLock<Mutex<DisplayType>> = LazyLock::new(|| Mutex::new(DisplayType::All));
pub static WHITELIST: LazyLock<List> = LazyLock::new(|| Mutex::new(Vec::new()));
pub static BLACKLIST: LazyLock<List> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Should the packet be shown based on the filters?
async fn should_show(id: u16, name: &String) -> bool {
    let id_str = &id.to_string();
    
    let show = SHOW.lock().await;
    match *show {
        DisplayType::All => true,
        DisplayType::Whitelist => {
            let whitelist = WHITELIST.lock().await;
            whitelist.is_empty() || whitelist.contains(name) || whitelist.contains(id_str)
        }
        DisplayType::Blacklist => {
            let blacklist = BLACKLIST.lock().await;
            !blacklist.contains(name) && !blacklist.contains(id_str)
        }
    }
}

const BIND_ADDRESS: &str = "0.0.0.0:8080";

pub type SocketSender = Arc<Sender<GameData>>;
pub type WebSocketClient = WebSocketStream<TcpStream>;
pub type ClientList = Mutex<Vec<WebSocketClient>>;

pub struct Visualizer {
    socket: TcpListener,
    clients: ClientList,

    pub tx: SocketSender,
    rx: Receiver<GameData>
}

impl Visualizer {
    /// Loads the user's settings from the configuration file.
    pub async fn load_settings() {
        let settings = UserConfig::load();
        *SHOW.lock().await = settings.display;
        *WHITELIST.lock().await = settings.whitelist;
        *BLACKLIST.lock().await = settings.blacklist;
    }
    
    pub async fn new() -> Result<Self> {
        let addr: SocketAddr = BIND_ADDRESS.parse()?;
        let socket = TcpListener::bind(addr).await?;

        let (tx, rx) = mpsc::channel(128);

        Ok(Visualizer {
            socket,
            clients: Mutex::new(Vec::new()),
            tx: Arc::new(tx),
            rx
        })
    }
    
    /// Runs the websocket server.
    pub async fn run(self) -> Result<()> {
        let clients = Arc::new(self.clients);

        // Spawn receiver task.
        let client_list = clients.clone();
        tokio::spawn(async move {
            Self::send_packets(client_list, self.rx).await;
        });

        // Spawn client listener task.
        tokio::spawn(async move {
            Self::handle_clients(self.socket, clients).await;
        });

        info!("Running visualizer server on {}...", BIND_ADDRESS);

        Ok(())
    }

    /// Sends the received packets to all connected clients.
    async fn send_packets(clients: Arc<ClientList>, mut rx: Receiver<GameData>) {
        while let Some(packet) = rx.recv().await {
            // Check if the packet is allowed to be sent.
            if !should_show(packet.packet_id, &packet.packet_name).await {
                continue;
            }
            
            // Create the visualizer message.
            let packet = VisualizerMessage {
                packet_id: MessageType::GamePacket,
                data: MessageData::GamePacket(packet)
            };

            // Encode the message to JSON.
            let encoded = serde_json::to_string(&packet)
                .expect("failed to encode visualizer message");
            let encoded = Message::from(encoded);

            // Send the message to all clients.
            let mut clients = clients.lock().await;
            for client in clients.iter_mut() {
                _ = client.send(encoded.clone()).await;
            }
            drop(clients);
        }
    }

    /// Handles new client connections.
    async fn handle_clients(socket: TcpListener, clients: Arc<ClientList>) {
        while let Ok((stream, _)) = socket.accept().await {
            let mut ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws_stream) => ws_stream,
                Err(error) => {
                    warn!("Failed to accept websocket connection: {}", error);
                    continue;
                }
            };

            // Send the client a handshake packet.
            let time = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("time went backwards")
                .as_secs();
            let packet = VisualizerMessage {
                packet_id: MessageType::Handshake,
                data: MessageData::Handshake(time)
            };
            let encoded = serde_json::to_string(&packet)
                .expect("failed to encode handshake message");
            let encoded = Message::from(encoded);
            _ = ws_stream.send(encoded).await;

            // Add the client to the list of clients.
            let mut clients = clients.lock().await;
            clients.push(ws_stream);
            drop(clients);
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VisualizerMessage {
    pub packet_id: MessageType,
    pub data: MessageData
}

#[repr(u8)]
#[derive(Serialize_repr)]
enum MessageType {
    Handshake = 0,
    GamePacket = 1
}

#[derive(Serialize)]
#[serde(untagged)]
enum MessageData {
    Handshake(u64),
    GamePacket(GameData)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GameData {
    pub time: u64,
    pub source: String,
    pub packet_id: u16,
    pub packet_name: String,
    pub length: u32,
    pub data: String
}

impl GameData {
    /// Creates a new packet data instance from an existing game packet.
    pub fn from_existing<S: AsRef<str>>(existing: GamePacket, name: S, decoded: String) -> Self {
        let time = START_TIME.elapsed()
            .expect("time went backwards");

        let name = name.as_ref().to_string();
        let packet_length = (existing.data.len() + existing.header.len()) as u32;

        Self {
            time: time.as_millis() as u64,
            // The source should be `client` or `server`.
            // We normalize it here using `to_lowercase`.
            source: existing.source.to_string().to_lowercase(),
            packet_id: existing.id,
            packet_name: name,
            length: packet_length,
            data: decoded
        }
    }
}