use crate::NetError;
use crate::broadcast::DeviceConnectionState::NEW;
use crate::device_manager::DeviceManager;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Sender;
use tokio::time::{Instant, sleep};

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    pub device_id: String,
    pub listening_port: u16,
    pub internal_ip: Option<IpAddr>,
    pub wants_to_connect: bool,
}

impl DiscoveryMessage {
    pub fn new(
        device_id: String,
        listening_port: u16,
        internal_ip: Option<IpAddr>,
        wants_to_connect: bool,
    ) -> Self {
        DiscoveryMessage {
            device_id,
            listening_port,
            internal_ip,
            wants_to_connect,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub connect_addr: SocketAddr,
    pub last_seen: Instant,
    pub state: DeviceConnectionState,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum DeviceConnectionState {
    #[default]
    NEW,
    OPEN,
    REQUESTED,
    CLOSED,
}

impl DiscoveredDevice {
    pub fn new(device_id: String, connect_addr: SocketAddr) -> Self {
        DiscoveredDevice {
            device_id,
            connect_addr,
            last_seen: Instant::now(),
            state: NEW,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }
}

pub type SharedKnownDevices = Arc<Mutex<HashMap<String, DiscoveredDevice>>>;
const DISCOVERY_PORT: u16 = 21028;
const BROADCAST_INTERVAL_SECONDS: u64 = 10;

// Device A (Client) sends a DiscoveryMessage (without passphrase).
// Device B (Server) receives it and sends back a ChallengeMessage containing a random nonce (a "number used once").
// Device A receives the ChallengeMessage, combines the nonce with the shared passphrase, hashes them together, and sends back a Response containing the hash.
// Device B receives the Response, computes the same hash using its knowledge of the passphrase and the nonce it sent, and compares it to Device A's response.
// If hashes match, Device B authenticates Device A.

pub async fn start_listener(
    device_manager_arc: Arc<Mutex<DeviceManager>>,
    sender_id: String,
    challenges_sender: Sender<(String, SocketAddr)>,
) -> Result<(), NetError> {
    let listen_addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT).parse()?;
    let socket = UdpSocket::bind(listen_addr).await?;
    println!("Broadcast listener started on {}", listen_addr);

    let mut buf = vec![0u8; 1024];

    let device_manager = device_manager_arc.lock().await;
    let devices_tx = &device_manager.discovery_tx;

    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        let message_str = String::from_utf8_lossy(&buf[..len]);

        match serde_json::from_str::<DiscoveryMessage>(&message_str) {
            Ok(msg) => {
                let lck = device_manager.get_known_devices();
                let known_devices = lck.lock().await;

                if msg.device_id != sender_id
                    && !(known_devices.contains_key(&sender_id)
                        && known_devices
                            .get(&sender_id)
                            .take_if(|x| x.state == DeviceConnectionState::OPEN)
                            .is_some())
                {
                    let remote_addr = msg
                        .internal_ip
                        .map_or(SocketAddr::new(peer_addr.ip(), msg.listening_port), |ip| {
                            SocketAddr::new(ip, msg.listening_port)
                        });
                    println!(
                        "Received broadcast from Device ID: {}, Listening Port: {}, Peer Addr: {}",
                        msg.device_id, msg.listening_port, remote_addr
                    );
                    devices_tx
                        .send((msg.device_id.clone(), remote_addr))
                        .await?;

                    //generate challenge
                    if msg.wants_to_connect {
                        challenges_sender
                            .send((msg.device_id.clone(), remote_addr))
                            .await?;
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Failed to parse discovery message: {} from {}, message {}",
                    e, peer_addr, message_str
                );
            }
        }
    }
}

pub async fn start_broadcast_announcer(
    device_id: String,
    listening_port: u16,
    local_ip: IpAddr,
) -> Result<(), NetError> {
    let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", DISCOVERY_PORT).parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let message = DiscoveryMessage::new(device_id, listening_port, Some(local_ip), false);
    let serialized_message = serde_json::to_string(&message)?;

    println!("Broadcast announcer started. Sending on {}", broadcast_addr);

    loop {
        socket
            .send_to(serialized_message.as_bytes(), broadcast_addr)
            .await?;
        sleep(Duration::from_secs(BROADCAST_INTERVAL_SECONDS)).await;
    }
}

pub async fn challenge_sender() {}
