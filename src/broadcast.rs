use crate::broadcast::DeviceConnectionState::NEW;
use crate::challenge::{ChallengeEvent, DefaultChallengeManager};
use crate::consts::{CommonThreadError, DeviceId, BROADCAST_INTERVAL_SECONDS, DEFAULT_SERVER_PORT, DISCOVERY_PORT};
use crate::device_manager::{DefaultDeviceManager, DeviceManagerQuery};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Instant};

#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoveryMessage {
    pub device_id: String,
    pub listening_port: u16,
    pub tcp_listening_port: u16,
    pub tcp_network_ip: Option<IpAddr>,
    pub internal_ip: Option<IpAddr>,
    pub wants_to_connect: bool,
}

impl DiscoveryMessage {
    pub fn new(
        device_id: String,
        listening_port: u16,
        internal_ip: Option<IpAddr>,
        tcp_listening_port: u16,
        tcp_network_ip: Option<IpAddr>,
        wants_to_connect: bool,
    ) -> Self {
        DiscoveryMessage {
            device_id,
            listening_port,
            tcp_listening_port,
            tcp_network_ip,
            internal_ip,
            wants_to_connect,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
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

// Device A (Client) sends a DiscoveryMessage (without passphrase).
// Device B (Server) receives it and sends back a ChallengeMessage containing a random nonce (a "number used once").
// Device A receives the ChallengeMessage, combines the nonce with the shared passphrase, hashes them together, and sends back a Response containing the hash.
// Device B receives the Response, computes the same hash using its knowledge of the passphrase and the nonce it sent, and compares it to Device A's response.
// If hashes match, Device B authenticates Device A.

pub async fn start_listener() -> Result<(), CommonThreadError> {
    let listen_addr: SocketAddr = format!("0.0.0.0:{}", DISCOVERY_PORT).parse()?;
    let socket = UdpSocket::bind(listen_addr).await?;
    info!("Broadcast listener started on {}", listen_addr);

    let mut buf = vec![0u8; 1024];

    let device_manager_arc = Arc::clone(&DefaultDeviceManager);
    let device_manager_sender = device_manager_arc.get_channel_sender();

    let challenge_manager = Arc::clone(&DefaultChallengeManager);

    loop {
        let (len, peer_addr) = socket.recv_from(&mut buf).await?;
        let message_str = String::from_utf8_lossy(&buf[..len]);
        let current_device_id = DeviceId.clone();
        match serde_json::from_str::<DiscoveryMessage>(&message_str) {
            Ok(msg) => {
                let remote_addr = msg
                    .internal_ip
                    .map_or(SocketAddr::new(peer_addr.ip(), msg.tcp_listening_port), |ip| {
                        SocketAddr::new(ip, msg.tcp_listening_port)
                    });

                if msg.device_id != current_device_id {
                    info!(
                    "device {:?} device id : {:?} sender id: {:?}",
                    msg,
                    msg.device_id,
                    current_device_id
                );
                    let known_devices = {
                        let read_guard = device_manager_arc.known_devices.read().await;
                        read_guard.clone()
                    };

                    if !known_devices.contains_key(&current_device_id) {
                        device_manager_sender
                            .send(DeviceManagerQuery::DiscoveredDevice {
                                device_id: msg.device_id.clone(),
                                socket_addr: remote_addr,
                            })
                            .await?;
                    }

                    //generate challenge
                    if msg.wants_to_connect && !challenge_manager.can_request_new_connection(&msg.device_id).await {
                        challenge_manager
                            .get_sender()
                            .send(ChallengeEvent::NewDevice {
                                device_id: msg.device_id.clone(),
                            })
                            .await?;
                    }
                }
            }
            Err(e) => {
                error!(
                    "Failed to parse discovery message: {} from {}, message {}",
                    e, peer_addr, message_str
                );
            }
        }
    }
}

pub async fn start_broadcast_announcer(
    listening_port: u16,
    local_ip: IpAddr,
) -> Result<(), CommonThreadError> {
    let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", DISCOVERY_PORT).parse()?;
    let socket = UdpSocket::bind(format!("{}:{}", local_ip, 0)).await?;
    socket.set_broadcast(true)?;

    let message = DiscoveryMessage::new(
        DeviceId.to_string(),
        listening_port,
        Some(local_ip),
        DEFAULT_SERVER_PORT,
        Some(local_ip),
        true,
    );
    let serialized_message = serde_json::to_string(&message)?;

    info!("Broadcast announcer started. Sending on {}", broadcast_addr);

    loop {
        socket
            .send_to(serialized_message.as_bytes(), broadcast_addr)
            .await?;
        sleep(Duration::from_secs(BROADCAST_INTERVAL_SECONDS)).await;
    }
}
