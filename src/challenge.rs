use crate::broadcast::DiscoveredDevice;
use crate::consts::CHALLENGE_DEATH;
use crate::device_manager::{DefaultDeviceManager, get_device};
use crate::keychain;
use crate::server::ConnectionRequestQuery;
use crate::utils::control::ConnectionStatusVerification;
use DeviceChallengeStatus::Active;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::aes::Aes128;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use lazy_static::lazy_static;
use log::{debug, info};
use rustls::compress::default_cert_compressors;
use std::any::Any;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::io::{ErrorKind, Read};
use std::net::SocketAddr;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

lazy_static! {
    pub static ref DefaultChallengeManager: Arc<ChallengeManager> = {
        let channel = mpsc::channel(200);
        Arc::new(ChallengeManager::new((channel.0, Mutex::new(channel.1))))
    };
}

pub struct ChallengeManager {
    //device_id -> _, nonce hash, ttl
    pub(crate) current_challenges: RwLock<HashMap<String, DeviceChallengeStatus>>,
    //receiver for emitted connection event
    bounded_channel: (Sender<ChallengeEvent>, Mutex<Receiver<ChallengeEvent>>),
}

pub enum ChallengeEvent {
    NewDevice {
        device_id: String,
    },
    ChallengeVerification {
        connection_response: ConnectionRequestQuery,
    },
}

#[derive(PartialEq)]
pub enum DeviceChallengeStatus {
    Active {
        socket_addr: SocketAddr,
        nonce: Vec<u8>,
        nonce_hash: Vec<u8>,
        passphrase: Vec<u8>,
        attempts: i16,
        ttl: Instant,
    },
    Closed {
        socket_addr: SocketAddr,
    },
}

//todo replace with actual errors
impl ConnectionStatusVerification for DeviceChallengeStatus {
    fn verify_self(&self) -> Result<bool, Box<dyn Error>> {
        let now = Instant::now();
        match self {
            DeviceChallengeStatus::Active {
                socket_addr,
                nonce,
                nonce_hash,
                passphrase,
                attempts,
                ttl,
            } => {
                if now.ge(ttl) {
                    return Ok(false);
                }
                if *attempts <= 0i16 {
                    return Ok(false);
                }
                Ok(true)
            }
            DeviceChallengeStatus::Closed { .. } => Ok(true),
        }
    }
}

impl ChallengeManager {
    pub fn new(
        bounded_channel: (Sender<ChallengeEvent>, Mutex<Receiver<ChallengeEvent>>),
    ) -> ChallengeManager {
        ChallengeManager {
            current_challenges: RwLock::new(HashMap::new()),
            bounded_channel,
        }
    }

    pub fn get_sender(&self) -> Sender<ChallengeEvent> {
        self.bounded_channel.0.clone()
    }
}

pub async fn cleanup() {
    let challenges_arc_clone = Arc::clone(&DefaultChallengeManager);
    loop {
        let now = Instant::now();
        let mut challenges_to_notify_closed: Vec<String> = Vec::new();

        {
            challenges_arc_clone
                .current_challenges
                .write()
                .await
                .retain(|device_id, status| match status {
                    Active {
                        ttl, socket_addr, ..
                    } => {
                        if now.duration_since(*ttl).as_secs() >= CHALLENGE_DEATH {
                            println!(
                                "[CLEANUP] Device {} challenge expired. Transitioning to Closed.",
                                device_id
                            );
                            *status = DeviceChallengeStatus::Closed {
                                socket_addr: *socket_addr,
                            };
                            challenges_to_notify_closed.push(device_id.clone());
                        }
                        true
                    }
                    DeviceChallengeStatus::Closed { .. } => {
                        println!(
                            "[CLEANUP] Removing already Closed challenge for device {}.",
                            device_id
                        );
                        false
                    }
                });
        }
        sleep(Duration::from_secs(15)).await;
    }
}

/**
* listen to the device manager and initiate device verification fro device
*/
pub async fn challenge_listener(manager: Arc<ChallengeManager>) {
    let challenge_manager = manager.clone();

    let receiver_mutex = &challenge_manager.bounded_channel.1;
    loop {
        let mut receiver = receiver_mutex.lock().await;
        tokio::select! {
        Some(message) = receiver.recv() => {
            match message {
             ChallengeEvent::NewDevice{ device_id } => {

                    }
                    ChallengeEvent::ChallengeVerification{ .. } => {}
                }
            }
        }
    }
}

/**
 * create challenge for device based on fetched hash of passphrase
* and nonce UUID, encoded with Aes128Gcm, amounts of retries of each client is set to base 3 for handling bruteforce
*/
pub async fn generate_challenge(
    device_id: String,
) -> Result<ConnectionRequestQuery, Box<dyn Error + Send + Sync>> {
    debug!("Generating a challenge for: {}", device_id);
    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());
    let signed = keychain::sign(nonce_uuid_hash.to_string())
        .expect("[CONNECTION] Somehow signing issues occurred ;(");

    {
        let default_challenge_manager_arc = Arc::clone(&DefaultChallengeManager);

        let mut current_challenges = default_challenge_manager_arc
            .current_challenges
            .write()
            .await;

        match get_device(device_id.clone()).await {
            None => {
                return Err(Box::new(io::Error::new(
                    ErrorKind::NotFound,
                    "No device discovered for challenge",
                )));
            }
            Some(device) => match current_challenges.get(&device.device_id) {
                None => {
                    current_challenges.insert(
                        device_id.clone(),
                        Active {
                            socket_addr: device.connect_addr,
                            nonce: signed.to_vec(),
                            nonce_hash: nonce_uuid_hash.as_bytes().to_vec(),
                            passphrase: blake3::hash(b"key").as_bytes().to_vec(),
                            attempts: 3,
                            ttl: Instant::now().add(Duration::from_secs(60 * 5)),
                        },
                    );
                }
                Some(device_connection_status) => match device_connection_status.verify_self() {
                    Ok(res) => {
                        debug!("Device is trying to reconnect again");
                    }
                    Err(_) => {}
                },
            },
        }
    }

    Ok(ConnectionRequestQuery::ChallengeRequest {
        device_id: device_id.clone(),
        nonce: signed.to_vec(),
    })
}
