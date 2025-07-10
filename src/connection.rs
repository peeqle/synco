use crate::broadcast::DiscoveredDevice;
use crate::consts::CHALLENGE_DEATH;
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
use std::io::Read;
use std::net::SocketAddr;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

lazy_static! {
    pub static ref DefaultChallengeManager: Arc<Mutex<Box<ChallengeManager>>> = {
        let channel = mpsc::channel(200);
        Arc::new(Mutex::new(Box::new(ChallengeManager::new(channel))))
    };
}

const AES_KEY_SIZE: usize = 32;

pub struct ChallengeManager {
    //device_id -> _, nonce hash, ttl
    current_challenges: HashMap<String, DeviceChallengeStatus>,
    //receiver for emitted connection event
    bounded_channel: (Sender<ChallengeEvent>, Receiver<ChallengeEvent>),
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
        bounded_channel: (Sender<ChallengeEvent>, Receiver<ChallengeEvent>),
    ) -> ChallengeManager {
        ChallengeManager {
            current_challenges: HashMap::new(),
            bounded_channel,
        }
    }

    pub fn get_sender(&self) -> Sender<ChallengeEvent> {
        self.bounded_channel.0.clone()
    }

    fn get_receiver(&mut self) -> &mut Receiver<ChallengeEvent> {
        &mut self.bounded_channel.1
    }
}

pub async fn cleanup() {
    let challenges_arc_clone = Arc::clone(&DefaultChallengeManager);
    loop {
        let now = Instant::now();
        let mut challenges_to_notify_closed: Vec<String> = Vec::new();

        {
            let mut ch_locked = challenges_arc_clone.lock().await;

            ch_locked
                .current_challenges
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
* Accepts device to connect and create challenge for it based on fetched hash of passphrase
* and nonce UUID, encoded with Aes128Gcm, amounts of retries of each client is set to base 3 for handling bruteforce
*/
pub async fn generate_challenge(device: &DiscoveredDevice) -> Result<ConnectionRequestQuery, Box<dyn Error + Send + Sync>> {
    debug!("Generating a challenge for: {}", device.device_id);
    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());
    let signed = keychain::sign(nonce_uuid_hash.to_string())
        .expect("[CONNECTION] Somehow signing issues occurred ;(");

    {
        let default_challenge_manager_arc = Arc::clone(&DefaultChallengeManager);

        let mut lck = default_challenge_manager_arc.lock().await;
        let current_device_challenge = lck.current_challenges.get(&device.device_id.clone());
        match current_device_challenge {
            None => {
                lck.current_challenges.insert(
                    device.device_id.clone(),
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
        }
    }

    Ok(ConnectionRequestQuery::ChallengeRequest {
        device_id: device.device_id.clone(),
        nonce: signed.to_vec(),
    })
}

pub fn encrypt_with_passphrase(
    nonce_hash: &[u8],
    passphrase: &[u8; AES_KEY_SIZE],
) -> Result<(Vec<u8>, [u8; 12]), aes_gcm::Error> {
    let cipher = Aes128Gcm::new_from_slice(passphrase).map_err(|_| aes_gcm::Error)?;

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext_with_tag = cipher.encrypt(nonce, nonce_hash)?;
    Ok((ciphertext_with_tag, iv_bytes))
}

pub fn decrypt_with_passphrase(
    passphrase: &[u8; 32],
    iv_bytes: &[u8; 12],
    ciphertext_with_tag: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes128Gcm::new_from_slice(passphrase).map_err(|_| aes_gcm::Error)?;
    let nonce = Nonce::from_slice(iv_bytes);

    cipher.decrypt(nonce, ciphertext_with_tag)
}

pub async fn verify_passphrase(_device: DiscoveredDevice, encoded_passphrase: &[u8]) -> bool {
    let default_challenge_manager_arc = Arc::clone(&DefaultChallengeManager);

    let mut lck = default_challenge_manager_arc.lock().await;
    let current_device_challenge = lck.current_challenges.get_mut(&_device.device_id);

    if let Some(device) = current_device_challenge {
        match device {
            Active {
                socket_addr,
                nonce,
                nonce_hash,
                passphrase,
                attempts,
                ttl,
            } => {
                if *attempts <= 0 {
                    debug!("User cannot connect due to retries fall");
                } else {
                    let mut passphrase_array: [u8; 32] = [0; 32];
                    passphrase_array.copy_from_slice(&passphrase);

                    let mut nonce_array: [u8; 12] = [0; 12];
                    nonce_array.copy_from_slice(&nonce_hash);

                    match decrypt_with_passphrase(
                        &passphrase_array,
                        &nonce_array,
                        encoded_passphrase,
                    ) {
                        Ok(_) => {}
                        Err(err) => {
                            info!(
                                "User {} tried to connect but failed with passphrase {}",
                                _device.connect_addr.ip().to_string(),
                                String::from_utf8_lossy(&passphrase_array)
                            )
                        }
                    };
                }
            }
            DeviceChallengeStatus::Closed { .. } => {}
        }
    };

    return false;
}
