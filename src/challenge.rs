use crate::challenge::DeviceChallengeStatus::{Closed, Pending};
use crate::client::ClientActivity::{ChangeStatus, OpenConnection};
use crate::client::DefaultClientManager;
use crate::consts::{CommonThreadError, CHALLENGE_DEATH};
use crate::device_manager::get_device;
use crate::server::model::{ServerResponse};
use crate::utils::control::ConnectionStatusVerification;
use crate::utils::{decrypt_with_passphrase, encrypt_with_passphrase};
use lazy_static::lazy_static;
use log::{debug, info};
use serde::de;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::io::{ErrorKind};
use std::net::SocketAddr;
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{sleep, Instant};
use uuid::Uuid;
use DeviceChallengeStatus::Active;
use crate::server::model::ConnectionState::{Access, Denied};

lazy_static! {
    pub static ref DefaultChallengeManager: Arc<ChallengeManager> = {
        let channel = mpsc::channel(200);
        Arc::new(ChallengeManager::new((channel.0, Mutex::new(channel.1))))
    };
}

pub struct ChallengeManager {
    //device_id -> _, nonce hash, ttl
    pub current_challenges: RwLock<HashMap<String, DeviceChallengeStatus>>,
    //receiver for emitted connection event
    bounded_channel: (Sender<ChallengeEvent>, Mutex<Receiver<ChallengeEvent>>),
}

pub enum ChallengeEvent {
    NewDevice {
        device_id: String,
    },
    NewChallengeRequest {
        device_id: String,
        nonce: Vec<u8>,
    },
    ChallengeVerification {
        device_id: String,
        iv_bytes: [u8; 12],
        salt: [u8; 16],
        ciphertext_with_tag: Vec<u8>,
    },
}

#[derive(PartialEq, Clone)]
pub enum DeviceChallengeStatus {
    //outcoming
    Active {
        socket_addr: SocketAddr,
        nonce: Vec<u8>,
        nonce_hash: Vec<u8>,
        salt: Vec<u8>,
        passphrase: Vec<u8>,
        attempts: u8,
        ttl: Instant,
    },
    //incoming
    Pending {
        socket_addr: SocketAddr,
        nonce: Vec<u8>,
    },
    Closed {
        socket_addr: SocketAddr,
    },
}

impl DeviceChallengeStatus {
    pub fn name(&self) -> &str {
        match &self {
            Active { .. } => "ACTIVE",
            DeviceChallengeStatus::Pending { .. } => "PENDING",
            DeviceChallengeStatus::Closed { .. } => "CLOSED",
        }
    }
}

//todo replace with actual errors
impl ConnectionStatusVerification for DeviceChallengeStatus {
    fn verify_self(&self) -> Result<bool, Box<dyn Error>> {
        let now = Instant::now();
        match self {
            Active {
                socket_addr,
                nonce,
                nonce_hash,
                salt,
                passphrase,
                attempts,
                ttl,
            } => {
                if now.ge(ttl) {
                    return Ok(false);
                }
                if *attempts == 0u8 {
                    return Ok(false);
                }
                Ok(true)
            }
            _ => Ok(true),
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

    pub async fn can_request_new_connection(&self, device_id: &String) -> bool {
        let challenges = self.current_challenges.read().await;
        !challenges.contains_key(device_id)
    }
}

pub async fn run(manager: Arc<ChallengeManager>) {
    let res = tokio::try_join!(
        tokio::spawn(challenge_listener(Arc::clone(&manager))),
        tokio::spawn(cleanup()),
    );
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
                    _ => true,
                });
        }
        sleep(Duration::from_secs(15)).await;
    }
}

/**
* listen to the device manager and initiate device verification
*/
pub async fn challenge_listener(manager: Arc<ChallengeManager>) -> Result<(), CommonThreadError> {
    let challenge_manager = manager.clone();
    let client_manager = Arc::clone(&DefaultClientManager);

    let receiver_mutex = &challenge_manager.bounded_channel.1;
    loop {
        let mut receiver = receiver_mutex.lock().await;

        if let Some(message) = receiver.recv().await {
            match message {
                ChallengeEvent::NewDevice { device_id } => {
                    info!("Registering new device: {}", device_id);
                    client_manager
                        .bounded_channel
                        .0
                        .send(OpenConnection {
                            device_id: device_id.clone(),
                        })
                        .await
                        .expect(&format!(
                            "Cannot send request for establishing new connection: {}",
                            device_id
                        ));
                }

                ChallengeEvent::ChallengeVerification {
                    device_id,
                    iv_bytes,
                    salt,
                    ciphertext_with_tag,
                } => {
                    let (is_valid, close_connection) =
                        verify_challenge(&device_id, iv_bytes, salt, ciphertext_with_tag).await?;

                    if is_valid {
                        client_manager
                            .bounded_channel
                            .0
                            .send(ChangeStatus {
                                device_id: device_id.clone(),
                                status: Access
                            })
                            .await
                            .expect(&format!(
                                "Cannot send request for changing status: {}",
                                device_id
                            ));
                    }else {
                        if close_connection {
                            client_manager
                                .bounded_channel
                                .0
                                .send(ChangeStatus {
                                    device_id: device_id.clone(),
                                    status: Denied
                                })
                                .await
                                .expect(&format!(
                                    "Cannot send request for changing status: {}",
                                    device_id
                                ));
                        }
                    }
                }
                ChallengeEvent::NewChallengeRequest { device_id, nonce } => {
                    let device = get_device(&device_id).await;
                    if let Some(_device) = device {
                        let mut mtx = challenge_manager.current_challenges.write().await;
                        match mtx.entry(device_id.clone()) {
                            Entry::Occupied(ent) => match ent.get() {
                                Active { .. } => {}
                                _ => {
                                    mtx.insert(
                                        device_id,
                                        Pending {
                                            socket_addr: _device.connect_addr.clone(),
                                            nonce,
                                        },
                                    );
                                }
                            },
                            Entry::Vacant(_) => {
                                mtx.insert(
                                    device_id,
                                    Pending {
                                        socket_addr: _device.connect_addr.clone(),
                                        nonce,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn verify_challenge(
    device_id: &String,
    iv_bytes: [u8; 12],
    salt: [u8; 16],
    ciphertext_with_tag: Vec<u8>,
    //is_valid, close_connection
) -> Result<(bool,bool), CommonThreadError> {
    let challenge_manager = Arc::clone(&DefaultChallengeManager);

    let mut challenges = challenge_manager.current_challenges.write().await;
    let sent_challenge = challenges.get_mut(device_id);

    if let Some(challenge) = sent_challenge {
        match challenge {
            Active {
                passphrase,
                nonce_hash,
                attempts,
                socket_addr,
                ..
            } => {
                let decrypted_hash =
                    decrypt_with_passphrase(&ciphertext_with_tag, &iv_bytes, &salt, &passphrase)
                        .expect("Cannot decrypt");

                if !decrypted_hash.eq(nonce_hash) {
                    *attempts -= 1;

                    if *attempts == 0u8 {
                        let mut challenges = challenge_manager.current_challenges.write().await;
                        challenges.remove_entry(device_id);

                        challenges.insert(
                            device_id.clone(),
                            Closed {
                                socket_addr: socket_addr.clone(),
                            },
                        );
                        return Ok((false,true))
                    }

                    return Ok((false, false));
                } else {
                    let mut challenges = challenge_manager.current_challenges.write().await;
                    challenges.remove_entry(device_id);

                    return Ok((true, false));
                }
            }
            _ => {}
        }
    }

    Ok((false, false))
}

/**
 * create challenge for device based on fetched hash of passphrase
* and nonce UUID, encoded with Aes128Gcm, amounts of retries of each client is set to base 3 for handling bruteforce
*/
pub async fn generate_challenge(
    device_id: String,
) -> Result<ServerResponse, Box<dyn Error + Send + Sync>> {
    debug!("Generating a challenge for: {}", device_id);
    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());
    let result = encrypt_with_passphrase(nonce_uuid_hash.as_bytes(), b"key").unwrap();

    let default_challenge_manager_arc = Arc::clone(&DefaultChallengeManager);

    let mut current_challenges = default_challenge_manager_arc
        .current_challenges
        .write()
        .await;

    match get_device(&device_id).await {
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
                        nonce: result.1.into(),
                        salt: result.2.into(),
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

    Ok(ServerResponse::ChallengeRequest {
        device_id: device_id.clone(),
        nonce: result.0,
    })
}
