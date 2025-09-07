use crate::challenge::DeviceChallengeStatus::{Closed, Pending};
use crate::client::ClientActivity::{ChangeStatus, OpenConnection};
use crate::client::DefaultClientManager;
use crate::consts::data::get_device_id;
use crate::consts::{CommonThreadError, CHALLENGE_DEATH};
use crate::device_manager::get_device;
use crate::server::model::ConnectionState::{Access, Denied};
use crate::server::model::ServerResponse;
use crate::utils::control::ConnectionStatusVerification;
use crate::utils::{decrypt_with_passphrase, encrypt_with_passphrase};
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use serde::de;
use std::collections::hash_map::Entry;
use std::collections::{self, HashMap};
use std::error::Error;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock, RwLockWriteGuard};
use tokio::time::{sleep, Instant};
use uuid::Uuid;
use DeviceChallengeStatus::Active;
use crate::keychain::data::get_device_passphrase;

lazy_static! {
    pub static ref DefaultChallengeManager: Arc<ChallengeManager> = {
        let channel = mpsc::channel(200);
        Arc::new(ChallengeManager::new((channel.0, Mutex::new(channel.1))))
    };
}

//todo remove two duplicated fields for in/out auth segregation
pub struct ChallengeManager {
    //device_id -> _, nonce hash, ttl
    //incoming challenges
    pub in_challenges: RwLock<HashMap<String, DeviceChallengeStatus>>,
    //only active challenges for devices
    pub(crate) out_challenges: RwLock<HashMap<String, DeviceChallengeStatus>>,
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
        nonce_hash: Vec<u8>,
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
            Pending { .. } => "PENDING",
            Closed { .. } => "CLOSED",
        }
    }
}

//todo replace with actual errors
impl ConnectionStatusVerification for DeviceChallengeStatus {
    fn verify_self(&self) -> Result<bool, Box<dyn Error>> {
        let now = Instant::now();
        match self {
            Active {
                attempts,
                ttl,
                ..
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
            in_challenges: RwLock::new(HashMap::new()),
            out_challenges: RwLock::new(HashMap::new()),
            bounded_channel,
        }
    }

    pub fn get_sender(&self) -> Sender<ChallengeEvent> {
        self.bounded_channel.0.clone()
    }

    pub async fn remove_incoming_challenge(&self, device_id: &String) {
        let mut challenges = self.in_challenges.write().await;
        challenges.remove_entry(device_id);
        debug!("Removed challenge: {}", device_id);
    }

    pub async fn can_request_new_connection(&self, device_id: &String) -> bool {
        let challenges = self.out_challenges.read().await;
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

    let expiration_retainer_fn =
        |now: Instant, mut collection: RwLockWriteGuard<HashMap<String, DeviceChallengeStatus>>| {
            collection.retain(|device_id, status| {
                if let Active {
                    ttl, socket_addr, ..
                } = status
                {
                    if now.duration_since(*ttl).as_secs() >= CHALLENGE_DEATH {
                        println!(
                            "[CLEANUP] Device {} challenge expired. Transitioning to Closed.",
                            device_id
                        );
                        *status = Closed {
                            socket_addr: *socket_addr,
                        };
                    }
                    true
                } else if let Closed { .. } = status {
                    println!(
                        "[CLEANUP] Removing already Closed challenge for device {}.",
                        device_id
                    );
                    false
                } else {
                    true
                }
            });
        };
    loop {
        let now = Instant::now();
        {
            expiration_retainer_fn(now, challenges_arc_clone.in_challenges.write().await);
            expiration_retainer_fn(now, challenges_arc_clone.out_challenges.write().await);
        }

        tokio::time::sleep(Duration::from_secs(15)).await;
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
                                status: Access,
                            })
                            .await
                            .expect(&format!(
                                "Cannot send request for changing status: {}",
                                device_id
                            ));
                    } else {
                        if close_connection {
                            client_manager
                                .bounded_channel
                                .0
                                .send(ChangeStatus {
                                    device_id: device_id.clone(),
                                    status: Denied,
                                })
                                .await
                                .expect(&format!(
                                    "Cannot send request for changing status: {}",
                                    device_id
                                ));
                        }
                    }
                }
                //todo add verification if device is already connected - could be mitm fishing attack
                //incoming
                ChallengeEvent::NewChallengeRequest { device_id, nonce } => {
                    let device = get_device(&device_id).await;
                    if let Some(_device) = device {
                        let mut mtx = challenge_manager.in_challenges.write().await;
                        mtx.insert(
                            device_id,
                            Pending {
                                socket_addr: _device.connect_addr,
                                nonce,
                            },
                        );
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
) -> Result<(bool, bool), CommonThreadError> {
    let challenge_manager = Arc::clone(&DefaultChallengeManager);

    let mut challenges = challenge_manager.out_challenges.write().await;
    let sent_challenge = challenges.get_mut(device_id);

    if let Some(challenge) = sent_challenge {
        if let Active {
            passphrase,
            nonce_hash,
            attempts,
            socket_addr,
            ..
        } = challenge
        {

            let mut error_func = async || {
                info!("Client passphrase invalid");
                *attempts -= 1;

                if *attempts == 0u8 {
                    let mut challenges = challenge_manager.out_challenges.write().await;
                    challenges.remove_entry(device_id);

                    challenges.insert(
                        device_id.clone(),
                        Closed {
                            socket_addr: socket_addr.clone(),
                        },
                    );
                    return Ok((false, true));
                }

                Ok((false, false))
            };

            return match decrypt_with_passphrase(&ciphertext_with_tag, &iv_bytes, &salt, passphrase) {
                Ok(decrypted_hash) => {
                    return if !decrypted_hash.eq(nonce_hash) {
                        error_func().await
                    } else {
                        // let mut challenges = challenge_manager.out_challenges.write().await;
                        // challenges.remove_entry(device_id);

                        Ok((true, false))
                    };
                }
                Err(e) => {
                    error!("Error during client passphrase decryption: {}", e);
                    error_func().await
                }
            }
        }
    }

    Ok((false, false))
}

/**
 * create challenge for device based on fetched hash of passphrase
* and nonce UUID, encoded with Aes128Gcm, amounts of retries of each client is set to base 3 for handling bruteforce
*/
pub async fn generate_challenge(
    device_id: &String,
) -> Result<ServerResponse, Box<dyn Error + Send + Sync>> {
    debug!("Generating challenge for: {}", device_id);

    let default_challenge_manager_arc = Arc::clone(&DefaultChallengeManager);
    let mut challenges = default_challenge_manager_arc.out_challenges.write().await;

    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());

    match get_device(device_id).await {
        None => {
            return Err(Box::new(io::Error::new(
                ErrorKind::NotFound,
                "No device discovered for challenge",
            )));
        }
        Some(device) => match challenges.get(device_id) {
            None => {
                challenges.insert(
                    device_id.clone(),
                    Active {
                        socket_addr: device.connect_addr,
                        nonce_hash: nonce_uuid_hash.as_bytes().to_vec(),
                        passphrase: get_device_passphrase().await,
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
        nonce: nonce_uuid_hash.as_bytes().to_vec(),
    })
}
