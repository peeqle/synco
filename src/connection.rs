use crate::consts::CHALLENGE_DEATH;
use crate::keychain;
use crate::server::{ConnectionRequestQuery, DefaultServer};
use lazy_static::lazy_static;
use log::{debug, info};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{sleep, Instant};
use uuid::Uuid;

lazy_static! {
    pub static ref DefaultChallengeManager: Arc<Mutex<Box<ChallengeManager>>> = {
        let channel = mpsc::channel(200);
        Arc::new(Mutex::new(Box::new(ChallengeManager::new(channel))))
    };
}

pub struct ChallengeManager {
    //device_id -> _, nonce hash, ttl
    current_challenges: HashMap<String, DeviceChallengeStatus>,
    //receiver for emitted connection event
    bounded_channel: (Sender<ChallengeEvent>, Arc<Mutex<Receiver<ChallengeEvent>>>),
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
        nonce: String,
        nonce_hash: String,
        passphrase: String,
        attempts: i16,
        ttl: Instant,
    },
    Closed {
        socket_addr: SocketAddr,
    },
}

impl ChallengeManager {
    pub fn new(
        bounded_channel: (Sender<ChallengeEvent>, Receiver<ChallengeEvent>),
    ) -> ChallengeManager {
        ChallengeManager {
            current_challenges: HashMap::new(),
            bounded_channel: (bounded_channel.0, Arc::new(Mutex::new(bounded_channel.1))),
        }
    }

    pub fn get_sender(&self) -> Sender<ChallengeEvent> {
        self.bounded_channel.0.clone()
    }

    fn get_receiver(&self) -> Arc<Mutex<Receiver<ChallengeEvent>>> {
        Arc::clone(&self.bounded_channel.1)
    }
}
pub async fn challenge_manager_listener_run() {
    debug!("[CHALLENGE MANAGER] Starting...");
    let manager_arc = Arc::clone(&DefaultChallengeManager);

    let receiver = {
        let mgr = manager_arc.lock().await;
        mgr.get_receiver().clone()
    };

    debug!("[CHALLENGE MANAGER] Started.");
    loop {
        let mut receiver_guard = receiver.lock().await;

        match receiver_guard.recv().await {
            Some(event) => {
                drop(receiver_guard);
                match event {
                    ChallengeEvent::NewDevice { device_id } => {
                        let exists = {
                            let mgr = manager_arc.lock().await;
                            mgr.current_challenges.contains_key(&device_id)
                        };
                        if exists {
                            generate_challenge(device_id).await;
                        }
                    }
                    ChallengeEvent::ChallengeVerification { .. } => {
                        // handle verification
                    }
                }
            }
            None => {
                debug!("[CHALLENGE MANAGER] Channel closed.");
                break;
            }
        }
    }
}

pub async fn cleanup() {
    let challenges_arc_clone = Arc::clone(&DefaultChallengeManager);
    loop {
        let now = Instant::now();
        let mut challenges_to_notify_closed: Vec<String> = Vec::new();

        let mut ch_locked = challenges_arc_clone.lock().await;

        ch_locked
            .current_challenges
            .retain(|device_id, status| match status {
                DeviceChallengeStatus::Active {
                    ttl, socket_addr, ..
                } => {
                    if now.duration_since(*ttl).as_secs() >= CHALLENGE_DEATH {
                        debug!(
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
                    debug!(
                        "[CLEANUP] Removing already Closed challenge for device {}.",
                        device_id
                    );
                    false
                }
            });
        
        debug!("[CONNECTION] Cleanup finished");
        sleep(Duration::from_secs(10)).await;
    }
}

pub async fn generate_challenge(device_id: String) {
    //create TCP/TLS session(server)
    //send nonce encoded in BLAKE3 crypt with ed25519
    //receive N2 hased with passphrase
    //dehash by passphrase and check validity of hash of nonce
    //connect if OK

    //generate nonce
    debug!("Generating a challenge for: {}", device_id);
    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());
    let signed = keychain::sign(nonce_uuid_hash.to_string())
        .expect("[CONNECTION] Somehow signing issues occurred ;(");

    DefaultServer
        .get_channel_sender()
        .send(ConnectionRequestQuery::ChallengeRequest {
            device_id: String::from(&device_id),
            nonce: signed.to_vec(),
            //todo make passphrase configurable
            passphrase_hash: blake3::hash(b"key").as_bytes().to_vec(),
        })
        .await
        .expect(format!("Cannot generate new challenge for: {}", device_id).as_str());
    debug!("Finished challenge generation for: {}", device_id);
}
