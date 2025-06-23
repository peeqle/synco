use crate::consts::{CHALLENGE_DEATH, CLEANUP_DELAY};
use crate::keychain;
use crate::keychain::load_private_key_arc;
use crate::server::{ConnectionRequestQuery, DefaultServer};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Instant, sleep};
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

//runs challenge for a device and connects sessions
pub async fn run() {
    let challenge_manager = Arc::clone(&DefaultChallengeManager);
    let cleanup_handle = {
        let _challenges_cleanup = Arc::clone(&challenge_manager);
        tokio::spawn(async move {
            cleanup().await;
        })
    };

    let private_key_arc = match load_private_key_arc() {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Error loading private key: {}", e);
            return;
        }
    };

    loop {
        let mut manager_lck = challenge_manager.lock().await;
        tokio::select! {
            Some(event) = manager_lck.get_receiver().recv() => {
                match event {
                    ChallengeEvent::NewDevice{ device_id} => {
                         // let ch_  = challenges.lock().await;
                if manager_lck.current_challenges.contains_key(&device_id) {
                     generate_challenge(device_id).await;
                }
                    }
                    ChallengeEvent::ChallengeVerification{ connection_response } => {
                        match connection_response {
                            ConnectionRequestQuery::ChallengeResponse{ device_id,response} => {

                            }
                            _ => {}
                            }
                    }
                }

            },
            else => break
        }
    }
    cleanup_handle.await.ok();
}

pub async fn cleanup() {
    let _challenges_arc_clone = Arc::clone(&DefaultChallengeManager);
    loop {
        let mut ch_locked = _challenges_arc_clone.lock().await;
        let now = Instant::now();

        ch_locked.as_mut().current_challenges.retain(|_, status| {
            match *status {
                DeviceChallengeStatus::Active {
                    ttl, socket_addr, ..
                } => {
                    if now.duration_since(ttl).as_secs() > CHALLENGE_DEATH {
                        *status = DeviceChallengeStatus::Closed { socket_addr };
                        return true;
                    }
                }
                DeviceChallengeStatus::Closed { .. } => {
                    return false;
                }
            }
            true
        });
        sleep(Duration::from_secs(CLEANUP_DELAY)).await;
    }
}

pub async fn generate_challenge(device_id: String) {
    //create TCP/TLS session(server)
    //send nonce encoded in BLAKE3 crypt with ed25519
    //receive N2 hased with passphrase
    //dehash by passphrase and check validity of hash of nonce
    //connect if OK

    //generate nonce
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
}
