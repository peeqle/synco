use crate::keychain;
use crate::keychain::load_private_key_arc;
use crate::server::{ConnectionRequestQuery, DefaultServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tokio::time::{Instant, sleep};
use uuid::Uuid;

//device_id -> _, nonce hash, ttl
type ChallengedDevices = Arc<Mutex<HashMap<String, DeviceChallengeStatus>>>;

pub struct ChallengeManager {
    current_challenges: ChallengedDevices,
    //receiver for emitted connection event
    _ch_rx: Receiver<ChallengeEvent>,
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
    const CLEANUP_DELAY: u64 = 15;
    const CHALLENGE_DEATH: u64 = 60;

    pub fn new(_ch_rx: Receiver<ChallengeEvent>) -> ChallengeManager {
        ChallengeManager {
            current_challenges: Arc::new(Mutex::new(HashMap::new())),
            _ch_rx,
        }
    }

    //runs challenge for a device and connects sessions
    pub async fn run(&mut self) {
        let cleanup_handle = {
            let _challenges_cleanup = Arc::clone(&self.current_challenges);
            tokio::spawn(async move {
                Self::cleanup(_challenges_cleanup).await;
            })
        };

        let private_key_arc = match load_private_key_arc() {
            Ok(key) => key,
            Err(e) => {
                eprintln!("Error loading private key: {}", e);
                return;
            }
        };

        let challenges = Arc::clone(&self.current_challenges);
        loop {
            tokio::select! {
                Some(event) = self._ch_rx.recv() => {
                    match event {
                        ChallengeEvent::NewDevice{ device_id} => {
                             let ch_  = challenges.lock().await;
                    if ch_.contains_key(&device_id) {
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

    pub async fn cleanup(_challenges: ChallengedDevices) {
        loop {
            sleep(Duration::from_secs(Self::CLEANUP_DELAY)).await;

            let mut ch_locked = _challenges.lock().await;
            let now = Instant::now();

            ch_locked.retain(|_, status| {
                match *status {
                    DeviceChallengeStatus::Active {
                        ttl, socket_addr, ..
                    } => {
                        if now.duration_since(ttl).as_secs() > Self::CHALLENGE_DEATH {
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
        }
    }

    pub async fn verify_challenge_response(&self, device_id: String, response: Vec<u8>) {
        let mut ch_locked = self.current_challenges.lock().await;
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
