use crate::keychain;
use crate::keychain::load_private_key_arc;
use rcgen::{KeyPair, generate_simple_self_signed};
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read};
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tokio::time::{Instant, sleep};
use uuid::Uuid;

//device_id -> _, nonce hash, ttl
type ChallengedDevices = Arc<Mutex<HashMap<String, (SocketAddr, Vec<u8>, Instant)>>>;
#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionRequest {
    InitialRequest {
        device_id: String,
    },
    ChallengeRequest {
        //encoded BLAKE3 x ed25519 string
        nonce: Vec<u8>,
    },
    ChallengeResponse {
        //uuid
        nonce: Vec<u8>,
        //string
        passphrase_hash: Vec<u8>,
    },
    AcceptConnection,
    RejectConnection(String),
}

pub struct ChallengeManager {
    current_challenges: ChallengedDevices,
    //receiver for emitted connection event
    _ch_rx: Receiver<(String, SocketAddr)>,
}

impl ChallengeManager {
    const CLEANUP_DELAY: u64 = 15;
    const CHALLENGE_DEATH: u64 = 60;

    pub fn new(_ch_rx: Receiver<(String, SocketAddr)>) -> ChallengeManager {
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
            let key = Arc::clone(&private_key_arc);
            tokio::select! {
                Some((device_id, socket)) = self._ch_rx.recv() => {
                    let ch_  = challenges.lock().await;
                    if ch_.contains_key(&device_id) {
                         generate_challenge(device_id, socket);
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

            ch_locked.retain(|addr, (_socket_addr, _nonce, ttl)| {
                if now.duration_since(*ttl).as_secs() > Self::CHALLENGE_DEATH {
                    return false;
                }
                true
            })
        }
    }
}

pub fn generate_challenge(device_id: String, remote_addr: SocketAddr) {
    //create TCP/TLS session(server)
    //send nonce encoded in BLAKE3 crypt with ed25519
    //receive N2 hased with passphrase
    //dehash by passphrase and check validity of hash of nonce
    //connect if OK

    //generate nonce
    let nonce_uuid_hash = blake3::hash(Uuid::new_v4().as_bytes());
    let signed = keychain::sign(nonce_uuid_hash.to_string())
        .expect("[CONNECTION] Somehow signing issues occurred ;(");

    //update status
}
