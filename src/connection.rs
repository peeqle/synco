use crate::keychain;
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

const DEFAULT_APP_SUBDIR: &str = "synco";
const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
const CERT_FILE_NAME: &str = "cert.pem";

//device_id -> _, nonce hash, ttl
type ChallengedDevices = Arc<Mutex<HashMap<String, (SocketAddr, Vec<u8>, Instant)>>>;
#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionRequest {
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
    //create TCP/TLS session
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

fn load_certs(called_within: bool) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut app_data_dir = dirs::data_dir().ok_or_else(|| {
        io::Error::new(
            ErrorKind::Unsupported,
            "Could not determine application data directory for this OS.",
        )
    })?;
    app_data_dir.push(DEFAULT_APP_SUBDIR);
    fs::create_dir_all(app_data_dir.clone())
        .map_err(|e| {
            rustls::Error::General(format!(
                "Failed to create directories at {}, {}",
                app_data_dir.clone().display(),
                e
            ))
        })
        .unwrap();

    let cert_path = app_data_dir.join(CERT_FILE_NAME);

    let file = OpenOptions::new().read(true).open(cert_path);
    match file {
        Ok(_) => {
            let mut reader = BufReader::new(file?);

            let cert_iter = certs(&mut reader);
            Ok(cert_iter.filter_map(|r| r.ok()).collect())
        }
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                if called_within {
                    return Err(err);
                }
                println!("File is not found - creating...");
                create_and_save_keys()?;
                load_certs(true)
            }
            ErrorKind::PermissionDenied => {
                eprintln!(
                    "[KEYS] Cannot generate keys for the server startup, generate them at: /keys..."
                );
                Err(err)
            }
            _ => Err(err),
        },
    }
}
fn load_private_key_arc() -> io::Result<Arc<KeyPair>> {
    let private_key = load_private_key(false)?;
    Ok(Arc::new(private_key))
}

fn load_private_key(called_within: bool) -> io::Result<KeyPair> {
    let mut app_data_dir = dirs::data_dir().ok_or_else(|| {
        io::Error::new(
            ErrorKind::Unsupported,
            "Could not determine application data directory for this OS.",
        )
    })?;
    app_data_dir.push(DEFAULT_APP_SUBDIR);
    let key_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);

    let file = OpenOptions::new().read(true).open(&key_path);
    match file {
        Ok(_) => {
            let mut reader = BufReader::new(file?);
            let mut pem_string = "".to_string();
            reader.read_to_string(&mut pem_string).expect(
                format!(
                    "Cannot properly read loaded key - check it {:?}",
                    key_path.display()
                )
                .as_str(),
            );

            KeyPair::from_pem(&pem_string).map_err(|e| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "[CONNECTION] Cannot read PEM to KeyPair",
                )
            })
        }
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                if called_within {
                    return Err(err);
                }
                println!("File is not found - creating...");
                create_and_save_keys()?;
                load_private_key(true)
            }
            ErrorKind::PermissionDenied => {
                eprintln!(
                    "[KEYS] Cannot generate keys for the server startup, generate them at: /keys..."
                );
                Err(err)
            }
            _ => Err(err),
        },
    }
}

pub fn create_and_save_keys() -> io::Result<()> {
    let dir = get_default_application_dir();
    println!("Generating keys directory at {}...", dir.display());
    fs::create_dir_all(&dir)?;

    println!("Generating new self-signed certificate and private key...");

    let cert_key_pair = generate_simple_self_signed(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "192.168.1.100".to_string(),
    ])
    .map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to generate self-signed certificate: {}", e),
        )
    })?;

    let cert_pem = cert_key_pair.cert.pem();
    let key_pem = cert_key_pair.key_pair.serialize_pem();

    let cert_path = dir.as_path().join("cert.pem");
    try_create_if_absent(&cert_path);

    let key_path = dir.join("key.pem");
    try_create_if_absent(&key_path);

    fs::write(&cert_path, cert_pem.as_bytes())?;
    println!("Certificate saved to: {}", cert_path.display());

    fs::write(&key_path, key_pem.as_bytes())?;
    println!("Private key saved to: {}", key_path.display());

    Ok(())
}

fn try_create_if_absent(path: &Path) {
    match fs::exists(path) {
        Ok(res) => {
            if !res {
                println!("[CONNECTION] Created file at {}", path.display());
                File::create_new(path).unwrap();
            }
        }
        Err(_) => {}
    }
}

fn get_default_application_dir() -> PathBuf {
    let mut app_data_dir = dirs::data_dir()
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::Unsupported,
                "Could not determine application data directory for this OS.",
            )
        })
        .unwrap();
    app_data_dir.push(DEFAULT_APP_SUBDIR);

    app_data_dir
}

mod connection_test {
    use crate::connection::{load_certs, load_private_key};

    #[test]
    fn load_certs_TEST() {
        let res = load_certs(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract CERT, {}", res.err().unwrap());
        }

        assert_eq!(1, res.unwrap().iter().count());
    }

    #[test]
    fn load_pk_TEST() {
        let res = load_private_key(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract PK, {}", res.err().unwrap());
        }

        assert_eq!(false, res.is_err());
    }
}
