use crate::broadcast::DiscoveredDevice;
use crate::challenge::DeviceChallengeStatus::Active;
use crate::challenge::{DefaultChallengeManager, DeviceChallengeStatus};
use crate::consts::{DEFAULT_APP_SUBDIR, DEFAULT_CLIENT_CERT_STORAGE, DEFAULT_SERVER_CERT_STORAGE};
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use log::{debug, info};
use rustls::RootCertStore;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

pub mod control {
    use std::error::Error;

    pub trait ConnectionStatusVerification {
        fn verify_self(&self) -> Result<bool, Box<dyn Error>>;
    }
}

pub fn get_default_application_dir() -> PathBuf {
    let mut app_data_dir = dirs::data_dir()
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::Unsupported,
                "Could not determine application data directory for this OS.",
            )
        })
        .unwrap();
    app_data_dir.push(DEFAULT_APP_SUBDIR);

    if !fs::exists(&app_data_dir).unwrap() {
        fs::create_dir_all(app_data_dir.clone())
            .map_err(|e| {
                rustls::Error::General(format!(
                    "Failed to create directories at {}, {}",
                    app_data_dir.clone().display(),
                    e
                ))
            })
            .unwrap();
    }

    app_data_dir
}

pub fn verify_permissions<T: AsRef<Path>>(path: T, need_write: bool) -> Result<(), Box<io::Error>> {
    if !fs::exists(path.as_ref())? {
        return Err(Box::new(io::Error::new(
            ErrorKind::NotFound,
            format!("File is not found: {}", path.as_ref().display()).as_str(),
        )));
    }

    let md = fs::metadata(path.as_ref())?;
    let permissions = md.permissions();
    let readonly = permissions.readonly();

    if readonly && need_write {
        return Err(Box::new(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Cannot reach file for write: {}", path.as_ref().display()).as_str(),
        )));
    }

    Ok(())
}

pub(crate) fn load_cas<T: AsRef<Path>>(path: T) -> io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader);
    for cert in certs {
        root_store
            .add(cert?)
            .expect("Cannot add cert to the client's RootCertStore");
    }
    Ok(root_store)
}

/**
Generates client storage on SERVER side for storing signed client PEM
*/
pub fn get_client_cert_storage_server() -> PathBuf {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir.join(DEFAULT_CLIENT_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_CLIENT_CERT_STORAGE)
}

pub fn get_server_cert_storage() -> PathBuf {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir.join(DEFAULT_SERVER_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_SERVER_CERT_STORAGE)
}

pub fn validate_server_cert_present() -> bool {
    let server_cert_path = get_server_cert_storage();
    if server_cert_path.exists() {
        let entries: Vec<_> = fs::read_dir(server_cert_path)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        if entries.is_empty() {
            return false;
        }

        println!("------------------------------");
        for path in entries.into_iter() {
            println!("Found CA: {}", path.file_name().to_str().unwrap());
        }
        return true;
    }
    false
}

pub fn encrypt_with_passphrase(
    nonce_hash: &[u8],
    passphrase: &[u8; 32],
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

    let mut lck = default_challenge_manager_arc
        .current_challenges
        .read()
        .await;
    let current_device_challenge = lck.get(&_device.device_id);

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

    false
}
