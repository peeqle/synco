use crate::consts::{DEFAULT_APP_SUBDIR, DEFAULT_CLIENT_CERT_STORAGE, DEFAULT_SERVER_CERT_STORAGE};
use crate::keychain::DEVICE_SIGNING_KEY;
use crate::utils::DirType::Action;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base32::Alphabet;
use der::Writer;
use pbkdf2::pbkdf2_hmac;
use rustls::RootCertStore;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, io};

pub mod control {
    use std::error::Error;

    pub trait ConnectionStatusVerification {
        fn verify_self(&self) -> Result<bool, Box<dyn Error>>;
    }
}

pub fn device_id() -> Option<String> {
    let cp = Arc::clone(&DEVICE_SIGNING_KEY);

    let public_key_bytes = cp.verifying_key().to_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&public_key_bytes);
    let hash_result = hasher.finalize();

    let device_id_raw = &hash_result.as_bytes()[..20];

    Some(base32::encode(Alphabet::Rfc4648 { padding: false }, device_id_raw).to_uppercase())
}

pub enum DirType {
    Action,
    Cache,
}

pub fn get_default_application_dir(dir_type: DirType) -> PathBuf {
    let mut app_data_dir = match dir_type {
        DirType::Action => {
            dirs::data_dir()
        }
        DirType::Cache => {
            dirs::cache_dir()
        }
    }.ok_or_else(|| {
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
pub fn get_client_cert_storage() -> PathBuf {
    let dir = get_default_application_dir(Action);
    fs::create_dir_all(&dir.join(DEFAULT_CLIENT_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_CLIENT_CERT_STORAGE)
}

pub fn get_server_cert_storage() -> PathBuf {
    let dir = get_default_application_dir(Action);
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
    passphrase: &[u8],
) -> Result<(Vec<u8>, [u8; 12], [u8; 16]), aes_gcm::Error> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key_bytes = [0u8; 16];
    pbkdf2_hmac::<Sha256>(passphrase, &salt, 100_000, &mut key_bytes);

    let cipher = Aes128Gcm::new_from_slice(&key_bytes).map_err(|_| aes_gcm::Error)?;

    let mut iv_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut iv_bytes);
    let nonce = Nonce::from_slice(&iv_bytes);

    let ciphertext_with_tag = cipher.encrypt(nonce, nonce_hash)?;
    Ok((ciphertext_with_tag, iv_bytes, salt))
}

pub fn decrypt_with_passphrase(
    ciphertext_with_tag: &[u8],
    nonce_bytes: &[u8; 12],
    salt_bytes: &[u8; 16],
    passphrase: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let mut key_bytes = [0u8; 16];
    pbkdf2_hmac::<Sha256>(passphrase, salt_bytes, 100_000, &mut key_bytes);

    let cipher = Aes128Gcm::new_from_slice(&key_bytes).map_err(|_| aes_gcm::Error)?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext_with_tag.as_ref())?;

    Ok(plaintext)
}

mod test {
    use crate::utils::{decrypt_with_passphrase, encrypt_with_passphrase};
    use uuid::Uuid;

    #[test]
    pub fn test_verification() {
        let uuid = Uuid::new_v4();
        let nonce_hash = blake3::hash(uuid.as_bytes());
        let passphrase = "Hello, World!";

        let data_to_encrypt = nonce_hash.as_bytes();

        let enc_response = encrypt_with_passphrase(data_to_encrypt, &passphrase.as_bytes())
            .expect("Cannot encrypt");

        let decr_response = decrypt_with_passphrase(
            &enc_response.0,
            &enc_response.1,
            &enc_response.2,
            passphrase.as_bytes(),
        )
            .expect("Cannot decrypt");

        println!("Decrypted data: {:?}", decr_response);
        assert_eq!(decr_response.as_slice(), data_to_encrypt);
    }
}
