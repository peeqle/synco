use base32::Alphabet;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use std::io::Write;
use std::sync::Arc;
use std::{error, fs, io};

lazy_static! {
    pub static ref DEVICE_SIGNING_KEY: Arc<SigningKey> = {
        match load_signing_key_or_create() {
            Ok(key) => Arc::new(key),
            Err(e) => {
                panic!("FATAL: Failed to load or create device signing key: {}", e);
            }
        }
    };
}

pub fn sign(msg: String) -> Result<Signature, Box<dyn Error + Send + Sync>> {
    let cp = Arc::clone(&DEVICE_SIGNING_KEY);

    cp.try_sign(msg.as_bytes())
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
}

fn load_signing_key_or_create() -> Result<SigningKey, Box<dyn Error + Send + Sync>> {
    let key_file_path = "signing_key.bin";

    match fs::read(key_file_path) {
        Ok(private_key_bytes) => {
            let secret_key_array: [u8; 32] =
                private_key_bytes.as_slice().try_into().map_err(|_| {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Signing key file has incorrect size (expected 32 bytes)",
                    )) as Box<dyn Error + Send + Sync>
                })?;
            Ok(SigningKey::from(secret_key_array))
        }
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                println!("Signing key file not found. Generating new keychain...");
                generate_new_keychain()?;
                load_signing_key_or_create()
            } else {
                Err(Box::new(e) as Box<dyn Error + Send + Sync>)
            }
        }
    }
}

fn generate_new_keychain() -> Result<(), Box<dyn Error + Sync + Send>> {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let private_key_bytes = signing_key.to_bytes();

    let key_file_path = "signing_key.bin";
    let mut file = fs::File::create(key_file_path)?;
    file.write_all(&private_key_bytes)?;
    println!("Private key stored in plaintext: {}", key_file_path);

    Ok(())
}

pub fn device_id() -> Option<String> {
    let cp = Arc::clone(&DEVICE_SIGNING_KEY);

    let public_key_bytes = cp.verifying_key().to_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&public_key_bytes);
    let hash_result = hasher.finalize();

    let device_id_raw = &hash_result.as_bytes()[..20];
    let device_id =
        base32::encode(Alphabet::Rfc4648 { padding: false }, device_id_raw).to_uppercase();

    Some(device_id)
}
