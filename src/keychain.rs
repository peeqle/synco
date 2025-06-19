use crate::utils::get_default_application_dir;
use base32::Alphabet;
use der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use pkcs8::ObjectIdentifier;
use rand::rngs::OsRng;
use rcgen::BasicConstraints::Unconstrained;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, DnValue, IsCa, KeyPair, PKCS_ED25519,
};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::sync::Arc;
use std::{error, fs, io};

const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
const CERT_FILE_NAME: &str = "cert.pem";
const SIGNING_KEY: &str = "signing_key.bin";

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

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
    let mut app_data_dir = get_default_application_dir();

    let key_file_path = app_data_dir.join(SIGNING_KEY);
    match fs::read(key_file_path) {
        Ok(private_key_bytes) => {
            let secret_key_array: [u8; 32] =
                private_key_bytes.as_slice().try_into().map_err(|_| {
                    Box::new(io::Error::new(
                        ErrorKind::InvalidData,
                        "Signing key file has incorrect size (expected 32 bytes)",
                    )) as Box<dyn Error + Send + Sync>
                })?;
            Ok(SigningKey::from(secret_key_array))
        }
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
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

    let mut app_data_dir = get_default_application_dir();

    let key_file_path = app_data_dir.join(SIGNING_KEY);
    let mut file = File::create(&key_file_path)?;
    file.write_all(&private_key_bytes)?;
    println!(
        "Private key stored in plaintext: {}",
        key_file_path.display()
    );

    Ok(())
}

pub fn generate_cert_keys() -> Result<(), Box<dyn Error + Sync + Send>> {
    let mut params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])?;
    let device_id = device_id().expect("Cannot extract device_id");

    let mut cert_name = DistinguishedName::new();
    cert_name.push(DnType::OrganizationName, device_id);
    cert_name.push(
        DnType::CommonName,
        DnValue::PrintableString("synco".try_into().unwrap()),
    );
    //marks the CA as signer
    params.is_ca = IsCa::Ca(Unconstrained);

    let keypair = generate_keypair()?;

    let cert = params.self_signed(&keypair)?;
    let private_key_pem = keypair.serialize_pem();
    let cert_pem = cert.pem();

    let app_data_dir = get_default_application_dir();

    let key_file_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);
    let cert_file_path = app_data_dir.join(CERT_FILE_NAME);

    fs::write(&key_file_path, private_key_pem.as_bytes())?;
    fs::write(&cert_file_path, cert_pem.as_bytes())?;

    Ok(())
}

pub fn generate_keypair() -> Result<KeyPair, Box<dyn Error + Sync + Send>> {
    let current_key = Arc::clone(&DEVICE_SIGNING_KEY);
    let pkcs8_pem = current_key.to_pkcs8_pem(LineEnding::LF)?;

    let rcgen_key_pair = KeyPair::from_pem_and_sign_algo(&pkcs8_pem, &PKCS_ED25519)
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    Ok(rcgen_key_pair)
}

pub(crate) fn load_private_key_arc() -> io::Result<Arc<KeyPair>> {
    let private_key = load_private_key(false)?;
    Ok(Arc::new(private_key))
}

pub(crate) fn load_cert_arc() -> io::Result<Arc<Certificate>> {
    let certs = load_cert(false)?;
    Ok(Arc::new(certs))
}

fn load_cert(called_within: bool) -> io::Result<Certificate> {
    let app_data_dir = get_default_application_dir();
    let cert_path = app_data_dir.join(CERT_FILE_NAME);

    let file = OpenOptions::new().read(true).open(cert_path);
    match file {
        Ok(_) => {
            let mut reader = BufReader::new(file?);
            let mut holder: String = String::new();
            reader.read_to_string(&mut holder)?;

            let cert_iter = CertificateParams::from_ca_cert_pem(&holder).unwrap();
            let loaded_kp = load_private_key_arc()?;

            Ok(cert_iter.self_signed(&loaded_kp).unwrap())
        }
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                if called_within {
                    return Err(err);
                }
                println!("Creating certificates...");
                generate_cert_keys().unwrap();
                load_cert(true)
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

fn load_private_key(called_within: bool) -> io::Result<KeyPair> {
    let app_data_dir = get_default_application_dir();
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
                println!("Creating certificates...");
                generate_cert_keys().unwrap();
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

mod keychain_test {
    use crate::keychain::*;

    #[test]
    fn load_certs_test() {
        let res = load_cert(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract CERT, {}", res.err().unwrap());
        }

        assert_eq!(true, res.is_ok() && !res.unwrap().pem().is_empty());
    }

    #[test]
    fn load_pk_test() {
        let res = load_private_key(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract PK, {}", res.err().unwrap());
        }

        assert_eq!(
            true,
            res.is_ok() && !res.unwrap().serialize_pem().is_empty()
        );
    }
}
