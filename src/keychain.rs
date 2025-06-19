use base32::Alphabet;
use base64::Engine as _;
use ed25519_dalek::{SecretKey, Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use pkcs8::{AlgorithmIdentifier, PrivateKeyInfo};
use rand::rngs::OsRng;
use rcgen::DnType::{CommonName, OrganizationName};
use rcgen::{CertificateParams, DistinguishedName, DnValue, Ia5String, KeyPair, SanType};
use rustls::pki_types::CertificateDer;
use rustls_pemfile::certs;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{error, fs, io};
use pkcs8::der::Encode;

const DEFAULT_APP_SUBDIR: &str = "synco";
const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
const CERT_FILE_NAME: &str = "cert.pem";
const SIGNING_KEY: &str = "signing_key.bin";

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

pub(crate) fn load_private_key_arc() -> io::Result<Arc<KeyPair>> {
    let private_key = load_private_key(false)?;
    Ok(Arc::new(private_key))
}

pub(crate) fn load_certs_arc() -> io::Result<Arc<Vec<CertificateDer<'static>>>> {
    let certs = load_certs(false)?;
    Ok(Arc::new(certs))
}

fn load_certs(called_within: bool) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut app_data_dir = get_default_application_dir();
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
                let signing_key = Arc::clone(&DEVICE_SIGNING_KEY);
                create_and_save_tls_keys_from_signing_key(signing_key.to_bytes())
                    .expect("Cannot create TLS key");
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

fn load_private_key(called_within: bool) -> io::Result<KeyPair> {
    let mut app_data_dir = get_default_application_dir();
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
                let signing_key = Arc::clone(&DEVICE_SIGNING_KEY);
                create_and_save_tls_keys_from_signing_key(signing_key.to_bytes())
                    .expect("Cannot create TLS key");
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

pub fn create_and_save_tls_keys_from_signing_key(
    secret_key: SecretKey,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir)?;

    println!("Generating new self-signed TLS certificate using existing signing key...");

    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("Cannot generate Certificate params.");

    let current_device_id = device_id().expect("Failed to get device ID for certificate");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(CommonName, DnValue::Utf8String(current_device_id.clone()));
    distinguished_name.push(OrganizationName, DnValue::Utf8String("synco".to_string()));
    params.distinguished_name = distinguished_name;

    params.subject_alt_names.push(SanType::DnsName(
        Ia5String::try_from(current_device_id.clone())
            .expect(format!("Cannot parse Ia5String from {:?}", current_device_id).as_str()),
    ));

    let rcgen_key_pair = KeyPair::tr(secret_key.as_ref()).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to create rcgen KeyPair from SigningKey: {}", e),
        )
    })?;
    
    let private_key_info = PrivateKeyInfo::new(AlgorithmIdentifier {
        oid: spki::ObjectIdentifier::new_unwrap("1.3.101.112"),
        parameters: None,
    }, secret_key.as_ref());

    let pkcs8_der = private_key_info.to_vec()
        .map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to serialize SecretKey to PKCS#8 DER: {}", e),
            )
        })?;


    let cert = params.self_signed(&rcgen_key_pair).map_err(|e| {
        io::Error::new(
            ErrorKind::Other,
            format!("Failed to generate self-signed certificate: {}", e),
        )
    })?;

    let cert_pem = cert.pem();
    let key_pem = rcgen_key_pair.serialize_pem();

    let cert_path = dir.as_path().join(CERT_FILE_NAME);
    let key_path = dir.join(PRIVATE_KEY_FILE_NAME);

    if cert_path.exists() {
        fs::remove_file(&cert_path)?;
    }
    if key_path.exists() {
        fs::remove_file(&key_path)?;
    }

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

pub fn clear_keys() -> io::Result<()> {
    println!("Clearing keystore...");
    let dir = get_default_application_dir();
    fs::remove_dir_all(dir)
}

mod keychain_test {
    use crate::keychain::{load_certs, load_private_key};

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
