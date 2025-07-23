use crate::consts::{
    CA_CERT_FILE_NAME, CA_KEY_FILE_NAME, CERT_FILE_NAME, DeviceId, PRIVATE_KEY_FILE_NAME,
    SIGNING_KEY,
};
use crate::utils::{get_default_application_dir, get_server_cert_storage};
use base32::Alphabet;
use der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Write};
use std::ops::Deref;
use std::path::PathBuf;
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

pub fn generate_server_ca_keys() -> Result<(PathBuf, PathBuf), Box<dyn Error + Send + Sync>> {
    println!("Generating new CA certificate for server operations...");

    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "synco server".to_string());

    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "synco CA".to_string());
    ca_params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "synco".to_string());

    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2045, 1, 1);

    let ca_keypair = KeyPair::generate()?;

    let ca_cert = ca_params.self_signed(&ca_keypair)?;
    let ca_cert_pem = ca_cert.pem();
    let ca_private_key_pem = ca_keypair.serialize_pem();

    let server_storage: PathBuf = get_server_cert_storage();
    fs::create_dir_all(&server_storage)?;

    let ca_cert_path = server_storage.join(CA_CERT_FILE_NAME);
    let ca_key_path = server_storage.join(CA_KEY_FILE_NAME);

    fs::write(&ca_cert_path, ca_cert_pem.as_bytes())?;
    fs::write(&ca_key_path, ca_private_key_pem.as_bytes())?;

    println!("Root CA generated and saved at: {}", ca_cert_path.display());
    println!("Main CA generated and saved at: {}", ca_key_path.display());

    // Generate server certificate signed by CA
    generate_server_cert_signed_by_ca(&ca_cert, &ca_keypair)?;

    Ok((ca_cert_path, ca_key_path))
}

pub fn generate_server_cert_signed_by_ca(
    ca_cert: &Certificate,
    ca_keypair: &KeyPair,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Generating server certificate signed by CA...");

    let mut server_params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])?;
    let mut cert_name = DistinguishedName::new();

    cert_name.push(DnType::OrganizationName, DeviceId.to_string());
    cert_name.push(
        DnType::CommonName,
        DnValue::PrintableString("synco".try_into().unwrap()),
    );
    server_params.distinguished_name = cert_name;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.is_ca = IsCa::NoCa;

    server_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(2045, 1, 1);

    let server_keypair = generate_keypair()?;

    // Sign server certificate with CA
    let server_cert = server_params.signed_by(&server_keypair, ca_cert, ca_keypair)?;
    let server_private_key_pem = server_keypair.serialize_pem();
    let server_cert_pem = server_cert.pem();

    let app_data_dir = get_default_application_dir();

    let key_file_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);
    let cert_file_path = app_data_dir.join(CERT_FILE_NAME);

    fs::write(&key_file_path, server_private_key_pem.as_bytes())?;
    fs::write(&cert_file_path, server_cert_pem.as_bytes())?;

    println!("Server certificate signed by CA and saved at: {}", cert_file_path.display());
    println!("Server private key saved at: {}", key_file_path.display());

    Ok(())
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

    let app_data_dir = get_default_application_dir();

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
    // This function is now deprecated - server certificates are generated
    // by generate_server_cert_signed_by_ca() which is called from generate_server_ca_keys()
    println!("Server certificates are now generated automatically by CA setup");
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
    let private_key = load_server_private_key(false)?;
    Ok(Arc::new(private_key))
}

pub(crate) fn load_cert_arc() -> io::Result<Arc<Certificate>> {
    let certs = load_server_cert(false)?;
    Ok(Arc::new(certs))
}

pub(crate) fn load_private_key_der() -> io::Result<PrivateKeyDer<'static>> {
    let private_key = load_server_private_key(false)?;
    Ok(PrivateKeyDer::try_from(private_key.serialize_der()).expect("Cannot cast"))
}

pub(crate) fn load_cert_der() -> io::Result<CertificateDer<'static>> {
    let certs: Certificate = load_server_cert(false)?;
    Ok(CertificateDer::from(certs.der().to_vec()))
}

fn load_server_cert(called_within: bool) -> io::Result<Certificate> {
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
                println!("Server certificate not found. Generating CA and server certificates...");
                // Generate CA which will also generate the server certificate
                generate_server_ca_keys().map_err(|e| {
                    io::Error::new(ErrorKind::Other, format!("Failed to generate certificates: {}", e))
                })?;
                load_server_cert(true)
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

fn load_server_private_key(called_within: bool) -> io::Result<KeyPair> {
    let app_data_dir = get_default_application_dir();
    let key_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);

    match load_pk(&key_path).map_err(|e| {
        io::Error::new(
            ErrorKind::InvalidData,
            "[CONNECTION] Cannot read PEM to KeyPair",
        )
    }) {
        Ok(pk) => Ok(pk),
        Err(err) => match err.kind() {
            ErrorKind::NotFound => {
                if called_within {
                    return Err(err);
                }
                println!("Server private key not found. Generating CA and server certificates...");
                // Generate CA which will also generate the server certificate and key
                generate_server_ca_keys().map_err(|e| {
                    io::Error::new(ErrorKind::Other, format!("Failed to generate certificates: {}", e))
                })?;
                load_server_private_key(true)
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

pub fn load_crt(path: &PathBuf) -> Result<Certificate, Box<dyn Error + Send + Sync>> {
    if !path.exists() {
        Err(Box::new(io::Error::new(
            ErrorKind::NotFound,
            format!(
                "Cannot find specified PK file: {}",
                path.as_path().display().to_string()
            ),
        )))
    } else {
        let file = File::open(path);
        let mut reader = BufReader::new(file?);
        let mut pem_string = String::new();

        reader.read_to_string(&mut pem_string).unwrap();

        let cert_iter = CertificateParams::from_ca_cert_pem(&pem_string).unwrap();
        let loaded_kp = load_private_key_arc()?;

        Ok(cert_iter.self_signed(&loaded_kp).unwrap())
    }
}

pub fn load_pk(path: &PathBuf) -> Result<KeyPair, Box<dyn Error + Send + Sync>> {
    if !path.exists() {
        Err(Box::new(io::Error::new(
            ErrorKind::NotFound,
            format!(
                "Cannot find specified PK file: {}",
                path.as_path().display().to_string()
            ),
        )))
    } else {
        let file = File::open(path);
        let mut reader = BufReader::new(file?);
        let mut pem_string = String::new();

        reader.read_to_string(&mut pem_string).unwrap();

        Ok(KeyPair::from_pem(&pem_string)?)
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

mod keychain_test {
    use crate::keychain::*;

    #[test]
    fn load_certs_test() {
        let res = load_server_cert(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract CERT, {}", res.err().unwrap());
        }

        assert_eq!(true, res.is_ok() && !res.unwrap().pem().is_empty());
    }

    #[test]
    fn load_pk_test() {
        let res = load_server_private_key(false);
        if res.is_err() {
            panic!("[CONNECTION] Cannot extract PK, {}", res.err().unwrap());
        }

        assert_eq!(
            true,
            res.is_ok() && !res.unwrap().serialize_pem().is_empty()
        );
    }
}
