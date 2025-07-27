use crate::consts::{CommonThreadError, DeviceId, CERT_FILE_NAME, PRIVATE_KEY_FILE_NAME, SIGNING_KEY};
use crate::utils::{device_id, get_default_application_dir};
use der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, PKCS_ED25519};
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

pub(crate) fn load_private_key_der() -> io::Result<PrivateKeyDer<'static>> {
    let private_key = load_private_key(false)?;
    Ok(PrivateKeyDer::try_from(private_key.serialize_der()).expect("Cannot cast"))
}

pub(crate) fn load_cert_der() -> io::Result<CertificateDer<'static>> {
    let certs: Certificate = load_cert(false)?;
    Ok(CertificateDer::from(certs.der().to_vec()))
}

pub fn load_cert(called_within: bool) -> io::Result<Certificate> {
    let app_data_dir = get_default_application_dir();
    let cert_path = app_data_dir.join(CERT_FILE_NAME);

    let file = OpenOptions::new().read(true).open(cert_path);
    match file {
        Ok(_) => {
            let mut reader = BufReader::new(file?);
            let mut holder: String = String::new();
            reader.read_to_string(&mut holder)?;

            let cert_iter = CertificateParams::from_ca_cert_pem(&holder).unwrap();
            let loaded_kp = load_private_key(false)?;

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

pub fn load_private_key(called_within: bool) -> io::Result<KeyPair> {
    let app_data_dir = get_default_application_dir();
    let key_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);

    let loader: fn(&PathBuf) -> Result<KeyPair, Box<dyn Error>> = |path: &PathBuf| {
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
    };

    match loader(&key_path).map_err(|e| {
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

pub mod node {
    use crate::consts::CommonThreadError;
    use crate::keychain::node_params;
    use crate::utils::{ get_default_application_dir};
    use log::info;
    use rcgen::{ DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
    use std::fs;
    use std::path::PathBuf;

    pub fn generate_node_csr(device_id: String) -> Result<(String, KeyPair), CommonThreadError> {
        info!("Generating CSR for device: {}", device_id);

        let client_keypair = KeyPair::generate()?;

        let csr = node_params(Some(device_id.clone())).serialize_request(&client_keypair)?;
        let csr_pem = csr.pem()?;

        info!("CSR generated for device: {}", device_id);

        Ok((csr_pem, client_keypair))
    }

    pub fn save_node_signed_cert(server_id: String, signed_cert: &str, keypair: KeyPair) -> Result<(PathBuf, PathBuf), CommonThreadError> {
        let app_data_dir = get_default_application_dir();

        let node_cert_path = app_data_dir.join(format!("{}_client_cert.pem", server_id));
        let node_key_path = app_data_dir.join(format!("{}_client_key.pem", server_id));

        let node_key_pem = keypair.serialize_pem();

        fs::write(&node_cert_path, signed_cert.as_bytes())
            .map_err(|e| format!("Failed to write client certificate: {}", e))?;

        fs::write(&node_key_path, node_key_pem.as_bytes())
            .map_err(|e| format!("Failed to write client private key: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Certificate can be readable by others (644)
            let cert_perms = std::fs::Permissions::from_mode(0o644);
            fs::set_permissions(&node_cert_path, cert_perms)?;

            // Private key should be readable only by owner (600)
            let key_perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&node_key_path, key_perms)?;
        }

        info!("Client certificate saved to: {}", node_cert_path.display());
        info!("Client private key saved to: {}", node_key_path.display());

        Ok((node_cert_path, node_key_path))
    }
    
    pub mod load {
        use std::fs;
        use std::io::Cursor;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use crate::consts::CommonThreadError;
        use crate::utils::get_default_application_dir;

        pub fn load_client_cert_pem(device_id: &str) -> Result<String, CommonThreadError> {
            let app_data_dir = get_default_application_dir();
            let client_cert_path = app_data_dir.join(format!("{}_client_cert.pem", device_id));

            if !client_cert_path.exists() {
                return Err(format!("Client certificate not found: {}", client_cert_path.display()).into());
            }

            let cert_pem = fs::read_to_string(&client_cert_path)
                .map_err(|e| format!("Failed to read client certificate: {}", e))?;

            Ok(cert_pem)
        }

        pub fn load_client_key_pem(device_id: &str) -> Result<String, CommonThreadError> {
            let app_data_dir = get_default_application_dir();
            let client_key_path = app_data_dir.join(format!("{}_client_key.pem", device_id));

            if !client_key_path.exists() {
                return Err(format!("Client private key not found: {}", client_key_path.display()).into());
            }

            let key_pem = fs::read_to_string(&client_key_path)
                .map_err(|e| format!("Failed to read client private key: {}", e))?;

            Ok(key_pem)
        }

        pub fn load_client_cert_der(device_id: &str) -> Result<CertificateDer<'static>, CommonThreadError> {
            let cert_pem = load_client_cert_pem(device_id)?;

            let mut cert_reader = Cursor::new(cert_pem.as_bytes());
            let cert_der = rustls_pemfile::certs(&mut cert_reader)
                .next()
                .ok_or("No certificate found in PEM file")?
                .map_err(|e| format!("Failed to parse certificate: {}", e))?;

            Ok(cert_der)
        }

        pub fn load_client_key_der(device_id: &str) -> Result<PrivateKeyDer<'static>, CommonThreadError> {
            let key_pem = load_client_key_pem(device_id)?;

            let mut key_reader = Cursor::new(key_pem.as_bytes());
            let key_der = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| format!("Failed to parse private key: {}", e))?
                .ok_or("No private key found in PEM file")?;

            Ok(key_der)
        }
    }
}

pub fn generate_certs(
    ca_cert_pem: &str,
    ca_key_pem: &str,
    node_ip_address: &str,
) -> Result<(PathBuf, PathBuf), CommonThreadError> {
    let node_name = device_id().unwrap();
    println!("Node CRT generation '{}'...", node_name);

    let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;

    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key_pair)?;


    let server_storage: PathBuf = get_default_application_dir();
    fs::create_dir_all(&server_storage)?;

    let server_keypair = KeyPair::generate()?;

    let mut server_params = CertificateParams::new(vec![])?;
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, format!("{}-server", node_name));
    server_params
        .distinguished_name
        .push(DnType::OrganizationName, "synco P2P Network".to_string());

    server_params.subject_alt_names = vec![SanType::IpAddress(node_ip_address.parse()?)];

    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_params.is_ca = IsCa::NoCa;
    server_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(2027, 1, 1);

    let server_cert = server_params.signed_by(&server_keypair, &ca_cert, &ca_key_pair)?;

    let server_cert_pem = server_cert.pem();
    let server_private_key_pem = server_keypair.serialize_pem();

    let server_cert_path = server_storage.join(format!("{}_server_cert.pem", node_name));
    let server_key_path = server_storage.join(format!("{}_server_key.pem", node_name));

    fs::write(&server_cert_path, server_cert_pem.as_bytes())?;
    fs::write(&server_key_path, server_private_key_pem.as_bytes())?;

    Ok((server_cert_path, server_key_path))
}

pub fn node_params(device: Option<String>) -> CertificateParams {
    let mut csr_params = CertificateParams::new(vec![])
        .unwrap();

    csr_params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(device_id) = device {
        csr_params
            .distinguished_name
            .push(DnType::CommonName, format!("{}-client", device_id));
    }
    csr_params
        .distinguished_name
        .push(DnType::OrganizationName, "synco P2P Network".to_string());

    csr_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    csr_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    csr_params.is_ca = IsCa::NoCa;

    csr_params
}

pub mod server {
    use crate::consts::{CommonThreadError, CA_CERT_FILE_NAME, CA_KEY_FILE_NAME};

    use crate::keychain::{load_cert, load_private_key, node_params};
    use crate::utils::{get_client_cert_storage, get_server_cert_storage};
    use log::info;
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    use std::error::Error;
    use std::fs;
    use std::fs::File;
    use std::path::PathBuf;

    pub fn generate_signing_ca() -> Result<(PathBuf, PathBuf), CommonThreadError> {
        let (ca_path, kp_path) = {
            let server_storage: PathBuf = get_server_cert_storage();
            fs::create_dir_all(&server_storage)?;

            (server_storage.join(CA_CERT_FILE_NAME), server_storage.join(CA_KEY_FILE_NAME))
        };
        if fs::exists(&ca_path)? && fs::exists(&kp_path)? {
            return Ok((ca_path, kp_path));
        }

        info!("Generating new CA certificate for server operations...");

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

        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];

        ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);;
        ca_params.not_after = rcgen::date_time_ymd(2045, 1, 1);

        let ca_keypair = KeyPair::generate()?;

        let ca_cert = ca_params.self_signed(&ca_keypair)?;
        let ca_cert_pem = ca_cert.pem();
        let ca_private_key_pem = ca_keypair.serialize_pem();

        fs::write(&ca_path, ca_cert_pem.as_bytes())?;
        fs::write(&kp_path, ca_private_key_pem.as_bytes())?;

        info!("CA generated and saved at: {}", ca_path.display());
        info!("Keys are generated and saved at: {}", kp_path.display());

        Ok((ca_path, kp_path))
    }

    pub fn sign_client_csr(csr_pem: &str) -> Result<(Vec<u8>, PathBuf), CommonThreadError> {
        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)?;

        let mut node_params = node_params(None);

        node_params.not_before = date_time_ymd(1975, 1, 1);
        node_params.not_after = date_time_ymd(4096, 1, 1);

        let loaded_crt = load_cert(false)?;
        let loaded_pk = load_private_key(false)?;

        let dn_value = node_params
            .distinguished_name
            .get(&DnType::CommonName)
            .unwrap().clone();

        let client_cert = node_params
            .signed_by(&csr.public_key, &loaded_crt, &loaded_pk)?;

        let client_cert_pem = client_cert.pem();

        let dir = get_client_cert_storage();
        fs::create_dir_all(&dir)?;

        let common_name = match dn_value {
            rcgen::DnValue::PrintableString(s) => s.to_string(),
            rcgen::DnValue::Utf8String(s) => s.to_string(),
            rcgen::DnValue::Ia5String(s) => s.to_string(),
            _ => panic!("Unsupported DN value type"),
        };
        let client_cert_file_name = format!("{}_cert.pem", common_name);

        let node_cert_path = dir.join(&client_cert_file_name);

        fs::write(&node_cert_path, client_cert_pem.as_bytes())?;

        println!(
            "Client certificate saved at: {}",
            node_cert_path.display()
        );

        Ok((client_cert_pem.as_bytes().to_vec(), node_cert_path))
    }
}

pub fn sign(msg: String) -> Result<Signature, CommonThreadError> {
    let cp = Arc::clone(&DEVICE_SIGNING_KEY);
    cp.try_sign(msg.as_bytes())
        .map_err(|e| Box::new(e) as CommonThreadError)
}


fn load_signing_key_or_create() -> Result<SigningKey, CommonThreadError> {
    let mut app_data_dir = get_default_application_dir();

    let key_file_path = app_data_dir.join(SIGNING_KEY);
    match fs::read(&key_file_path) {
        Ok(private_key_bytes) => {
            let secret_key_array: [u8; 32] =
                private_key_bytes.as_slice().try_into().map_err(|_| {
                    Box::new(io::Error::new(
                        ErrorKind::InvalidData,
                        "Signing key file has incorrect size (expected 32 bytes)",
                    )) as CommonThreadError
                })?;
            Ok(SigningKey::from(secret_key_array))
        }
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                println!("Signing key file not found. Generating new keychain...");
                generate_new_keychain()?;
                load_signing_key_or_create()
            } else {
                Err(Box::new(e) as CommonThreadError)
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
    let mut params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])?;
    let mut cert_name = DistinguishedName::new();

    cert_name.push(DnType::OrganizationName, DeviceId.to_string());
    cert_name.push(
        DnType::CommonName,
        DnValue::PrintableString("synco".try_into().unwrap()),
    );
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::NoCa;

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
        .map_err(|e| Box::new(e) as CommonThreadError)?;

    Ok(rcgen_key_pair)
}