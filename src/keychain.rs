use crate::consts::{CommonThreadError, DeviceId, CERT_FILE_NAME, LEAF_CERT_NAME, LEAF_KEYS_NAME, PRIVATE_KEY_FILE_NAME, SIGNING_KEY};
use crate::keychain::server::generate_root_ca;
use crate::utils::DirType::Action;
use crate::utils::{get_default_application_dir, get_server_cert_storage};
use der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Cursor, ErrorKind, Read, Write};
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

pub(crate) fn load_leaf_cert_der() -> Result<CertificateDer<'static>, CommonThreadError> {
    let leaf_cert_path = get_server_cert_storage().join(LEAF_CERT_NAME);

    if !leaf_cert_path.exists() {
        server::generate_leaf_crt()?;
    }

    let leaf_cert_pem = fs::read_to_string(&leaf_cert_path)
        .map_err(|e| format!("Failed to read leaf certificate: {}", e))?;

    let mut cert_reader = Cursor::new(leaf_cert_pem.as_bytes());
    let leaf_cert_der = rustls_pemfile::certs(&mut cert_reader)
        .next()
        .ok_or("No certificate found in leaf PEM file")?
        .map_err(|e| format!("Failed to parse leaf certificate: {}", e))?;

    Ok(leaf_cert_der)
}

pub(crate) fn load_leaf_private_key_der() -> Result<PrivateKeyDer<'static>, CommonThreadError> {
    let leaf_key_path = get_server_cert_storage().join(LEAF_KEYS_NAME);

    if !leaf_key_path.exists() {
        server::generate_leaf_crt()?;
    }

    let leaf_key_pem = fs::read_to_string(&leaf_key_path)
        .map_err(|e| format!("Failed to read leaf private key: {}", e))?;

    let mut key_reader = Cursor::new(leaf_key_pem.as_bytes());
    let leaf_key_der = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("Failed to parse leaf private key: {}", e))?
        .ok_or("No private key found in leaf key PEM file")?;

    Ok(leaf_key_der)
}

pub fn load_cert(called_within: bool) -> io::Result<Certificate> {
    let file = OpenOptions::new().read(true).open(get_default_application_dir(Action).join(CERT_FILE_NAME));
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
    let app_data_dir = get_default_application_dir(Action);
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
    use crate::consts::{CommonThreadError, CERT_FILE_NAME, DEFAULT_CLIENT_CERT_STORAGE, PRIVATE_KEY_FILE_NAME};
    use crate::utils::get_default_application_dir;
    use crate::utils::DirType::Action;
    use log::info;
    use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
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
        let client_keys_storage = get_default_application_dir(Action)
            .join(&DEFAULT_CLIENT_CERT_STORAGE).join(&server_id);
        fs::create_dir_all(&client_keys_storage)?;

        let node_cert_path = client_keys_storage.join(CERT_FILE_NAME);
        let node_key_path = client_keys_storage.join(PRIVATE_KEY_FILE_NAME);

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

    pub fn node_params(device: Option<String>) -> CertificateParams {
        let mut csr_params = CertificateParams::new(vec![])
            .unwrap();

        csr_params.distinguished_name = DistinguishedName::new();
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

    pub mod load {
        use crate::consts::{CommonThreadError, CERT_FILE_NAME, DEFAULT_CLIENT_CERT_STORAGE, PRIVATE_KEY_FILE_NAME};
        use crate::utils::DirType::Action;
        use crate::utils::{get_default_application_dir, get_server_cert_storage};
        use log::info;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use std::fs;
        use std::io::Cursor;

        pub fn load_server_signed_cert_der(server_id: &str) -> Result<CertificateDer<'static>, CommonThreadError> {
            let client_keys_storage = get_default_application_dir(Action)
                .join(&DEFAULT_CLIENT_CERT_STORAGE).join(server_id);

            if !client_keys_storage.exists() {
                return Err(format!("Server CA certificate not found at: {}", client_keys_storage.display()).into());
            }

            let ca_cert_pem = fs::read_to_string(&client_keys_storage.join(CERT_FILE_NAME))
                .map_err(|e| format!("Failed to read server CA certificate: {}", e))?;

            let mut cert_reader = Cursor::new(ca_cert_pem.as_bytes());
            let ca_cert_der = rustls_pemfile::certs(&mut cert_reader)
                .next()
                .ok_or("No certificate found in server CA PEM file")?
                .map_err(|e| format!("Failed to parse server CA certificate: {}", e))?;

            Ok(ca_cert_der)
        }

        pub fn node_cert_exists(server_id: &str) -> bool {
            let client_keys_storage = get_default_application_dir(Action)
                .join(&DEFAULT_CLIENT_CERT_STORAGE).join(server_id);
            let node_cert_path = client_keys_storage.join(CERT_FILE_NAME);
            let node_key_path = client_keys_storage.join(PRIVATE_KEY_FILE_NAME);

            let exists = node_cert_path.exists() && node_key_path.exists();
            info!("Certificate check for {}: cert={}, key={}, both={}", 
          server_id,
          node_key_path.exists(),
          node_cert_path.exists(),
          exists);
            exists
        }

        pub fn load_node_cert_pem(server_id: &str) -> Result<String, CommonThreadError> {
            let client_keys_storage = get_default_application_dir(Action)
                .join(&DEFAULT_CLIENT_CERT_STORAGE).join(server_id);
            let node_cert_path = client_keys_storage.join(CERT_FILE_NAME);

            if !node_cert_path.exists() {
                return Err(format!("Client certificate not found: {}", node_cert_path.display()).into());
            }

            let cert_pem = fs::read_to_string(&node_cert_path)
                .map_err(|e| format!("Failed to read client certificate: {}", e))?;

            Ok(cert_pem)
        }

        pub fn load_node_key_pem(server_id: &str) -> Result<String, CommonThreadError> {
            let client_keys_storage = get_default_application_dir(Action)
                .join(&DEFAULT_CLIENT_CERT_STORAGE).join(server_id);
            let node_key_path = client_keys_storage.join(PRIVATE_KEY_FILE_NAME);

            if !node_key_path.exists() {
                return Err(format!("Client private key not found: {}", node_key_path.display()).into());
            }

            let key_pem = fs::read_to_string(&node_key_path)
                .map_err(|e| format!("Failed to read client private key: {}", e))?;

            Ok(key_pem)
        }

        pub fn load_node_cert_der(device_id: &str) -> Result<CertificateDer<'static>, CommonThreadError> {
            let cert_pem = load_node_cert_pem(device_id)?;

            let mut cert_reader = Cursor::new(cert_pem.as_bytes());
            let cert_der = rustls_pemfile::certs(&mut cert_reader)
                .next()
                .ok_or("No certificate found in PEM file")?
                .map_err(|e| format!("Failed to parse certificate: {}", e))?;

            Ok(cert_der)
        }

        pub fn load_node_key_der(device_id: &str) -> Result<PrivateKeyDer<'static>, CommonThreadError> {
            let key_pem = load_node_key_pem(device_id)?;

            let mut key_reader = Cursor::new(key_pem.as_bytes());
            let key_der = rustls_pemfile::private_key(&mut key_reader)
                .map_err(|e| format!("Failed to parse private key: {}", e))?
                .ok_or("No private key found in PEM file")?;

            Ok(key_der)
        }
    }
}

pub mod server {
    use crate::consts::{of_type, CommonThreadError, CA_CERT_FILE_NAME, CA_KEY_FILE_NAME, CERT_FILE_NAME, LEAF_CERT_NAME, LEAF_KEYS_NAME};

    use crate::keychain::server::load::load_leaf_crt;
    use crate::keychain::{create_leaf_ca_params, create_root_ca_params, generate_cert_keys, load_cert, load_private_key};
    use crate::utils::DirType::Action;
    use crate::utils::{get_client_cert_storage, get_default_application_dir, get_server_cert_storage};
    use log::info;
    use log::Level::Error;
    use rcgen::IsCa::NoCa;
    use rcgen::{date_time_ymd, BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType};
    use std::fs;
    use std::fs::File;
    use std::io::{ErrorKind, Write};
    use std::path::PathBuf;

    pub fn generate_root_ca() -> Result<(PathBuf, PathBuf), CommonThreadError> {
        let (ca_path, kp_path) = {
            let server_storage: PathBuf = get_default_application_dir(Action);
            fs::create_dir_all(&server_storage)?;
            (server_storage.join(CA_CERT_FILE_NAME), server_storage.join(CA_KEY_FILE_NAME))
        };

        if fs::exists(&ca_path)? && fs::exists(&kp_path)? {
            return Ok((ca_path, kp_path));
        }

        info!("Generating new CA certificate for server operations...");

        let ca_params = create_root_ca_params()?;
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

    pub fn generate_leaf_crt() -> Result<(PathBuf, PathBuf), CommonThreadError> {
        let leaf_cert_path = get_server_cert_storage().join(LEAF_CERT_NAME);
        let leaf_key_path = get_server_cert_storage().join(LEAF_KEYS_NAME);

        if leaf_cert_path.exists() && leaf_key_path.exists() {
            return Ok((leaf_cert_path, leaf_key_path));
        }

        let (ca_cert_path, ca_key_path) = generate_root_ca()?;

        let ca_cert_pem = fs::read_to_string(&ca_cert_path)?;
        let ca_key_pem = fs::read_to_string(&ca_key_path)?;

        let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;
        let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;

        let leaf_keypair = KeyPair::generate()?;

        let leaf_params = create_leaf_ca_params()?;

        let leaf_cert = leaf_params.signed_by(&leaf_keypair, &ca_cert, &ca_key_pair)?;

        let leaf_cert_pem = leaf_cert.pem();
        let leaf_key_pem = leaf_keypair.serialize_pem();

        fs::write(&leaf_cert_path, leaf_cert_pem.as_bytes())?;
        fs::write(&leaf_key_path, leaf_key_pem.as_bytes())?;

        info!("Leaf certificate generated and saved at: {}", leaf_cert_path.display());
        info!("Leaf private key saved at: {}", leaf_key_path.display());

        Ok((leaf_cert_path, leaf_key_path))
    }

    pub fn sign_client_csr(csr_pem: &str) -> Result<Vec<u8>, CommonThreadError> {
        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)?;

        let (ca_cert_path, ca_key_path) = generate_root_ca()?;
        let ca_cert_pem = fs::read_to_string(&ca_cert_path)?;
        let ca_key_pem = fs::read_to_string(&ca_key_path)?;

        let ca_key_pair = KeyPair::from_pem(&ca_key_pem)?;

        let ca_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
        let ca_cert = ca_params.self_signed(&ca_key_pair)?;

        let client_cert = csr.signed_by(&ca_cert, &ca_key_pair)?;

        let client_cert_pem = client_cert.pem();

        let dir = get_client_cert_storage();
        fs::create_dir_all(&dir)?;

        Ok(client_cert_pem.as_bytes().to_vec())
    }

    pub fn save_server_cert(device_id: String, cert: String) -> Result<(), CommonThreadError> {
        let dir = get_server_cert_storage().join(&device_id);
        fs::create_dir_all(&dir)?;

        let file_path = dir.join(CERT_FILE_NAME);
        let mut file = File::create(&file_path)?;

        file.write_all(cert.as_bytes())?;

        Ok(())
    }

    pub mod load {
        use crate::consts::{of_type, CommonThreadError, CERT_FILE_NAME, LEAF_CERT_NAME};
        use crate::keychain::server::generate_root_ca;
        use crate::utils::get_server_cert_storage;
        use rustls_pki_types::CertificateDer;
        use std::fs;
        use std::io::{Cursor, ErrorKind};

        /**
        *Load server signed CA from client's storage for verification
        */
        pub fn load_server_signed_ca(server_id: &String) -> Result<CertificateDer<'static>, CommonThreadError> {
            let ca_cert_path = get_server_cert_storage()
                .join(&server_id)
                .join(CERT_FILE_NAME);

            if !ca_cert_path.exists() {
                return Err(format!("Server CA certificate not found: {}", ca_cert_path.display()).into());
            }

            let ca_cert_pem = fs::read_to_string(&ca_cert_path)
                .map_err(|e| format!("Failed to read server CA certificate: {}", e))?;

            let mut cert_reader = Cursor::new(ca_cert_pem.as_bytes());
            let ca_cert_der = rustls_pemfile::certs(&mut cert_reader)
                .next()
                .ok_or("No certificate found in server CA PEM file")?
                .map_err(|e| format!("Failed to parse server CA certificate: {}", e))?;

            Ok(ca_cert_der)
        }

        /**
        PEM
        */
        pub fn load_leaf_crt() -> Result<String, CommonThreadError> {
            let leaf_cert_path = get_server_cert_storage().join(LEAF_CERT_NAME);

            if !leaf_cert_path.exists() {
                return Err(of_type("Cannot find leaf crt", ErrorKind::Other));
            }

            match fs::read_to_string(&leaf_cert_path) {
                Ok(res) => {
                    Ok(res)
                }
                Err(e) => {
                    Err(of_type("Cannot read leaf crt", ErrorKind::Other))
                }
            }
        }

        pub fn load_server_crt_pem() -> Result<String, CommonThreadError> {
            let (cert_path, _) = generate_root_ca()?;

            let crt = fs::read_to_string(&cert_path)
                .map_err(|e| format!("Failed to read CRT: {}", e))?;

            Ok(crt)
        }
    }
}

pub fn sign(msg: String) -> Result<Signature, CommonThreadError> {
    let cp = Arc::clone(&DEVICE_SIGNING_KEY);
    cp.try_sign(msg.as_bytes())
        .map_err(|e| Box::new(e) as CommonThreadError)
}


fn load_signing_key_or_create() -> Result<SigningKey, CommonThreadError> {
    let mut app_data_dir = get_default_application_dir(Action);

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

    let app_data_dir = get_default_application_dir(Action);

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
    let (ca_cert_path, ca_key_path) = generate_root_ca()?;

    let ca_key_pem = fs::read_to_string(&ca_key_path)?;
    let ca_key_pair = rcgen::KeyPair::from_pem(&ca_key_pem)?;

    let ca_params = create_root_ca_params()?;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])?;
    let mut cert_name = DistinguishedName::new();

    cert_name.push(DnType::OrganizationName, DeviceId.to_string());
    cert_name.push(
        DnType::CommonName,
        DnValue::PrintableString("synco".try_into().unwrap()),
    );
    params.distinguished_name = cert_name;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.is_ca = IsCa::NoCa;

    let keypair = generate_keypair()?;

    let cert = params.signed_by(&keypair, &ca_cert, &ca_key_pair)?;
    let private_key_pem = keypair.serialize_pem();
    let cert_pem = cert.pem();

    let app_data_dir = get_default_application_dir(Action);
    let key_file_path = app_data_dir.join(PRIVATE_KEY_FILE_NAME);
    let cert_file_path = app_data_dir.join(CERT_FILE_NAME);

    fs::write(&key_file_path, private_key_pem.as_bytes())?;
    fs::write(&cert_file_path, cert_pem.as_bytes())?;

    Ok(())
}


fn create_root_ca_params() -> Result<CertificateParams, CommonThreadError> {
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "synco server".to_string());
    ca_params.distinguished_name.push(DnType::OrganizationName, "synco CA".to_string());
    ca_params.distinguished_name.push(DnType::OrganizationalUnitName, "synco".to_string());
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyAgreement];
    ca_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth, ExtendedKeyUsagePurpose::ServerAuth];
    ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    Ok(ca_params)
}

fn create_leaf_ca_params() -> Result<CertificateParams, CommonThreadError> {
    use crate::machine_utils::get_local_ip;

    let local_ip = get_local_ip().ok_or("Could not determine local IP address")?;

    let san_entries = vec![
        local_ip.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];

    let mut ca_params = CertificateParams::new(san_entries)?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(DnType::CommonName, "synco server".to_string());
    ca_params.distinguished_name.push(DnType::OrganizationName, "synco CA".to_string());
    ca_params.distinguished_name.push(DnType::OrganizationalUnitName, "synco".to_string());
    ca_params.is_ca = IsCa::NoCa;
    ca_params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    ca_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    ca_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    Ok(ca_params)
}

pub fn generate_keypair() -> Result<KeyPair, Box<dyn Error + Sync + Send>> {
    let current_key = Arc::clone(&DEVICE_SIGNING_KEY);
    let pkcs8_pem = current_key.to_pkcs8_pem(LineEnding::LF)?;

    let rcgen_key_pair = KeyPair::from_pem_and_sign_algo(&pkcs8_pem, &PKCS_ED25519)
        .map_err(|e| Box::new(e) as CommonThreadError)?;

    Ok(rcgen_key_pair)
}