use crate::consts::{
    DeviceId, CERT_FILE_NAME, PRIVATE_KEY_FILE_NAME,
    SIGNING_KEY,
};
use crate::utils::get_default_application_dir;
use der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey};
use error::Error;
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, DnValue,
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

pub mod server {
    use crate::consts::{CA_CERT_FILE_NAME, CA_KEY_FILE_NAME};
    use crate::keychain::{load_cert, load_private_key};
    use crate::utils::{get_client_cert_storage, get_server_cert_storage};
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    use std::error::Error;
    use std::fs;
    use std::fs::File;
    use std::path::PathBuf;

    pub fn generate_ca_keys() -> Result<(PathBuf, PathBuf), Box<dyn Error + Send + Sync>> {
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

        Ok((ca_cert_path, ca_key_path))
    }

    pub fn sign_client_csr(csr_pem: &str) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        let csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)?;

        let mut client_params = CertificateParams::default();

        client_params.distinguished_name = csr.params.distinguished_name;
        client_params.subject_alt_names = csr.params.subject_alt_names;
        client_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        client_params.is_ca = IsCa::NoCa;
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];

        client_params.not_before = date_time_ymd(1975, 1, 1);
        client_params.not_after = date_time_ymd(4096, 1, 1);

        let loaded_crt = load_cert(false)?;
        let loaded_pk = load_private_key(false)?;

        let client_cert = client_params
            .clone()
            .signed_by(&loaded_pk, &loaded_crt, &loaded_pk)?;

        let client_cert_pem = client_cert.pem();

        let dir = get_client_cert_storage();

        let dn_value = client_params
            .distinguished_name
            .get(&DnType::CommonName)
            .unwrap();

        let common_name = match dn_value {
            rcgen::DnValue::PrintableString(s) => s.to_string(),
            rcgen::DnValue::Utf8String(s) => s.to_string(),
            rcgen::DnValue::Ia5String(s) => s.to_string(),
            _ => panic!("Unsupported DN value type"),
        };
        let client_cert_file_name = format!("{}_cert.pem", common_name);

        let client_cert_path = dir.join(&client_cert_file_name);
        File::create_new(&client_cert_path).expect("File creation exception");

        fs::write(&client_cert_path, client_cert_pem.as_bytes())?;

        println!(
            "Client certificate saved at: {}",
            client_cert_path.display()
        );

        Ok(client_cert_path)
    }
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
        .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)?;

    Ok(rcgen_key_pair)
}


mod test {
    use crate::keychain::server::sign_client_csr;
    use crate::server::tls_utils::clear_client_cert_dir;
    use rcgen::{CertificateParams, DnType, DnValue, KeyPair};
    use uuid::Uuid;

    #[test]
    fn test_client_signing() {
        clear_client_cert_dir();

        let client_pem = create_client_pem_template();
        let server_signed_csr = sign_client_csr(&client_pem);

        if server_signed_csr.is_err() {
            let err = server_signed_csr.err().unwrap();
            panic!("User certificate signing has failed: {}", err);
        }

        assert!(server_signed_csr.unwrap().exists());
    }

    //replace with actual csr generation method
    fn create_client_pem_template() -> String {
        let mut params = CertificateParams::default();
        let ds = &mut params.distinguished_name;
        ds.push(DnType::CommonName, "client".to_string());
        ds.push(
            DnType::OrganizationName,
            DnValue::Utf8String(blake3::hash(Uuid::new_v4().as_bytes().as_slice()).to_string()),
        );

        params.is_ca = rcgen::IsCa::NoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];

        let pk = KeyPair::generate().unwrap();
        let cert = params.serialize_request(&pk).unwrap();

        let csr_pem = cert.pem().unwrap();
        println!("Client CSR:\n{}", csr_pem);

        csr_pem
    }
}