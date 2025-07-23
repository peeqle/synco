use crate::keychain::{load_cert_arc, load_private_key_arc};
use crate::utils::{get_client_cert_storage, get_default_application_dir, get_server_cert_storage};
use rcgen::{
    date_time_ymd, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use std::error::Error;
use std::fs;
use std::fs::File;
use std::path::PathBuf;

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

    use crate::keychain::load_pk;
    use crate::utils::get_server_cert_storage;
    use crate::consts::{CA_CERT_FILE_NAME, CA_KEY_FILE_NAME};
    
    let server_cert_dir = get_server_cert_storage();
    let ca_cert_path = server_cert_dir.join(CA_CERT_FILE_NAME);
    let ca_key_path = server_cert_dir.join(CA_KEY_FILE_NAME);
    
    let ca_cert = crate::keychain::load_crt(&ca_cert_path)?;
    let ca_key = load_pk(&ca_key_path)?;

    let client_cert = client_params
        .clone()
        .signed_by(&ca_key, &ca_cert, &ca_key)?;

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

pub fn clear_client_cert_dir() {
    let dir = get_client_cert_storage();
    fs::remove_dir_all(dir).expect("Cannot clear client cert DIR");
    
    fs::remove_dir_all(get_server_cert_storage())
        .expect("Cannot clear server cert DIR");
    
    fs::remove_dir_all(get_default_application_dir())
        .expect("Cannot clear application DIR");
}

mod crt_test {
    use crate::server::tls_utils::{clear_client_cert_dir, sign_client_csr};
    use crate::utils::get_client_cert_storage;
    use rcgen::{CertificateParams, DnType, DnValue, KeyPair};
    use std::fs;
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
