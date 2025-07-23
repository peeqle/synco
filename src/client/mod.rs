use crate::consts::CA_CERT_FILE_NAME;
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::{load_cert_der, load_private_key_der, generate_keypair};
use crate::server::model::ConnectionState::Unknown;
use crate::server::model::{ConnectionState, ServerTcpPeer, TcpServer};
use crate::utils::{get_client_cert_storage, get_server_cert_storage, load_cas};
use lazy_static::lazy_static;
use log::info;
use rustls::client::WebPkiServerVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{IpAddr, Ipv4Addr, ServerName};
use rustls_pemfile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::hash::Hash;
use std::io;
use std::io::{BufReader, ErrorKind};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::{TlsConnector, TlsStream};
use rcgen::{CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
use std::fs;
use std::path::PathBuf;
use crate::consts::{DeviceId, PRIVATE_KEY_FILE_NAME, CERT_FILE_NAME};
use crate::utils::get_default_application_dir;

lazy_static! {
    pub static ref DefaultClientManager: Arc<ClientManager> = {
        let (sender, receiver) = mpsc::channel::<ClientActivity>(500);
        Arc::new( ClientManager {
            connections:Arc::new(Mutex::new(HashMap::new())),
            bounded_channel: (sender, Mutex::new(receiver)) 
        })
    };
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientActivity {
    OpenConnection { device_id: String }
}

pub struct ClientManager {
    connections: Arc<Mutex<HashMap<String, TcpClient>>>,
    pub bounded_channel: (Sender<ClientActivity>, Mutex<Receiver<ClientActivity>>),
}

#[derive(Clone, Debug)]
pub struct TcpClient {
    server_id: String,
    configuration: Arc<ClientConfig>,
    pub connection: Arc<Mutex<Option<ClientTcpPeer>>>,
}
#[derive(Clone, Debug)]
pub struct ClientTcpPeer {
    pub connection: Arc<Mutex<tokio_rustls::client::TlsStream<TcpStream>>>,
    pub connection_status: ConnectionState,
    pub sender: Sender<String>,
}

impl TcpClient {
    pub fn new(server_id: String) -> Result<TcpClient, Box<dyn Error + Send + Sync>> {
        Ok(TcpClient {
            server_id,
            configuration: Arc::new(Self::create_client_config()?),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    fn create_client_config() -> Result<ClientConfig, Box<dyn Error + Send + Sync>> {
        // Generate or load client certificate (not server certificate!)
        let (client_cert, client_key) = Self::get_or_generate_client_cert()?;

        let ca_verification = load_cas(&get_server_cert_storage().join(CA_CERT_FILE_NAME))?;

        let client_cert_verifier: Arc<WebPkiServerVerifier> = {
            WebPkiServerVerifier::builder(Arc::new(ca_verification))
                .build()
                .map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Failed to build client verifier: {:?}", e),
                    )
                })?
        };

        let config = ClientConfig::builder()
            .with_webpki_verifier(client_cert_verifier)
            .with_client_auth_cert(vec![client_cert], client_key)?;
        Ok(config)
    }

    fn get_or_generate_client_cert() -> Result<(rustls_pki_types::CertificateDer<'static>, rustls_pki_types::PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
        let client_cert_dir = get_client_cert_storage();
        let client_cert_path = client_cert_dir.join("client_cert.pem");
        let client_key_path = client_cert_dir.join("client_key.pem");

        // Check if client certificate already exists
        if client_cert_path.exists() && client_key_path.exists() {
            println!("Loading existing client certificate...");
            return Self::load_client_cert(&client_cert_path, &client_key_path);
        }

        // Generate new client certificate
        println!("Generating new client certificate...");
        Self::generate_client_cert(&client_cert_path, &client_key_path)
    }

    fn load_client_cert(cert_path: &PathBuf, key_path: &PathBuf) -> Result<(rustls_pki_types::CertificateDer<'static>, rustls_pki_types::PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
        // Load certificate
        let cert_pem = fs::read_to_string(cert_path)?;
        let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next()
            .ok_or("No certificate found in file")??;

        // Load private key
        let key_pem = fs::read_to_string(key_path)?;
        let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
            .ok_or("No private key found in file")?;

        Ok((cert_der, key_der))
    }

    fn generate_client_cert(cert_path: &PathBuf, key_path: &PathBuf) -> Result<(rustls_pki_types::CertificateDer<'static>, rustls_pki_types::PrivateKeyDer<'static>), Box<dyn Error + Send + Sync>> {
        // Generate client certificate parameters
        let mut client_params = CertificateParams::default();
        client_params.distinguished_name.push(DnType::CommonName, format!("synco-client-{}", DeviceId.clone()));
        client_params.distinguished_name.push(DnType::OrganizationName, "synco client".to_string());
        
        client_params.extended_key_usages.push(ExtendedKeyUsagePurpose::ClientAuth);
        client_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        client_params.is_ca = IsCa::NoCa;

        client_params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        client_params.not_after = rcgen::date_time_ymd(2045, 1, 1);

        // Generate keypair for client
        let client_keypair = generate_keypair()?;

        // Load CA certificate and key for signing
        use crate::keychain::load_pk;
        use crate::consts::{CA_CERT_FILE_NAME, CA_KEY_FILE_NAME};
        
        let server_cert_dir = get_server_cert_storage();
        let ca_cert_path = server_cert_dir.join(CA_CERT_FILE_NAME);
        let ca_key_path = server_cert_dir.join(CA_KEY_FILE_NAME);
        
        let ca_cert = crate::keychain::load_crt(&ca_cert_path)?;
        let ca_key = load_pk(&ca_key_path)?;

        // Sign client certificate with CA
        let client_cert = client_params.signed_by(&client_keypair, &ca_cert, &ca_key)?;
        
        let client_cert_pem = client_cert.pem();
        let client_key_pem = client_keypair.serialize_pem();

        // Save certificate and key
        fs::create_dir_all(cert_path.parent().unwrap())?;
        fs::write(cert_path, client_cert_pem.as_bytes())?;
        fs::write(key_path, client_key_pem.as_bytes())?;

        println!("Client certificate generated and saved at: {}", cert_path.display());
        println!("Client private key saved at: {}", key_path.display());

        // Convert to DER format for rustls
        let cert_der = rustls_pki_types::CertificateDer::from(client_cert.der().to_vec());
        let key_der = rustls_pki_types::PrivateKeyDer::try_from(client_keypair.serialize_der())?;

        Ok((cert_der, key_der))
    }
}
pub async fn run(_manager: Arc<ClientManager>) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting client...");
    let res = tokio::try_join!(
        tokio::spawn(listen(Arc::clone(&_manager))),
    );
    Ok(())
}


async fn listen(_manager: Arc<ClientManager>) {
    let handle_fn = async |x: ClientActivity| {
        match x {
            ClientActivity::OpenConnection { device_id } => {
                open_connection(device_id.clone()).await
                    .expect(&format!("Cannot open connection for: {}", device_id));
            }
        }
    };
    loop {
        let mut receiver = _manager.bounded_channel.1.lock().await;
        tokio::select! {
                 Some(message) = receiver.recv() => handle_fn(message).await
        }
    }
}


async fn open_connection(server_id: String) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Opening connection to: {}", &server_id);
    let device_manager = Arc::clone(&DefaultDeviceManager);
    if let Some(device) = device_manager.known_devices.read().await.get(&server_id) {
        let stream = TcpStream::connect(&device.connect_addr).await?;

        let client = TcpClient::new(device.device_id.clone())?;
        let connector = TlsConnector::from(client.configuration.clone());

        if let Ok(e) = connector.connect(ServerName::IpAddress(
            IpAddr::V4(Ipv4Addr::try_from(device.connect_addr.ip().to_string().as_str())?)), stream).await {
            let (client_sender, mut client_receiver) = mpsc::channel(200);
            let mut mtx = client.connection.lock().await;

            mtx.replace(ClientTcpPeer {
                connection: Arc::new(Mutex::new(e)),
                connection_status: Unknown,
                sender: client_sender,
            });
            drop(mtx);

            {
                tokio::spawn(async move {
                    loop {
                        while let Some(message) = client_receiver.recv().await {
                            info!("MESSAGE: {}", message);
                        }
                    }
                });
            }
        }
        
        info!("Client created: {:?}", &client);
        let _manager = Arc::clone(&DefaultClientManager);
        let mut mtx = _manager.connections.lock().await;
        mtx.insert(device.device_id.clone(), client);
        drop(mtx);
    }

    Err(Box::new(io::Error::new(ErrorKind::BrokenPipe, format!("Cannot open new Tcp Client for {}", server_id))))
}