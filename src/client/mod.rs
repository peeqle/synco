use crate::consts::CA_CERT_FILE_NAME;
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::{load_cert_der, load_private_key_der};
use crate::server::model::ConnectionState::Unknown;
use crate::server::model::{ConnectionState, ServerTcpPeer, TcpServer};
use crate::utils::{get_server_cert_storage, load_cas};
use lazy_static::lazy_static;
use log::info;
use rustls::client::WebPkiServerVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{IpAddr, Ipv4Addr, ServerName};
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
    pub fn new(server_id: String) -> Result<TcpClient, Box<dyn Error>> {
        Ok(TcpClient {
            server_id,
            configuration: Arc::new(Self::create_client_config()?),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    fn create_client_config() -> Result<ClientConfig, Box<dyn Error>> {
        let pk = load_private_key_der()?;
        let cert = load_cert_der()?;

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
            .with_client_auth_cert(vec![cert], pk)?;
        Ok(config)
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


async fn open_connection(server_id: String) -> Result<(), Box<dyn Error>> {
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