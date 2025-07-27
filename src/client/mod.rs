use crate::broadcast::DiscoveredDevice;
use crate::consts::{of_type, CommonThreadError, CA_CERT_FILE_NAME, DEFAULT_SIGNING_SERVER_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::node::load::load_node_cert_der;
use crate::keychain::node::{generate_node_csr, save_node_signed_cert};
use crate::keychain::{load_cert_der, load_private_key_der};
use crate::server::model::ConnectionState::Unknown;
use crate::server::model::{ConnectionState, ServerResponse, ServerTcpPeer, SigningServerRequest, TcpServer};
use crate::utils::{get_server_cert_storage, load_cas, save_server_cert};
use lazy_static::lazy_static;
use log::{error, info};
use rustls::client::WebPkiServerVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::format;
use std::fs::File;
use std::hash::Hash;
use std::io;
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, TlsStream};

lazy_static! {
    pub static ref DefaultClientManager: Arc<ClientManager> = {
        let (sender, receiver) = mpsc::channel::<ClientActivity>(500);
        Arc::new( ClientManager {
            connections:Arc::new(Mutex::new(HashMap::new())),
            bounded_channel: (sender, Mutex::new(receiver)) 
        })
    };

    pub static ref SigningRequests: Arc<Mutex<HashMap<String, bool>>> = Arc::new(Mutex::new(HashMap::new()));
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
    pub fn new(server_id: String) -> Result<TcpClient, CommonThreadError> {
        Ok(TcpClient {
            server_id: server_id.clone(),
            configuration: Arc::new(Self::create_client_config(server_id.clone())?),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    fn create_client_config(server_id: String) -> Result<ClientConfig, CommonThreadError> {
        let pk = load_private_key_der()?;
        let cert = load_cert_der()?;

        let ca_verification = {
            let mut root_store = RootCertStore::empty();
            match load_node_cert_der(&server_id) {
                Ok(crt) => {
                    root_store.add(crt).expect(&format!("Cannot load specified CRT for {}", server_id));
                }
                Err(_) => {
                    return Err(of_type("Error loading server CRT to RootStore", ErrorKind::Other))
                }
            };

            root_store
        };

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
pub async fn run(_manager: Arc<ClientManager>) -> Result<(), CommonThreadError> {
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
                let empty = {
                    let mtx = Arc::clone(&DefaultClientManager);
                    !mtx.connections.lock().await.contains_key(&device_id)
                };

                if empty {
                    let device_manager = Arc::clone(&DefaultDeviceManager);
                    if let Some(device) = device_manager.known_devices.read().await.get(&device_id) {
                        request_ca(&device).await.expect(&format!("Cannot fetch requested CA from: {}", &device_id));
                        //request server sign on client's csr
                        match request_signed_cert(device).await {
                            Ok(_) => {
                                open_connection(device_id.clone()).await
                                    .expect(&format!("Cannot open connection for: {}", device_id));
                            }
                            Err(e) => {
                                error!("Cannot open connection to {} due to crt request error: {}", device_id, e)
                            }
                        }
                    }
                }
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


async fn open_connection(server_id: String) -> Result<(), CommonThreadError> {
    info!("Opening connection to: {}", &server_id);
    let device_manager = Arc::clone(&DefaultDeviceManager);
    if let Some(device) = device_manager.known_devices.read().await.get(&server_id) {
        let stream = TcpStream::connect(&device.connect_addr).await?;

        let client = TcpClient::new(device.device_id.clone())?;
        let connector = TlsConnector::from(client.configuration.clone());

        if let Ok(e) = connector.connect(ServerName::IpAddress(
            rustls_pki_types::IpAddr::V4(rustls_pki_types::Ipv4Addr::try_from(device.connect_addr.ip().to_string().as_str())?)), stream).await {
            info!("TLS connection to: {} is established.", server_id);
            
            let (client_sender, mut client_receiver) = mpsc::channel(200);
            let mut mtx = client.connection.lock().await;

            let new_peer = ClientTcpPeer {
                connection: Arc::new(Mutex::new(e)),
                connection_status: Unknown,
                sender: client_sender,
            };

            let connection_listener = Arc::clone(&new_peer.connection);
            tokio::spawn(async move {
                let mut buffer = vec![0; 4096];

                loop {
                    let mut locked_connection = connection_listener.lock().await;

                    let bytes_read = match locked_connection.read(&mut buffer).await {
                        Ok(0) => {
                            println!("Connection closed");
                            break;
                        }
                        Ok(n) => n,
                        Err(e) => {
                            eprintln!("Tls read error: {}", e);
                            break;
                        }
                    };

                    let received_data = String::from_utf8_lossy(&buffer[..bytes_read]);
                    println!("Получено {} байт: {}", bytes_read, received_data);
                }
            });

            mtx.replace(new_peer);
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
            
            info!("Client created: {:?}", &client);
            let _manager = Arc::clone(&DefaultClientManager);
            let mut mtx = _manager.connections.lock().await;
            mtx.insert(device.device_id.clone(), client);
            drop(mtx);
            
        }
    }

    Err(Box::new(io::Error::new(ErrorKind::BrokenPipe, format!("Cannot open new Tcp Client for {}", server_id))))
}

pub async fn request_ca(_device: &DiscoveredDevice) -> Result<Option<ServerResponse>, CommonThreadError> {
    let response = call_signing_server(SigningServerRequest::FetchCrt, _device).await?;

    if let Some(ServerResponse::Certificate { cert }) = response {
        if let Err(e) = save_server_cert(_device.device_id.clone(), cert) {
            error!("Error while saving server CRT: {}", e);
            return Err(e);
        }
    } else {
        return Err(of_type("Certificate fetch has failed!", ErrorKind::Other));
    }

    Ok(None)
}

pub async fn request_signed_cert(_device: &DiscoveredDevice) -> Result<(), CommonThreadError> {
    let (csr_pem, node_keypair) = generate_node_csr(_device.device_id.clone())?;

    if let Some(response) = call_signing_server(SigningServerRequest::SignCsr {
        csr: csr_pem
    }, _device).await.expect("Cannot execute call to signing server") {
        if let ServerResponse::SignedCertificate { device_id, cert_pem } = response {
            info!("Got CRT: {}", &cert_pem);
            save_node_signed_cert(device_id, cert_pem.as_str(), node_keypair)?;
            return Ok(());
        } else {
            return Err(of_type(&format!("Cannot perform signing request from {}", _device.device_id), ErrorKind::Other));
        }
    }
    Err(of_type("Cannot fetch server CRT", ErrorKind::BrokenPipe))
}

pub async fn call_signing_server(req: SigningServerRequest, _device: &DiscoveredDevice) -> Result<Option<ServerResponse>, CommonThreadError> {
    let mut stream = TcpStream::connect(SocketAddr::new(
        IpAddr::try_from(Ipv4Addr::from_str(&_device.connect_addr.ip().to_string())?)?, DEFAULT_SIGNING_SERVER_PORT)).await?;

    stream.write_all(serde_json::to_vec(&req)?.as_slice()).await?;

    let mut buffer = Vec::new();
    let bytes_read_total = stream.read_to_end(&mut buffer).await?;

    if bytes_read_total == 0 {
        return Ok(None);
    }
    match serde_json::from_slice(&buffer[..bytes_read_total]) {
        Ok(resp) => Ok(Some(resp)),
        Err(e) => {
            Err(format!("Failed to deserialize server response. Raw data: '{}', Error: {}",
                        String::from_utf8_lossy(&buffer), e).into())
        }
    }
}