mod cert;

use crate::broadcast::DiscoveredDevice;
use crate::challenge::ChallengeEvent::NewChallengeRequest;
use crate::challenge::{ChallengeEvent, DefaultChallengeManager};
use crate::client::cert::{request_ca, request_signed_cert};
use crate::consts::{
    of_type, CommonThreadError, CA_CERT_FILE_NAME, CERT_FILE_NAME, DEFAULT_SIGNING_SERVER_PORT,
};
use crate::device_manager::DefaultDeviceManager;
use crate::diff::files::{append, get_file, get_file_writer};
use crate::diff::{files::get_seeding_files, Files};
use crate::keychain::node::load::{
    load_node_cert_der, load_node_cert_pem, load_node_key_der, load_server_signed_cert_der,
    node_cert_exists,
};
use crate::keychain::node::{generate_node_csr, save_node_signed_cert};
use crate::keychain::server::load::load_server_signed_ca;
use crate::keychain::server::save_server_cert;
use crate::server::model::ConnectionState::Unknown;
use crate::server::model::{ConnectionState, ServerRequest, ServerResponse};
use crate::tcp_utils::{receive_file_chunked, send_framed};
use crate::utils::DirType::Action;
use crate::utils::{get_default_application_dir, get_server_cert_storage};
use lazy_static::lazy_static;
use log::{error, info};
use rustls::client::WebPkiServerVerifier;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::format;
use std::fs::File;
use std::hash::Hash;
use std::io::{BufRead, BufReader, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::DerefMut;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{io, mem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task::spawn_blocking;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, TlsStream};

lazy_static! {
    pub static ref DefaultClientManager: Arc<ClientManager> = {
        let (sender, receiver) = mpsc::channel::<ClientActivity>(500);
        Arc::new(ClientManager {
            connections: Arc::new(Mutex::new(HashMap::new())),
            bounded_channel: (sender, Mutex::new(receiver)),
        })
    };
    pub static ref SigningRequests: Arc<Mutex<HashMap<String, bool>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientActivity {
    OpenConnection {
        device_id: String,
    },
    ChangeStatus {
        device_id: String,
        status: ConnectionState,
    },
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
    pub sender: Sender<ServerRequest>,
}

impl TcpClient {
    pub fn new(server_id: String) -> Result<TcpClient, CommonThreadError> {
        Ok(TcpClient {
            server_id: server_id.clone(),
            configuration: Arc::new(Self::create_client_config(server_id.clone())?),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    pub fn update_client_status(&self, status: ConnectionState) {
        let tcp_peer = self.connection.clone();
        tokio::spawn(async move {
            let mut mtx = tcp_peer.lock().await;

            if let Some(conn) = mtx.deref_mut() {
                conn.connection_status = status;
            }
        });
    }

    pub fn new_with_verified_certs(server_id: String) -> Result<TcpClient, CommonThreadError> {
        if !node_cert_exists(&server_id) {
            return Err(format!("Client certificate not found for device: {}", server_id).into());
        }

        let ca_cert_path = get_server_cert_storage()
            .join(&server_id)
            .join(CERT_FILE_NAME);
        if !ca_cert_path.exists() {
            return Err(format!("CA certificate not found for server: {}", server_id).into());
        }

        Ok(TcpClient {
            server_id: server_id.clone(),
            configuration: Arc::new(Self::create_client_config(server_id.clone())?),
            connection: Arc::new(Mutex::new(None)),
        })
    }

    fn create_client_config(server_id: String) -> Result<ClientConfig, CommonThreadError> {
        info!("Creating client TLS config for server: {}", server_id);

        let pk = load_node_key_der(&server_id)?;
        let cert = load_node_cert_der(&server_id)?;
        info!("Loaded client private key and certificate");

        let ca_verification = {
            let mut root_store = RootCertStore::empty();

            info!("Loading server CA certificate for: {}", server_id);
            let ca_cert_der = load_server_signed_ca(&server_id).map_err(|e| {
                error!(
                    "Failed to load server CA certificate for {}: {}",
                    server_id, e
                );
                format!("Cannot load server CA certificate for {}: {}", server_id, e)
            })?;

            root_store.add(ca_cert_der).map_err(|e| {
                error!(
                    "Cannot add server CA certificate to RootStore for {}: {:?}",
                    server_id, e
                );
                format!("Cannot add server CA certificate to RootStore: {:?}", e)
            })?;

            info!(
                "Successfully loaded server CA certificate for: {}",
                server_id
            );
            root_store
        };

        let client_cert_verifier: Arc<WebPkiServerVerifier> = {
            WebPkiServerVerifier::builder(Arc::new(ca_verification))
                .build()
                .map_err(|e| {
                    error!("Failed to build client verifier for {}: {:?}", server_id, e);
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Failed to build client verifier: {:?}", e),
                    )
                })?
        };

        let config = ClientConfig::builder()
            .with_webpki_verifier(client_cert_verifier)
            .with_client_auth_cert(vec![cert], pk)
            .map_err(|e| {
                error!(
                    "Failed to create client config with client auth for {}: {:?}",
                    server_id, e
                );
                format!("Failed to create client config: {:?}", e)
            })?;

        info!(
            "Successfully created TLS client configuration for: {}",
            server_id
        );
        Ok(config)
    }
}

pub async fn run(_manager: Arc<ClientManager>) {
    let handle_fn = async |x: ClientActivity| match x {
        ClientActivity::OpenConnection { device_id } => {
            let empty = {
                let cp = Arc::clone(&DefaultClientManager);
                !cp.connections.lock().await.contains_key(&device_id)
            };

            if empty {
                let device_manager = Arc::clone(&DefaultDeviceManager);
                if let Some(device) = device_manager.known_devices.read().await.get(&device_id) {
                    info!("Starting certificate setup for device: {}", device_id);

                    let ca_cert_path = get_server_cert_storage()
                        .join(&device_id)
                        .join(CERT_FILE_NAME);
                    let need_ca = !ca_cert_path.exists();
                    let need_client_cert = !node_cert_exists(&device_id);

                    if need_ca {
                        info!("CA certificate missing for {}, fetching...", device_id);
                        match request_ca(&device).await {
                            Ok(_) => {
                                info!(
                                    "CA certificate fetched successfully for device: {}",
                                    device_id
                                );
                            }
                            Err(e) => {
                                error!(
                                    "Failed to fetch CA certificate for device {}: {}",
                                    device_id, e
                                );
                                return;
                            }
                        }
                    } else {
                        info!("CA certificate already exists for device: {}", device_id);
                    }

                    if need_client_cert {
                        info!(
                            "Client certificate missing for {}, requesting signature...",
                            device_id
                        );
                        match request_signed_cert(device).await {
                            Ok(_) => {
                                info!(
                                    "Client certificate signed successfully for device: {}",
                                    device_id
                                );
                            }
                            Err(e) => {
                                error!(
                                    "Failed to get signed certificate for device {}: {}",
                                    device_id, e
                                );
                                return;
                            }
                        }
                    } else {
                        info!(
                            "Client certificate already exists for device: {}",
                            device_id
                        );
                    }

                    match open_connection(device_id.clone()).await {
                        Ok(_) => {
                            info!("Connection opened successfully for device: {}", device_id);
                        }
                        Err(e) => {
                            error!("Failed to open connection for device {}: {}", device_id, e);

                            if e.to_string().contains("UnknownIssuer")
                                || e.to_string().contains("invalid peer certificate")
                            {
                                error!(
                                    "Certificate validation failed, cleaning up certificates for {}",
                                    device_id
                                );

                                let _ = std::fs::remove_dir_all(
                                    get_server_cert_storage().join(&device_id),
                                );
                                let _ = std::fs::remove_dir_all(
                                    get_default_application_dir(Action)
                                        .join("client")
                                        .join(&device_id),
                                );

                                info!("Retrying certificate setup for device: {}", device_id);

                                if let Err(retry_error) = async {
                                    request_ca(&device).await?;
                                    request_signed_cert(&device).await?;
                                    open_connection(device_id.clone()).await
                                }
                                .await
                                {
                                    error!(
                                        "Retry failed for device {}: {}",
                                        device_id, retry_error
                                    );
                                } else {
                                    info!("Retry successful for device: {}", device_id);
                                }
                            }
                        }
                    }
                } else {
                    error!("Device {} not found in known devices registry", device_id);
                }
            } else {
                info!("Connection already exists for device: {}", device_id);
            }
        }
        ClientActivity::ChangeStatus { device_id, status } => {
            let cp = Arc::clone(&DefaultClientManager);
            let mut mtx = cp.connections.lock().await;

            if let Some(_device) = mtx.get_mut(&device_id) {
                _device.update_client_status(status);
                info!("Opened connection for: {}", device_id);
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
    info!("Looking up device {} in known devices", server_id);

    let device = device_manager
        .known_devices
        .read()
        .await
        .get(&server_id)
        .cloned()
        .ok_or_else(|| {
            error!("Device not found in known devices: {}", server_id);
            format!("Device not found: {}", server_id)
        })?;

    info!(
        "Device found: {} at {}",
        device.device_id, device.connect_addr
    );

    info!("Connecting to: {}", device.connect_addr);
    let stream = TcpStream::connect(&device.connect_addr)
        .await
        .map_err(|e| {
            error!("Failed to connect to {}: {}", device.connect_addr, e);
            format!("Failed to connect to {}: {}", device.connect_addr, e)
        })?;

    info!(
        "TCP connection established, creating TLS client configuration for: {}",
        server_id
    );
    let client = TcpClient::new_with_verified_certs(device.device_id.clone()).map_err(|e| {
        error!(
            "Failed to create TLS client config for {}: {}",
            server_id, e
        );
        format!("TLS client configuration failed: {}", e)
    })?;

    let connector = TlsConnector::from(client.configuration.clone());

    info!("Establishing TLS connection to: {}", server_id);
    let tls_stream = connector
        .connect(
            ServerName::IpAddress(rustls_pki_types::IpAddr::V4(
                rustls_pki_types::Ipv4Addr::try_from(
                    device.connect_addr.ip().to_string().as_str(),
                )?,
            )),
            stream,
        )
        .await
        .map_err(|e| {
            error!("TLS handshake failed with {}: {}", server_id, e);
            format!("TLS connection failed: {}", e)
        })?;

    info!(
        "TLS connection established successfully with: {}",
        server_id
    );

    let (client_sender, client_receiver) = mpsc::channel(200);

    let new_peer = ClientTcpPeer {
        connection: Arc::new(Mutex::new(tls_stream)),
        connection_status: Unknown,
        sender: client_sender,
    };

    server_response_listener(&new_peer);

    //Tcp client connection set up
    {
        let mut mtx = client.connection.lock().await;
        mtx.replace(new_peer);
    }

    //new client append
    {
        let manager = Arc::clone(&DefaultClientManager);
        let mut connections = manager.connections.lock().await;
        connections.insert(device.device_id.clone(), client);
    }

    //request receiver initialization
    client_request_listener(&device.device_id, client_receiver).await;

    info!("Connection setup completed for: {}", server_id);
    Ok(())
}

fn server_response_listener(peer: &ClientTcpPeer) {
    let challenge_manager = DefaultChallengeManager.clone();
    let connection_reader = Arc::clone(&peer.connection);
    tokio::spawn(async move {
        let mut buffer = Vec::new();
        loop {
            let mut locked_connection = connection_reader.lock().await;
            if let Ok(_) = locked_connection.read(&mut buffer).await {
                if let Ok(req) = serde_json::from_slice::<ServerResponse>(&buffer) {
                    match req {
                        ServerResponse::ChallengeRequest { device_id, nonce } => {
                            challenge_manager
                                .get_sender()
                                .send(NewChallengeRequest { device_id, nonce })
                                .await
                                .expect("Cannot send");
                        }
                        ServerResponse::SeedingFiles { shared_files } => {
                            for file_data in shared_files {
                                append(file_data).await;
                            }
                        }
                        ServerResponse::FileMetadata { file_id, size } => {
                            if let Some(existing_file) = get_file(&file_id).await {
                                if let Ok(file_writer) = get_file_writer(&existing_file).await {
                                    receive_file_chunked(
                                        Arc::clone(&connection_reader),
                                        size,
                                        file_writer,
                                    )
                                    .await
                                    .expect(&format!("Cannot receive file {}", file_id));
                                }
                            }
                        }
                        ServerResponse::Error { .. } => {}
                        _ => {}
                    }
                }

                AsyncWriteExt::flush(&mut buffer)
                    .await
                    .expect("Cannot flush");
            }
        }
    });
}

async fn client_request_listener(server_id: &String, mut client_receiver: Receiver<ServerRequest>) {
    let manager = Arc::clone(&DefaultClientManager);
    let mut connections = manager.connections.lock().await;

    if let Some(device) = connections.get_mut(server_id).cloned() {
        let peer_mtx = device.connection.lock().await;
        if peer_mtx.as_ref().is_none() {
            error!("Cannot find opened connection for device: {}", server_id);
        } else if let Some(connector) = peer_mtx.as_ref() {
            let connection_arc = connector.connection.clone();
            tokio::spawn(async move {
                while let Some(message) = client_receiver.recv().await {
                    let serialized = serde_json::to_vec(&message).expect("Cannot serialize");
                    send_framed(connection_arc.clone(), serialized)
                        .await
                        .expect(&format!("Cannot send request to the server: {:?}", message));
                }
            });
        }
    }
}
