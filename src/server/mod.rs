use crate::broadcast::DiscoveredDevice;
use crate::challenge::generate_challenge;
use crate::consts::{CA_CERT_FILE_NAME, DEFAULT_SERVER_PORT};
use crate::device_manager::{get_device, DefaultDeviceManager};
use crate::keychain::{
    generate_server_ca_keys, load_cert_der, load_private_key_der,
};
use crate::machine_utils::get_local_ip;
use crate::server::ConnectionRequestQuery::RejectConnection;
use crate::server::ConnectionState::{Access, Denied, Pending, Unknown};
use crate::utils::{get_server_cert_storage, load_cas, validate_server_cert_present};
use crate::NetError;
use ed25519_dalek::Signer;
use lazy_static::lazy_static;
use log::{error, info};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{crypto, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio_rustls::TlsAcceptor;

mod tls_utils;

lazy_static! {
    pub static ref DefaultServer: Arc<TcpServer> = {
        let channel = mpsc::channel::<ServerActivity>(500);
        let tcp_server = TcpServer::new((channel.0, Mutex::new(channel.1)))
            .expect("Cannot create new TcpServer instance");
        Arc::new(tcp_server)
    };
}

struct StaticCertResolver {
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}
impl Debug for StaticCertResolver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl ResolvesServerCert for StaticCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let certified_key = rustls::sign::CertifiedKey {
            cert: self.certs.clone(),
            key: crypto::aws_lc_rs::sign::any_ecdsa_type(&self.key).expect("Cannot extract key"),
            ocsp: None,
        };
        Some(Arc::new(certified_key))
    }
}

pub struct TcpServer {
    local_ip: IpAddr,
    loaded_configuration: ServerConfig,
    current_acceptor: Arc<TlsAcceptor>,
    //socket_addr to device_id
    connected_devices: Arc<Mutex<HashMap<String, TcpPeer>>>,
    pub(crate) bounded_channel: (Sender<ServerActivity>, Mutex<Receiver<ServerActivity>>),
}

pub struct TcpPeer {
    device_id: String,
    connection: Mutex<ServerConnection>,
    connection_status: ConnectionState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionRequestQuery {
    InitialRequest {
        device_id: String,
    },
    ChallengeRequest {
        device_id: String,
        nonce: Vec<u8>,
    },
    ChallengeResponse {
        device_id: String,
        //encoded BLAKE3 x ed25519 string
        response: Vec<u8>,
    },
    AcceptConnection(String),
    RejectConnection(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerActivity {
    SendChallenge { device_id: String },
}

#[derive(Clone, PartialEq, Default)]
pub enum ConnectionState {
    #[default]
    Unknown,
    Denied,
    Access,
    Pending,
}

impl TcpServer {
    fn new(
        server_channel: (Sender<ServerActivity>, Mutex<Receiver<ServerActivity>>),
    ) -> Result<TcpServer, Box<dyn Error + Send + Sync>> {
        let validation = validate_server_cert_present();
        if !validation {
            let res = generate_server_ca_keys();
            if res.is_err() {
                return Err(Box::new(io::Error::new(
                    ErrorKind::InvalidData,
                    "Server certificates are invalid, try to run [regenerate]",
                )));
            }
        }
        let configuration = Self::create_server_config()?;
        Ok(TcpServer {
            local_ip: get_local_ip().unwrap(),
            loaded_configuration: configuration.clone(),
            current_acceptor: Arc::new(TlsAcceptor::from(Arc::new(configuration))),
            connected_devices: Arc::new(Mutex::new(HashMap::new())),
            bounded_channel: server_channel,
        })
    }

    fn create_server_config() -> io::Result<ServerConfig> {
        let server_certs = load_cert_der()?;
        let server_key = load_private_key_der()?;

        let server_ca_verification = load_cas(&get_server_cert_storage().join(CA_CERT_FILE_NAME))?;

        let client_cert_verifier: Arc<dyn ClientCertVerifier> = {
            WebPkiClientVerifier::builder(Arc::new(server_ca_verification))
                .build()
                .map_err(|e| {
                    io::Error::new(
                        ErrorKind::InvalidInput,
                        format!("Failed to build client verifier: {:?}", e),
                    )
                })?
        };

        let server_cert_resolver = Arc::new(StaticCertResolver {
            certs: vec![server_certs],
            key: server_key,
        });

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_cert_verifier)
            .with_cert_resolver(server_cert_resolver);

        Ok(config)
    }
}

pub async fn start_server(server: Arc<TcpServer>) -> Result<(), NetError> {
    let listener =
        TcpListener::bind(format!("{}:{}", server.local_ip, DEFAULT_SERVER_PORT)).await?;

    let acceptor = server.current_acceptor.clone();
    let default_device_manager = DefaultDeviceManager.clone();

    loop {
        let (socket, peer_addr) = listener.accept().await?;

        let server_arc = server.clone();
        let acceptor_clone = acceptor.clone();
        let default_device_manager_clone = default_device_manager.clone();

        task::spawn(async move {
            match acceptor_clone.accept(socket).await {
                Ok(mut tls_stream) => {
                    let (tcp_stream, mut connection) = tls_stream.get_mut();

                    let connecting_device_option: Option<DiscoveredDevice> = {
                        let discovered_devices_guard =
                            default_device_manager_clone.known_devices.read().await;

                        discovered_devices_guard
                            .iter()
                            .filter(|(_id, device)| device.connect_addr.ip() == peer_addr.ip())
                            .map(|(_id, device)| device.clone())
                            .last()
                    };

                    if connecting_device_option.is_some() {
                        let connecting_device = connecting_device_option.unwrap();

                        let can_connect = {
                            let mtx = server_arc.connected_devices.lock().await;
                            let server_known_device = mtx.get(&connecting_device.device_id);

                            server_known_device.is_some() && server_known_device.unwrap().connection_status != Denied
                        };

                        if !can_connect {
                            match serde_json::to_vec(&RejectConnection("You cannot connect to that machine".to_string())) {
                                Ok(res) => {
                                    connection.writer().write(&res).expect("Cannot send");
                                }
                                Err(_) => {
                                    error!("Cannot serialize Rejection response");
                                }
                            }
                        } else {
                            handle_client_actions(
                                server_arc.clone(),
                                connecting_device.clone(),
                                peer_addr,
                                connection,
                            ).await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}

async fn listen_actions(server: Arc<TcpServer>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_cp = Arc::clone(&server);
    loop {
        let mut receiver = server_cp.bounded_channel.1.lock().await;
        if let Some(message) = receiver.recv().await {
            handle_receiver_message(server_cp.clone(), message).await?;
        }
    }
}

async fn handle_receiver_message(server: Arc<TcpServer>, message: ServerActivity) -> Result<(), Box<dyn Error + Send + Sync>> {
    match message {
        ServerActivity::SendChallenge { device_id } => {
            let mut cp = server.connected_devices.lock().await;
            let mut _device = cp.get_mut(&device_id);

            if _device.is_some() {
                let device_connection = _device.unwrap();
                if device_connection.connection_status == Unknown {
                    if let Some(d_device) = get_device(device_id.clone()).await {
                        let mut mutex = device_connection.connection.lock().await;
                        match send_challenge(d_device, &mut mutex).await {
                            Ok(_) => {
                                device_connection.connection_status = Pending;
                            }
                            Err(_) => {}
                        }
                    }
                }

                if device_connection.connection_status == Denied {
                    return Err(Box::new(io::Error::new(ErrorKind::AlreadyExists, "Connection is denied")));
                }
                if device_connection.connection_status == Access {
                    return Err(Box::new(io::Error::new(ErrorKind::AlreadyExists, "Connection is already opened")));
                }
            }
        }
    }
    Ok(())
}

async fn handle_client_actions(
    server: Arc<TcpServer>,
    connecting_device: DiscoveredDevice,
    peer_arc: SocketAddr,
    connection: &mut ServerConnection,
) {
    let arc = server.connected_devices.clone();
    let guard = arc.lock().await;

    let mut buffer = vec![0; 4096];
    let mut result = vec![];

    loop {
        let bytes_read = connection.reader().read(&mut buffer).unwrap();
        if bytes_read == 0 {
            break;
        }
        result.extend_from_slice(&buffer[..bytes_read]);
    }

    if !result.is_empty() {
        match serde_json::from_slice::<ConnectionRequestQuery>(result.as_slice()) {
            Ok(query) => match query {
                ConnectionRequestQuery::InitialRequest { .. } => {}
                ConnectionRequestQuery::ChallengeRequest { .. } => {}
                ConnectionRequestQuery::ChallengeResponse { device_id, response } => {
                    verify_challenge
                }
                ConnectionRequestQuery::AcceptConnection(_) => {}
                ConnectionRequestQuery::RejectConnection(_) => {}
            },
            Err(err) => {
                println!(
                    "[SERVER] Error occurred while processing client's message: {}",
                    err
                )
            }
        };
    }
}

async fn send_challenge(device: DiscoveredDevice, connection: &mut ServerConnection) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Ok(ser) = get_serialized_challenge(device.clone()).await {
        if let Err(e) = connection.writer().write_all(&ser) {
            eprintln!("Failed to write challenge: {}", e);
            Err(Box::new(io::Error::new(
                ErrorKind::Interrupted,
                format!(
                    "Failed to write challenge: {}", e
                ),
            )))
        } else {
            println!("Sent challenge to: {}", device.device_id.to_string());
            Ok(())
        }
    } else {
        eprintln!("Failed to serialize challenge.");
        Err(Box::new(io::Error::new(
            ErrorKind::Interrupted,
            "Failed to serialize challenge.",
        )))
    }
}

async fn get_serialized_challenge(
    device: DiscoveredDevice,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let challenge_query = generate_challenge(device.device_id.clone()).await?;
    let serialized = serde_json::to_vec(&challenge_query)?;
    Ok(serialized)
}
