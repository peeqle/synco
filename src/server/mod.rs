use crate::NetError;
use crate::broadcast::DiscoveredDevice;
use crate::connection::generate_challenge;
use crate::consts::{CA_CERT_FILE_NAME, DEFAULT_SERVER_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::{
    DEVICE_SIGNING_KEY, generate_server_ca_keys, load_cert_der, load_private_key_der,
};
use crate::machine_utils::get_local_ip;
use crate::server::ConnectionRequestQuery::ChallengeRequest;
use crate::utils::{get_server_cert_storage, load_cas, validate_server_cert_present};
use ed25519_dalek::Signer;
use lazy_static::lazy_static;
use log::info;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{ServerConfig, ServerConnection, crypto};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, mpsc};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

mod tls_utils;

lazy_static! {
    pub static ref DefaultServer: Arc<TcpServer> = {
        let channel = mpsc::channel::<ConnectionRequestQuery>(500);
        let tcp_server = TcpServer::new(channel).expect("Cannot create new TcpServer instance");
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
    connected_devices: Arc<Mutex<HashMap<String, String>>>,
    pub(crate) bounded_channel: (
        Sender<ConnectionRequestQuery>,
        Receiver<ConnectionRequestQuery>,
    ),
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

impl TcpServer {
    fn new(
        server_channel: (
            Sender<ConnectionRequestQuery>,
            Receiver<ConnectionRequestQuery>,
        ),
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

    pub async fn start(&self) -> Result<(), NetError> {
        let listener =
            TcpListener::bind(format!("{}:{}", &self.local_ip, DEFAULT_SERVER_PORT)).await?;

        let some = Arc::new(self.bounded_channel.0.clone());
        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let acceptor = self.current_acceptor.clone();

            socket.readable().await?;
            let sender_clone = Arc::clone(&some);
            let connected_devices_clone_arc = Arc::clone(&self.connected_devices);
            let discovered_devices = Arc::clone(&DefaultDeviceManager);

            let peer_arc = Arc::new(peer_addr);

            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(mut tls_stream) => {
                        let (reader, mut writer) = tls_stream.get_mut();

                        let cn_lock = connected_devices_clone_arc.lock().await;
                        let connecting_device_option: Option<DiscoveredDevice> = {
                            let discovered_devices_guard =
                                discovered_devices.known_devices.read().expect(
                                    "Cannot find suitable known devices holder in devices manager",
                                );

                            discovered_devices_guard
                                .iter()
                                .filter(|(id, device)| device.connect_addr.ip().eq(&peer_arc.ip()))
                                .map(|(id, device)| device.clone())
                                .last()
                        };

                        handle_client_actions(connecting_device_option, peer_arc, reader, writer, &cn_lock).await;
                    }
                    Err(e) => {
                        eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                    }
                }
            });
        }

        async fn handle_client_actions(
            connecting_device_option: Option<DiscoveredDevice>,
            peer_arc: Arc<SocketAddr>,
            reader: &mut TcpStream,
            writer: &mut ServerConnection,
            cn_lock: &HashMap<String, String>,
        ) {
            if !connecting_device_option.is_some() {
                info!("Cannot identify device of IP {}", peer_arc.ip().to_string());
                return;
            } else if !cn_lock.contains_key(&peer_arc.ip().to_string()) {
                let device = connecting_device_option.unwrap();
                if let Ok(ser) = get_serialized_challenge(device.clone()).await {
                    if let Err(e) = writer.writer().write_all(&ser) {
                        eprintln!("Failed to write challenge: {}", e);
                    }
                } else {
                    eprintln!("Failed to serialize challenge.");
                }
            } else {
                let mut buffer = vec![0; 4096];
                let mut result = vec![];

                loop {
                    let bytes_read = reader.try_read(&mut buffer).unwrap();
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
                            ConnectionRequestQuery::ChallengeResponse { .. } => {}
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
        }

        async fn get_serialized_challenge(
            device: DiscoveredDevice,
        ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
            let challenge_query = generate_challenge(&device).await?;
            let serialized = serde_json::to_vec(&challenge_query)?;
            Ok(serialized)
        }
    }

    pub async fn generate_device_handshake_challenge(&self, device_id: String) {
        let nonce = Uuid::new_v4();
        let device_pk = DEVICE_SIGNING_KEY.clone();

        let encoded_nonce = device_pk.sign(nonce.as_bytes().as_slice());
        &self
            .get_channel_sender()
            .send(ChallengeRequest {
                device_id,
                nonce: encoded_nonce.to_vec(),
            })
            .await;
    }

    pub fn get_channel_sender(&self) -> Sender<ConnectionRequestQuery> {
        self.bounded_channel.0.clone()
    }
}
