use crate::consts::CA_CERT_FILE_NAME;
use crate::keychain::{generate_server_ca_keys, load_cert_der, load_private_key_der};
use crate::machine_utils::get_local_ip;
use crate::utils::{get_server_cert_storage, load_cas, validate_server_cert_present};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{crypto, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::io;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

impl TcpServer {
    pub fn new(
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

    pub fn create_server_config() -> io::Result<ServerConfig> {
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

pub struct StaticCertResolver {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
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
            key: crypto::aws_lc_rs::sign::any_supported_type(&self.key).expect("Cannot extract key"),
            ocsp: None,
        };
        Some(Arc::new(certified_key))
    }
}

pub struct TcpServer {
    pub local_ip: IpAddr,
    pub loaded_configuration: ServerConfig,
    pub current_acceptor: Arc<TlsAcceptor>,
    //socket_addr to device_id
    pub connected_devices: Arc<Mutex<HashMap<String, ServerTcpPeer>>>,
    pub bounded_channel: (Sender<ServerActivity>, Mutex<Receiver<ServerActivity>>),
}

pub struct ServerTcpPeer {
    pub device_id: String,
    pub connection: Arc<Mutex<TlsStream<TcpStream>>>,
    pub connection_status: ConnectionState,
    pub sender: Sender<String>,
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
    VerifiedChallenge { device_id: String },
}

#[derive(Clone, PartialEq, Default,Debug)]
pub enum ConnectionState {
    #[default]
    Unknown,
    Denied,
    Access,
    Pending,
}