use crate::consts::CommonThreadError;
use crate::diff::model::FileEntityDto;
use crate::keychain::server::generate_root_ca;
use crate::keychain::{generate_cert_keys, load_leaf_cert_der, load_leaf_private_key_der};
use crate::machine_utils::get_local_ip;
use crate::utils::{load_cas, validate_server_cert_present};
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WantsServerCert, WebPkiClientVerifier};
use rustls::{crypto, ConfigBuilder, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::{default, io};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use vis::vis;

impl TcpServer {
    pub fn new(
        server_channel: (Sender<ServerActivity>, Mutex<Receiver<ServerActivity>>),
    ) -> Result<TcpServer, Box<dyn Error + Send + Sync>> {
        let validation = validate_server_cert_present();
        if !validation {
            let res = generate_cert_keys();
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
            current_acceptor: Arc::new(TlsAcceptor::from(Arc::new(configuration))),
            connected_devices: Arc::new(Mutex::new(HashMap::new())),
            bounded_channel: server_channel,
        })
    }

    pub fn create_server_config() -> Result<ServerConfig, CommonThreadError> {
        let server_certs = load_leaf_cert_der()?;
        let server_key = load_leaf_private_key_der()?;

        // FIX: Use root CA instead of leaf certificate for client verification
        let (ca_cert_path, _) = generate_root_ca()?;
        let server_ca_verification = load_cas(&ca_cert_path)?;

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

    pub fn create_signing_server_config() -> ConfigBuilder<ServerConfig, WantsServerCert> {
        ServerConfig::builder()
            .with_no_client_auth()
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
    pub current_acceptor: Arc<TlsAcceptor>,
    //socket_addr to device_id
    pub connected_devices: Arc<Mutex<HashMap<String, ServerTcpPeer>>>,
    pub bounded_channel: (Sender<ServerActivity>, Mutex<Receiver<ServerActivity>>),
}

#[derive(Clone)]
#[vis(pub)]
pub struct ServerTcpPeer {
    device_id: String,
    connection: Arc<Mutex<TlsStream<TcpStream>>>,
    connection_status: Arc<RwLock<ConnectionState>>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Crud {
    Create,
    Read,
    Update,
    Delete
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerRequest {
    InitialRequest {
        device_id: String,
    },
    ChallengeResponse {
        device_id: String,
        //encoded BLAKE3 x ed25519 string
        response: Vec<u8>,
    },
    AcceptConnection(String),
    RejectConnection(String),
    FileRequest(String),
    SeedingFiles
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningServerRequest {
    FetchCrt,
    SignCsr {
        csr: String
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ServerResponse {
    ChallengeRequest {
        device_id: String,
        nonce: Vec<u8>,
    },
    SignedCertificate {
        device_id: String,
        cert_pem: String,
    },
    Certificate {
        cert: String
    },
    SeedingFiles {
        shared_files: Vec<FileEntityDto>
    },
    FileMetadata {
        file_id: String,
        size: u64
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone)]
pub enum ServerActivity {
    SendChallenge { device_id: String , connection: Arc<Mutex<TlsStream<TcpStream>>>},
    VerifiedChallenge { device_id: String },
}

#[derive(Clone, PartialEq, Default, Debug)]
pub enum ConnectionState {
    #[default]
    Unknown,
    Denied,
    Access,
    Pending,
}