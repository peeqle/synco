use crate::client::load_client_cas;
use crate::keychain::{load_cert_der, load_private_key_der};
use crate::machine_utils::get_local_ip;
use crate::utils::validate_server_cert_present;
use lazy_static::lazy_static;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{crypto, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_rustls::TlsAcceptor;

mod tls_utils;

const DEFAULT_SERVER_PORT: u64 = 21029;

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
    pub(crate) bounded_channel: (
        Sender<ConnectionRequestQuery>,
        Receiver<ConnectionRequestQuery>,
    ),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ConnectionRequestQuery {
    InitialRequest {
        device_id: String,
    },
    ChallengeRequest {
        device_id: String,
        nonce: Vec<u8>,
        passphrase_hash: Vec<u8>,
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
            return Err(Box::new(io::Error::new(
                ErrorKind::InvalidData,
                "Server certificates are invalid, try to run [regenerate]",
            )));
        }
        let configuration = Self::create_server_config()?;
        Ok(TcpServer {
            local_ip: get_local_ip().unwrap(),
            loaded_configuration: configuration.clone(),
            current_acceptor: Arc::new(TlsAcceptor::from(Arc::new(configuration))),
            bounded_channel: server_channel,
        })
    }

    fn create_server_config() -> io::Result<ServerConfig> {
        let server_certs = load_cert_der()?;
        let server_key = load_private_key_der()?;

        let client_root_store = load_client_cas()?;

        let client_cert_verifier: Arc<dyn ClientCertVerifier> = {
            WebPkiClientVerifier::builder(Arc::new(client_root_store))
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

    async fn _start(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let listener =
            TcpListener::bind(format!("{}:{}", &self.local_ip, DEFAULT_SERVER_PORT)).await?;
        println!(
            "Server listening on {}:{}",
            &self.local_ip, DEFAULT_SERVER_PORT
        );

        loop {
            tokio::select! {
            Ok((socket, peer_addr)) = listener.accept() => {
                                let acceptor = self.current_acceptor.clone();
                                tokio::spawn(async move {
                                    match acceptor.accept(socket).await {
                                        Ok(mut tls_stream) => {
                                let(reader, writer) = tls_stream.get_ref();
                                let mut buf = [0;1024];let read_result = reader.try_read(&mut buf);}Err(e) => {eprintln!("TLS handshake failed with {}: {}", peer_addr, e);}}});}}
        }
    }

    pub fn get_channel_sender(&self) -> Sender<ConnectionRequestQuery> {
        self.bounded_channel.0.clone()
    }
}
