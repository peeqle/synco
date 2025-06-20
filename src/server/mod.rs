use crate::client::load_client_cas;
use crate::keychain::{load_cert_der, load_private_key_der};
use crate::utils::validate_server_cert_present;
use rustls::server::danger::ClientCertVerifier;
use rustls::server::{ResolvesServerCert, WebPkiClientVerifier};
use rustls::{ServerConfig, crypto};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io;
use std::io::ErrorKind;
use std::ops::Deref;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

mod tls_utils;

const DEFAULT_SERVER_PORT: u64 = 20000;

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

struct TcpServer {}

impl TcpServer {
    pub async fn start(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let validation = validate_server_cert_present();
        if !validation {
            return Err(Box::new(io::Error::new(
                ErrorKind::InvalidData,
                "Server certificates are invalid, try to run [regenerate]",
            )));
        }
        let acceptor = TlsAcceptor::from(Arc::new(create_server_config()?));

        let listener = TcpListener::bind(format!("127.0.0.1:{}", DEFAULT_SERVER_PORT)).await?;
        println!("Server listening on 127.0.0.1:{}", DEFAULT_SERVER_PORT);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(mut tls_stream) => {
                        let mut buf = Vec::new();
                        match tls_stream.read_to_end(&mut buf).await {
                            Ok(n) => println!(
                                "Read {} bytes from client: {:?}",
                                n,
                                String::from_utf8_lossy(&buf)
                            ),
                            Err(e) => eprintln!("Error reading from client: {}", e),
                        }
                        match tls_stream.write_all(b"Hello from server!").await {
                            Ok(_) => println!("Sent data to client."),
                            Err(e) => eprintln!("Error writing to client: {}", e),
                        }
                    }
                    Err(e) => {
                        eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                    }
                }
            });
        }
    }
}

pub fn create_server_config() -> io::Result<ServerConfig> {
    let server_certs = load_cert_der()?;
    let server_key = load_private_key_der()?;

    let client_root_store = load_client_cas()?;

    let client_cert_verifier: Arc<dyn ClientCertVerifier> = {
        WebPkiClientVerifier::builder(Arc::new(client_root_store))
            .build()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
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
