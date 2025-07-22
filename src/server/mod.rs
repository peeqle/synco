use crate::broadcast::DiscoveredDevice;
use crate::challenge::DeviceChallengeStatus::Active;
use crate::challenge::{
    generate_challenge, ChallengeEvent, DefaultChallengeManager, DeviceChallengeStatus,
};
use crate::consts::{CA_CERT_FILE_NAME, DEFAULT_SERVER_PORT};
use crate::device_manager::{get_device, DefaultDeviceManager};
use crate::keychain::{generate_server_ca_keys, load_cert_der, load_private_key_der};
use crate::machine_utils::get_local_ip;
use crate::server::model::ConnectionRequestQuery::RejectConnection;
use crate::server::model::ConnectionState::{Access, Denied, Pending, Unknown};
use crate::server::model::{ConnectionRequestQuery, ConnectionState, ServerActivity, StaticCertResolver, TcpPeer, TcpServer};
use crate::utils::{
    decrypt_with_passphrase, get_server_cert_storage, load_cas, validate_server_cert_present,
};
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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

mod tls_utils;
pub(crate) mod model;

lazy_static! {
    pub static ref DefaultServer: Arc<TcpServer> = {
        let channel = mpsc::channel::<ServerActivity>(500);
        let tcp_server = TcpServer::new((channel.0, Mutex::new(channel.1)))
            .expect("Cannot create new TcpServer instance");
        Arc::new(tcp_server)
    };
}

pub async fn run(server: Arc<TcpServer>) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting server...");
    let res = tokio::try_join!(
        tokio::spawn(start_server(Arc::clone(&server))),
        tokio::spawn(listen_actions(Arc::clone(&server))),
    );

    match res {
        Ok((start_server_result, listen_actions_result)) => {
            start_server_result?;
            listen_actions_result?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Error in run: {:?}", e);
            Err(e.into())
        }
    }
}

pub async fn start_server(server: Arc<TcpServer>) -> Result<(), NetError> {
    if !is_tcp_port_available(DEFAULT_SERVER_PORT).await {
        panic!("Cannot start server on {}", DEFAULT_SERVER_PORT);
    }

    let listener =
        TcpListener::bind(format!("{}:{}", server.local_ip, DEFAULT_SERVER_PORT)).await?;

    let acceptor = server.current_acceptor.clone();
    let default_device_manager = DefaultDeviceManager.clone();

    info!("Server started.");
    loop {
        let (socket, peer_addr) = listener.accept().await?;

        let server_arc = server.clone();
        let acceptor_clone = acceptor.clone();
        let default_device_manager_clone = default_device_manager.clone();
        task::spawn(async move {
            match acceptor_clone.accept(socket).await {
                Ok(mut tls_stream) => {
                    let (tcp_stream, connection) = tls_stream.get_mut();

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

                            server_known_device.is_some()
                                && server_known_device.unwrap().connection_status != Denied && server_known_device.unwrap().connection_status != Access
                        };

                        if can_connect {
                            if let Err(e) = open_stream(
                                server_arc.clone(),
                                connecting_device.device_id.clone(),
                                tls_stream,
                            ).await {
                                error!("Failed to open stream for device {}: {}",
                       connecting_device.device_id, e);
                            }
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

async fn open_stream(
    server: Arc<TcpServer>,
    device_id: String,
    tls_stream: TlsStream<TcpStream>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if server.connected_devices.lock().await.contains_key(&device_id) {
        return Err(Box::new(io::Error::new(
            ErrorKind::AlreadyExists,
            "Peer connection already established",
        )));
    }
    
    let (sender, receiver) = mpsc::channel::<String>(100);

    let tcp_peer = TcpPeer {
        device_id: device_id.clone(),
        connection: Arc::new(Mutex::new(tls_stream)),
        connection_status: Unknown,
        sender,
    };

    server.connected_devices.lock().await.insert(device_id.clone(), tcp_peer);

    let server_clone = server.clone();
    let device_id_clone = device_id.clone();
    tokio::spawn(async move {
        handle_client_actions(
            server_clone,
            device_id_clone,
            receiver,
        ).await;
    });

    info!("Successfully created and opened TcpPeer connection");
    Ok(())
}

async fn handle_client_actions(
    server: Arc<TcpServer>,
    device_id: String,
    mut client_receiver: Receiver<String>,
) {
    info!("Started client handler for device: {}", device_id);

    while let Some(message) = client_receiver.recv().await {
        info!("Received message from {}: {}", device_id, message);

        match serde_json::from_str::<ConnectionRequestQuery>(&message) {
            Ok(query) => {
                match query {
                    ConnectionRequestQuery::InitialRequest { .. } => {}
                    ConnectionRequestQuery::ChallengeRequest { .. } => {}
                    ConnectionRequestQuery::ChallengeResponse { .. } => {
                        if let Err(e) = DefaultChallengeManager
                            .get_sender()
                            .send(ChallengeEvent::ChallengeVerification {
                                connection_response: query,
                            })
                            .await
                        {
                            error!("Failed to send challenge verification: {}", e);
                        }
                    }
                    ConnectionRequestQuery::AcceptConnection(_) => {}
                    ConnectionRequestQuery::RejectConnection(_) => {
                        break;
                    }
                }
            }
            Err(err) => {
                error!("Error processing message from {}: {}", device_id, err);
            }
        }
    }
    info!("Client handler for device {} has ended", device_id);
    server.connected_devices.lock().await.remove(&device_id);
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

async fn handle_receiver_message(
    server: Arc<TcpServer>,
    message: ServerActivity,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match message {
        ServerActivity::SendChallenge { device_id } => {
            info!("Received new connection request to: {}", &device_id);
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
                    return Err(Box::new(io::Error::new(
                        ErrorKind::AlreadyExists,
                        "Connection is denied",
                    )));
                }
                if device_connection.connection_status == Access {
                    return Err(Box::new(io::Error::new(
                        ErrorKind::AlreadyExists,
                        "Connection is already opened",
                    )));
                }
            }
        }
        ServerActivity::VerifiedChallenge { device_id } => {
            let mut cp = server.connected_devices.lock().await;
            let mut _device = cp.get_mut(&device_id);
            if let Some(device) = _device {
                device.connection_status = Access;
            }
        }
    }
    Ok(())
}

async fn send_challenge(
    device: DiscoveredDevice,
    connection: &mut ServerConnection,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Ok(ser) = get_serialized_challenge(device.clone()).await {
        if let Err(e) = connection.writer().write_all(&ser) {
            eprintln!("Failed to write challenge: {}", e);
            Err(Box::new(io::Error::new(
                ErrorKind::Interrupted,
                format!("Failed to write challenge: {}", e),
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

async fn is_tcp_port_available(port: u16) -> bool {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    match TcpListener::bind(addr).await {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}

mod test {}