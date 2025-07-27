use crate::broadcast::DiscoveredDevice;
use crate::challenge::{
    generate_challenge, ChallengeEvent, DefaultChallengeManager,
};
use crate::consts::{of_type, DeviceId, CA_CERT_FILE_NAME, DEFAULT_SERVER_PORT, DEFAULT_SIGNING_SERVER_PORT};
use crate::device_manager::{get_device, get_device_by_socket, DefaultDeviceManager};
use crate::keychain::server::{load_server_crt_pem, sign_client_csr};
use crate::keychain::{load_cert, load_cert_der};
use crate::server::model::ConnectionState::{Access, Denied, Unknown};
use crate::server::model::{ServerActivity, ServerRequest, ServerResponse, ServerTcpPeer, SigningServerRequest, TcpServer};
use crate::utils::get_server_cert_storage;
use crate::CommonThreadError;
use lazy_static::lazy_static;
use log::{error, info};
use rustls::{server, ServerConnection};
use std::error::Error;
use std::fmt::format;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fs, io};
use std::thread::sleep;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio::task::spawn_blocking;
use tokio_rustls::TlsStream;

pub(crate) mod tls_utils;
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
    let res = tokio::join!(
        tokio::spawn(start_server(Arc::clone(&server))),
        tokio::spawn(listen_actions(Arc::clone(&server))),
        tokio::spawn(start_signing_server()),
    );
    Ok(())
}

pub async fn start_signing_server() -> Result<(), CommonThreadError> {
    if !is_tcp_port_available(DEFAULT_SIGNING_SERVER_PORT).await {
        panic!("Cannot start signing server on {}", DEFAULT_SIGNING_SERVER_PORT);
    }
    let listener = TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_SIGNING_SERVER_PORT)).await?;

    info!("Signing server started at: {}", listener.local_addr()?.ip().to_string());
    loop {
        let (stream, socket) = listener.accept().await?;
        tokio::spawn(handle_ca_request(stream, socket));
    }
}


pub async fn start_server(server: Arc<TcpServer>) -> Result<(), CommonThreadError> {
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
                Ok(tls_stream) => {
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


                        let (req_sender, req_receiver) = mpsc::channel::<ServerRequest>(100);
                        let (res_sender, mut res_receiver) = mpsc::channel::<ServerResponse>(100);

                        {
                            let mut connected_devices_arc = server_arc.connected_devices.lock().await;
                            let device_connection = connected_devices_arc.entry(connecting_device.device_id.clone())
                                .or_insert_with(|| ServerTcpPeer {
                                    device_id: connecting_device.device_id.clone(),
                                    connection: Arc::new(Mutex::new(tls_stream)),
                                    connection_status: Unknown,
                                    writer_request: req_sender,
                                    writer_response: res_sender,
                                });
                            if device_connection.connection_status == Unknown {
                                let server_clone = server_arc.clone();
                                tokio::spawn(async move {
                                    info!("Peer connection established");
                                    handle_client_actions(
                                        server_clone,
                                        connecting_device.device_id.clone(),
                                        req_receiver,
                                    ).await.expect("Pipe broken: handle_client_actions");
                                });
                            }

                            let connection = device_connection.connection.clone();
                            tokio::spawn(async move {
                                let mut  mtx = connection.lock().await;
                                let(c, m) = mtx.get_mut();
                                m.writer().write_all(b"Ping").unwrap();
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            });
                        }


                        tokio::spawn(async move {
                            loop {
                                while let Some(message) = res_receiver.recv().await {
                                    match message.clone() {
                                        ServerResponse::SignedCertificate { device_id, .. } => {
                                            let connected_devices_arc = server_arc.connected_devices.lock().await;
                                            if let Some(_device) = connected_devices_arc.get(&device_id) {
                                                send_response_to_client(_device.connection.clone(), message.clone()).await
                                                    .expect(&format!("Cannot send message to the client: {:?}", message));
                                            }
                                        }
                                        ServerResponse::Error { .. } => {}
                                        ServerResponse::Certificate { .. } => {}
                                    }
                                }
                            }
                        });
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}


async fn handle_client_actions(
    server: Arc<TcpServer>,
    device_id: String,
    mut server_receiver: Receiver<ServerRequest>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Started client handler for device: {}", device_id);

    while let Some(message) = server_receiver.recv().await {
        info!("Received message from {}: {:?}", device_id, message);
        match message {
            ServerRequest::InitialRequest { .. } => {}
            ServerRequest::ChallengeRequest { .. } => {}
            ServerRequest::ChallengeResponse { .. } => {
                if let Err(e) = DefaultChallengeManager
                    .get_sender()
                    .send(ChallengeEvent::ChallengeVerification {
                        connection_response: message,
                    })
                    .await
                {
                    error!("Failed to send challenge verification: {}", e);
                }
            }
            ServerRequest::AcceptConnection(_) => {}
            ServerRequest::RejectConnection(_) => {
                break;
            }
        }
    }
    info!("Client handler for device {} has ended", device_id);
    server.connected_devices.lock().await.remove(&device_id);
    Ok(())
}

async fn listen_actions(server: Arc<TcpServer>) -> Result<(), Box<dyn Error + Send + Sync>> {
    let server_cp = Arc::clone(&server);

    let mut receiver = server_cp.bounded_channel.1.lock().await;
    while let Some(message) = receiver.recv().await {
        handle_receiver_message(server_cp.clone(), message).await?;
    }
    Ok(())
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
                        // match send_challenge(d_device, &mut mutex).await {
                        //     Ok(_) => {
                        //         device_connection.connection_status = Pending;
                        //     }
                        //     Err(_) => {}
                        // }
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

async fn send_response_to_client(
    connection: Arc<Mutex<tokio_rustls::server::TlsStream<TcpStream>>>,
    response: ServerResponse,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let serialized = serde_json::to_vec(&response)?;
    if let Err(e) = connection.lock().await.write_all(&serialized).await {
        Err(Box::new(io::Error::new(
            ErrorKind::Interrupted,
            format!("Failed to write response: {}", e),
        )))
    } else {
        connection.lock().await.flush().await?;
        Ok(())
    }
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

async fn handle_ca_request(mut stream: TcpStream, socket: SocketAddr) -> Result<(), CommonThreadError> {
    let mut buffer = vec![0; 4096];
    let bytes_read = stream.read(&mut buffer).await
        .map_err(|e| of_type("Failed to read client request", ErrorKind::Other))?;

    let current_device_id = DeviceId.clone();

    match serde_json::from_slice::<SigningServerRequest>(&buffer[..bytes_read]) {
        Ok(request) => {
            match request {
                SigningServerRequest::FetchCrt => {
                    if let Some(device) = get_device_by_socket(&socket).await {
                        info!("Received CSR from device {}. Attempting to load origin CA...", device.device_id);
                        let ca_cert = load_server_crt_pem()?;

                        stream.write_all(&serde_json::to_vec(
                            &ServerResponse::Certificate {
                                cert: ca_cert.clone()
                            }
                        )?).await?;
                    }
                }
                SigningServerRequest::SignCsr { csr } => {
                    let (signed_crt, _) = sign_client_csr(&csr)?;
                    stream.write_all(&serde_json::to_vec(
                        &ServerResponse::SignedCertificate {
                            device_id: current_device_id,
                            cert_pem: String::from_utf8_lossy(signed_crt.as_slice()).to_string(),
                        }
                    )?).await?;
                }
            }
            Ok(())
        }
        Err(e) => {
            Err(of_type("Cannot sign client CA", ErrorKind::Other))
        }
    }
}
//
// async fn handle_device_csr_signing(csr_pem: String) -> Result<Vec<u8>, CommonThreadError> {
//     let sign_result = spawn_blocking(move || {
//         sign_client_csr(&csr_pem)
//     }).await;
//
//     match sign_result? {
//         Ok((signed_cert, path)) => {
//             Ok(signed_cert)
//         }
//         Err(e) => {
//             error!("Failed to sign CSR");
//             Err(e)
//         }
//     }
// }

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