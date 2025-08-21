use crate::broadcast::DiscoveredDevice;
use crate::challenge::{generate_challenge, ChallengeEvent, DefaultChallengeManager};
use crate::consts::{
    of_type, DeviceId, CA_CERT_FILE_NAME, DEFAULT_SERVER_PORT, DEFAULT_SIGNING_SERVER_PORT,
};
use crate::device_manager::{get_device, get_device_by_socket, DefaultDeviceManager};
use crate::diff::{attach, get_file, get_seeding_files, Files};
use crate::keychain::server::load::load_server_crt_pem;
use crate::keychain::server::sign_client_csr;
use crate::keychain::{load_cert, load_cert_der};
use crate::server::model::ConnectionState::{Access, Denied, Unknown};
use crate::server::model::{
    Crud, ServerActivity, ServerRequest, ServerResponse, ServerTcpPeer, SigningServerRequest,
    TcpServer,
};
use crate::server::util::is_tcp_port_available;
use crate::tcp_utils::{receive_frame, send_file_chunked, send_framed};
use crate::CommonThreadError;
use lazy_static::lazy_static;
use log::{error, info};
use rustls::{server, ServerConnection};
use std::error::Error;
use std::fmt::format;
use std::io::{read_to_string, ErrorKind, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{fs, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio::task::spawn_blocking;
use tokio_rustls::TlsStream;

pub(crate) mod model;
mod util;

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
        panic!(
            "Cannot start signing server on {}",
            DEFAULT_SIGNING_SERVER_PORT
        );
    }
    let listener = TcpListener::bind(format!("0.0.0.0:{}", DEFAULT_SIGNING_SERVER_PORT)).await?;

    info!(
        "Signing server started at: {}",
        listener.local_addr()?.ip().to_string()
    );
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

                    handle_device_connection(
                        server_arc.clone(),
                        tls_stream,
                        connecting_device_option,
                    )
                    .await;
                }
                Err(e) => {
                    eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}

async fn handle_device_connection(
    server_arc: Arc<TcpServer>,
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    connecting_device_option: Option<DiscoveredDevice>,
) -> Result<(), CommonThreadError> {
    if let Some(connecting_device) = connecting_device_option {
        let (res_sender, mut res_receiver) = mpsc::channel::<ServerResponse>(100);

        {
            let mut connected_devices_arc = server_arc.connected_devices.lock().await;
            let device_connection = connected_devices_arc
                .entry(connecting_device.device_id.clone())
                .or_insert_with(|| ServerTcpPeer {
                    device_id: connecting_device.device_id.clone(),
                    connection: Arc::new(Mutex::new(tls_stream)),
                    connection_status: Unknown,
                });

            if device_connection.connection_status == Unknown {
                open_device_connection(device_connection, res_sender).await;
            }
        }

        let device_id = connecting_device.device_id.clone();
        tokio::spawn(async move {
            let connected_device_id = device_id.clone();

            let connection = {
                let connected_devices_arc = server_arc.connected_devices.lock().await;
                if let Some(con) = connected_devices_arc.get(&connected_device_id) {
                    con.connection.clone()
                } else {
                    return;
                }
            };

            loop {
                while let Some(message) = res_receiver.recv().await {
                    send_response_to_client(connection.clone(), message.clone())
                        .await
                        .expect(&format!("Cannot send message to the client: {:?}", message));
                }
            }
        });
    }
    Ok(())
}

async fn open_device_connection(device_connection: &mut ServerTcpPeer, sender: Sender<ServerResponse> ) {
    let connection = device_connection.connection.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(request) = receive_frame(connection.clone()).await {
                match request {
                    ServerRequest::InitialRequest { .. } => {}
                    ServerRequest::ChallengeRequest { .. } => {}
                    ServerRequest::ChallengeResponse { .. } => {}
                    ServerRequest::AcceptConnection(_) => {}
                    ServerRequest::RejectConnection(_) => {}
                    ServerRequest::FileRequest(file_id) => {
                        if let Some(file) = get_file(&file_id).await {
                            send_file_chunked(connection.clone(), &file)
                                .await
                                .expect("Error while sending file");
                        }
                    }
                    ServerRequest::SeedingFiles => {
                        sender
                            .send(ServerResponse::SeedingFiles {
                                files_data: get_seeding_files().await,
                            })
                            .await
                            .expect("Cannot send");
                    }
                }
            }
        }
    });
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
    send_framed(connection, serialized).await
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

async fn handle_ca_request(
    mut stream: TcpStream,
    socket: SocketAddr,
) -> Result<(), CommonThreadError> {
    let mut buffer = vec![0; 4096];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .map_err(|e| of_type("Failed to read client request", ErrorKind::Other))?;

    let current_device_id = DeviceId.clone();

    match serde_json::from_slice::<SigningServerRequest>(&buffer[..bytes_read]) {
        Ok(request) => {
            match request {
                SigningServerRequest::FetchCrt => {
                    if let Some(device) = get_device_by_socket(&socket).await {
                        info!(
                            "Received CRT request from device {}. Attempting to load origin CA...",
                            device.device_id
                        );
                        match load_server_crt_pem() {
                            Ok(ca_cert) => {
                                stream
                                    .write_all(&serde_json::to_vec(&ServerResponse::Certificate {
                                        cert: ca_cert.clone(),
                                    })?)
                                    .await?;
                            }
                            Err(e) => {
                                error!("Failed to load server certificate: {}", e);
                                stream
                                    .write_all(&serde_json::to_vec(&ServerResponse::Error {
                                        message: format!(
                                            "Failed to load server certificate: {}",
                                            e
                                        ),
                                    })?)
                                    .await?;
                            }
                        }
                    } else {
                        error!(
                            "Device not found for IP address: {}. Device must be discovered first through UDP broadcast.",
                            socket.ip()
                        );
                        stream.write_all(&serde_json::to_vec(
                            &ServerResponse::Error {
                                message: format!("Device not found for IP address: {}. Device must be discovered first through UDP broadcast.", socket.ip())
                            }
                        )?).await?;
                    }
                }
                SigningServerRequest::SignCsr { csr } => match sign_client_csr(&csr) {
                    Ok(signed_crt) => {
                        stream
                            .write_all(&serde_json::to_vec(&ServerResponse::SignedCertificate {
                                device_id: current_device_id,
                                cert_pem: String::from_utf8_lossy(signed_crt.as_slice())
                                    .to_string(),
                            })?)
                            .await?;
                    }
                    Err(e) => {
                        error!("Failed to sign client CSR: {}", e);
                        stream
                            .write_all(&serde_json::to_vec(&ServerResponse::Error {
                                message: format!("Failed to sign client CSR: {}", e),
                            })?)
                            .await?;
                    }
                },
            }
            Ok(())
        }
        Err(e) => {
            error!("Failed to deserialize signing server request: {}", e);
            stream
                .write_all(&serde_json::to_vec(&ServerResponse::Error {
                    message: format!("Invalid request format: {}", e),
                })?)
                .await?;
            Ok(())
        }
    }
}
