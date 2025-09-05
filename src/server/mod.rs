use crate::broadcast::DiscoveredDevice;
use crate::challenge::DeviceChallengeStatus::Active;
use crate::challenge::{generate_challenge, ChallengeEvent, DefaultChallengeManager};
use crate::client::{get_client_connection, get_client_sender};
use crate::consts::data::get_device_id;
use crate::consts::{of_type, DEFAULT_SERVER_PORT, DEFAULT_SIGNING_SERVER_PORT};
use crate::device_manager::{get_device, get_device_by_socket, DefaultDeviceManager};
use crate::diff::files::{get_file, get_seeding_files};
use crate::keychain::server::load::load_server_crt_pem;
use crate::keychain::server::sign_client_csr;
use crate::server::data::{get_default_server, smoke_client_pipe};
use crate::server::model::ConnectionState::{Access, Denied, Pending, Unknown};
use crate::server::model::{
    Crud, ServerActivity, ServerRequest, ServerResponse, ServerTcpPeer, SigningServerRequest,
    TcpServer,
};
use crate::server::util::is_tcp_port_available;
use crate::tcp_utils::{receive_frame, send_file_chunked, send_framed};
use crate::CommonThreadError;
use lazy_static::lazy_static;
use log::{debug, error, info};
use model::ConnectionState;
use rustls::{server, ServerConnection};
use std::error::Error;
use std::fmt::format;
use std::io::{read_to_string, ErrorKind, Write};
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::{fs, io};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task;

pub mod model;
mod util;

pub mod data {
    use crate::server::model::{ServerActivity, TcpServer};
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio::sync::{mpsc, Mutex, OnceCell};
    use tokio_rustls::server::TlsStream;

    static DefaultServer: OnceCell<Arc<TcpServer>> = OnceCell::const_new();
    pub async fn init_server() -> Arc<TcpServer> {
        let channel = mpsc::channel::<ServerActivity>(500);
        let tcp_server = TcpServer::new((channel.0, Mutex::new(channel.1)))
            .await
            .expect("Cannot create new TcpServer instance");
        Arc::new(tcp_server)
    }

    pub async fn get_default_server() -> Arc<TcpServer> {
        let cp = DefaultServer
            .get_or_init(|| async { init_server().await })
            .await;
        cp.clone()
    }

    /**
    Recv server-established connection via server::stream
    CLIENT stream in DefaultClientManager
    */
    pub async fn smoke_client_pipe(client_id: &String) -> Option<Arc<Mutex<TlsStream<TcpStream>>>> {
        let cp = get_default_server().await.connected_devices.clone();
        let mtx = cp.lock().await;

        if let Some(client) = mtx.get(client_id) {
            return Some(client.connection.clone());
        }

        None
    }
}

pub async fn run(server: Arc<TcpServer>) -> Result<(), Box<dyn Error + Send + Sync>> {
    info!("Starting server...");
    let res = tokio::join!(
        tokio::spawn(start_server(Arc::clone(&server))),
        tokio::spawn(start_signing_server()),
        tokio::spawn(listen_actions(Arc::clone(&server))),
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
                    .await
                    .expect("Cant establish secure connection to the device");
                }
                Err(e) => {
                    eprintln!("TLS handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}

/*
Opening server requests transmitter and Sending session authorization request to the client
 */
async fn handle_device_connection(
    server_arc: Arc<TcpServer>,
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    connecting_device_option: Option<DiscoveredDevice>,
) -> Result<(), CommonThreadError> {
    if let Some(connecting_device) = connecting_device_option {
        let (res_sender, mut res_receiver) = mpsc::channel::<ServerResponse>(100);

        {
            let cp = server_arc.connected_devices.clone();
            let mut mtx = cp.lock().await;
            let device_connection = mtx
                .entry(connecting_device.device_id.clone())
                .or_insert_with(|| ServerTcpPeer {
                    device_id: connecting_device.device_id.clone(),
                    connection: Arc::new(Mutex::new(tls_stream)),
                    connection_status: Arc::new(RwLock::new(Unknown)),
                });

            open_device_connection(device_connection, res_sender).await;
        }
        
        let device_id = connecting_device.device_id.clone();
        let _ = server_arc
            .bounded_channel
            .0
            .clone()
            .send(ServerActivity::SendChallenge {
                device_id: device_id.clone(),
            })
            .await;

        tokio::spawn(async move {
            let connection = {
                let connected_devices_arc = server_arc.connected_devices.lock().await;
                if let Some(con) = connected_devices_arc.get(&device_id) {
                    con.connection.clone()
                } else {
                    return;
                }
            };

            loop {
                while let Some(message) = res_receiver.recv().await {
                    debug!("Sending to client: {:?}", message);
                    send_response_to_client(connection.clone(), message.clone())
                        .await
                        .expect(&format!("Cannot send message to the client: {:?}", message));
                }
            }
        });
    }
    Ok(())
}

async fn open_device_connection(
    device_connection: &mut ServerTcpPeer,
    sender: Sender<ServerResponse>,
) {
    let cp = device_connection.clone();

    tokio::spawn(async move {
        debug!("DEVICE CONNECTION OPENED");
        loop {
            let current_status = cp.connection_status.read().await;

            if let Ok(frame) = receive_frame::<_, ServerRequest>(cp.connection.clone()).await {
                debug!("[RECV:{:?}] {:?}", *current_status, frame);
                match *current_status {
                    Access => {
                        match frame {
                            ServerRequest::ChallengeResponse {
                                iv_bytes,
                                salt,
                                ciphertext_with_tag,
                            } => {
                                let challenge_manager = DefaultChallengeManager.clone();
                                challenge_manager
                                    .get_sender()
                                    .send(ChallengeEvent::ChallengeVerification {
                                        device_id: cp.device_id.clone(),
                                        iv_bytes,
                                        salt,
                                        ciphertext_with_tag,
                                    })
                                    .await
                                    .expect("Cannot send");
                            }
                            ServerRequest::RejectConnection(_) => {
                                //todo
                            }
                            ServerRequest::FileRequest(file_id) => {
                                if let Some(file) = get_file(&file_id).await {
                                    send_file_chunked(cp.connection.clone(), &file)
                                        .await
                                        .expect("Error while sending file");
                                }
                            }
                            ServerRequest::SeedingFiles => {
                                sender
                                    .send(ServerResponse::SeedingFiles {
                                        shared_files: get_seeding_files().await,
                                    })
                                    .await
                                    .expect("Cannot send");
                            }
                            _ => {
                                sender
                                    .send(ServerResponse::Error {
                                        message: "Connection already established".to_string(),
                                    })
                                    .await
                                    .expect("Cannot send");
                            }
                        }
                    }
                    Denied => {
                        sender
                            .send(ServerResponse::Error {
                                message: "Denied".to_string(),
                            })
                            .await
                            .expect("Cannot send");
                    }
                    Unknown => {
                        let server_manager = get_default_server().await;
                        server_manager
                            .bounded_channel
                            .0
                            .clone()
                            .send(ServerActivity::SendChallenge {
                                device_id: cp.device_id.clone(),
                            })
                            .await
                            .expect("Cannot send");
                    }
                    _ => match frame {
                        ServerRequest::InitialRequest { .. } => {}
                        ServerRequest::ChallengeResponse { .. } => {}
                        ServerRequest::AcceptConnection(_) => {}
                        ServerRequest::RejectConnection(_) => {}
                        _ => {
                            sender
                                .send(ServerResponse::Error {
                                    message: "Cannot access resource".to_string(),
                                })
                                .await
                                .expect("Cannot send");
                        }
                    },
                }
            }
        }
    });
}

//revision 0509 transmit via server tcp connection to client in order
// to escape connection inconsistency over tcp established sessions - todo review possibilities of transmission over client::tcp_stream
async fn listen_actions(server: Arc<TcpServer>) -> Result<(), CommonThreadError> {
    let server_cp = Arc::clone(&server);

    let mut receiver = server_cp.bounded_channel.1.lock().await;
    while let Some(message) = receiver.recv().await {
        match message {
            ServerActivity::SendChallenge { device_id } => {
                if let Ok(challenge) = get_serialized_challenge(&device_id).await {
                    if let Some(connection) = smoke_client_pipe(&device_id).await {
                        debug!("Sent connection challenge");
                        send_framed(connection.clone(), challenge).await?;
                    }
                }
            }
            ServerActivity::VerifiedChallenge { device_id } => {
                let mut cp = server.connected_devices.lock().await;
                let mut _device = cp.get_mut(&device_id);
                if let Some(device) = _device {
                    let mut mtx = device.connection_status.write().await;
                    *mtx = Access;
                }
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

async fn get_serialized_challenge(
    device_id: &String,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let challenge_query = generate_challenge(&device_id).await?;
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
                                device_id: get_device_id().await,
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
