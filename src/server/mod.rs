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
use crate::server::data::{get_default_server, get_server_peer};
use crate::server::model::ConnectionState::{Access, Denied, Pending, Unknown};
use crate::server::model::ServerResponse::FileRequest;
use crate::server::model::{
    Crud, ServerActivity, ServerRequest, ServerResponse, ServerTcpPeer, SigningServerRequest,
    TcpServer,
};
use crate::server::util::is_tcp_port_available;
use crate::tcp_utils::{receive_frame, send_file_chunked, send_framed};
use crate::{CommonThreadError, JoinsChannel};
use futures::future::err;
use futures::AsyncWrite;
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
use std::time::Duration;
use std::{fs, io};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task;
use tokio_rustls::server::TlsStream;

pub mod model;
mod util;

pub mod data {
    use crate::server::model::{ServerActivity, TcpServer};
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex, OnceCell};

    use super::model::ServerTcpPeer;

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
    pub async fn get_server_peer(client_id: &String) -> Option<Arc<ServerTcpPeer>> {
        let server = get_default_server().await;
        let cp = server.connected_devices.clone();
        let mtx = cp.lock().await;

        if let Some(client) = mtx.get(client_id) {
            Some(client.clone())
        } else {
            None
        }
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
    tls_stream: TlsStream<TcpStream>,
    connecting_device_option: Option<DiscoveredDevice>,
) -> Result<(), CommonThreadError> {
    if let Some(connecting_device) = connecting_device_option {
        let (mut read_h, mut write_h) = tokio::io::split(tls_stream);
        let (res_sender, mut res_receiver) = mpsc::channel::<ServerResponse>(100);

        {
            let cp = server_arc.connected_devices.clone();
            let mut mtx = cp.lock().await;
            let _ = mtx
                .entry(connecting_device.device_id.clone())
                .or_insert_with(|| {
                    Arc::new(ServerTcpPeer {
                        device_id: connecting_device.device_id.clone(),
                        response_sender: res_sender.clone(),
                        connection_status: RwLock::new(Unknown),
                    })
                });
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

        let write_task = tokio::spawn(async move {
            while let Some(response) = res_receiver.recv().await {
                debug!("Sending to client: {:?}", response);
                if let FileRequest { file_id } = response {
                    if let Some(file) = get_file(&file_id).await {
                        send_file_chunked(&mut write_h, &file)
                            .await
                            .expect("Error while sending file");
                    }
                } else {
                    send_response_to_client(&mut write_h, response)
                        .await
                        .expect("Cannot send message to the client");
                }
            }
        });

        let read_task = tokio::spawn(async move {
            let cp = server_arc.connected_devices.clone();
            let connection_arc = {
                let connected_devices_guard = cp.lock().await;

                if let Some(device_peer) = connected_devices_guard.get(&device_id) {
                    device_peer.clone()
                } else {
                    return;
                }
            };
            loop {
                match receive_frame::<_, ServerRequest>(&mut read_h).await {
                    Ok(frame) => {
                        let current_state = connection_arc.connection_status.read().await.clone();
                        consume_frame(res_sender.clone(), current_state, frame, device_id.clone())
                            .await;
                    }
                    Err(e) => {
                        error!("Cannot receive frame: {:?}", e);
                    }
                }
            }
        });

        JoinsChannel.0.send(write_task)?;
        JoinsChannel.0.send(read_task)?;
    }
    Ok(())
}

async fn consume_frame(
    response_sender: Sender<ServerResponse>,
    current_status: ConnectionState,
    frame: ServerRequest,
    device_id: String,
) {
    match current_status {
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
                            device_id,
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
                ServerRequest::FileRequest(file_id) => {}
                ServerRequest::SeedingFiles => {
                    response_sender
                        .send(ServerResponse::SeedingFiles {
                            shared_files: get_seeding_files().await,
                        })
                        .await
                        .expect("Cannot send");
                }
                _ => {
                    response_sender
                        .send(ServerResponse::Error {
                            message: "Connection already established".to_string(),
                        })
                        .await
                        .expect("Cannot send");
                }
            }
        }
        Denied => {
            response_sender
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
                .send(ServerActivity::SendChallenge { device_id })
                .await
                .expect("Cannot send");
        }
        _ => match frame {
            ServerRequest::InitialRequest { .. } => {}
            ServerRequest::ChallengeResponse { .. } => {}
            ServerRequest::AcceptConnection(_) => {}
            ServerRequest::RejectConnection(_) => {}
            _ => {
                response_sender
                    .send(ServerResponse::Error {
                        message: "Cannot access resource".to_string(),
                    })
                    .await
                    .expect("Cannot send");
            }
        },
    }
}

//revision 0509 transmit via server tcp connection to client in order
// to escape connection inconsistency over tcp established sessions - todo review possibilities of transmission over client::tcp_stream
async fn listen_actions(server: Arc<TcpServer>) -> Result<(), CommonThreadError> {
    let server_cp = Arc::clone(&server);

    let mut receiver = server_cp.bounded_channel.1.lock().await;
    while let Some(message) = receiver.recv().await {
        match message {
            ServerActivity::SendChallenge { device_id } => {
                let challenge_query = generate_challenge(&device_id).await?;
                if let Some(connection) = get_server_peer(&device_id).await {
                    connection.response_sender.send(challenge_query)
                        .await?;
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

async fn send_response_to_client<T>(
    connection: &mut T,
    response: ServerResponse,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    T: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let serialized = serde_json::to_vec(&response)?;
    send_framed(connection, serialized).await
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
