use std::net::SocketAddr;
use tokio::net::TcpListener;

pub async fn is_tcp_port_available(port: u16) -> bool {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    match TcpListener::bind(addr).await {
        Ok(listener) => {
            drop(listener);
            true
        }
        Err(_) => false,
    }
}