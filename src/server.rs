use std::fmt::Debug;
use rustls::ServerConfig;

fn create_temp_tcp_server() {
    ServerConfig::builder()
        .unwrap()
}