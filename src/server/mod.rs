use crate::keychain::{load_cert_arc, load_private_key_arc};
use crate::utils::get_client_cert_storage_server;
use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose, date_time_ymd,
};
use rustls::ServerConfig;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::hash::Hash;
use tokio::net::TcpListener;

mod tls_utils;

struct TcpServer {
    tcp_listener: TcpListener,
    loaded_configuration: ServerConfig,
}
