use crate::consts::CommonThreadError;
use crate::server::tls_utils::clear_client_cert_dir;
use std::error::Error;
use std::ops::Deref;

mod balancer;
mod broadcast;
mod challenge;
mod client;
mod consts;
mod device_manager;
mod diff;
mod keychain;
mod machine_utils;
mod server;
mod state;
mod utils;
mod menu;

#[tokio::main]
async fn main() -> Result<(), CommonThreadError> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let fresh = args.contains(&"--fresh".to_string()) || args.contains(&"-f".to_string());

    if fresh {
        clear_client_cert_dir();
    }

    Ok(())
}
