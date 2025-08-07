use crate::consts::CommonThreadError;
use crate::menu::display_menu;
use crate::server::tls_utils::clear_client_cert_dir;
use std::error::Error;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

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

    load_banner();
    display_menu();

    Ok(())
}

fn load_banner() {
    let assets = PathBuf::from("assets");
    if assets.exists() {
        if fs::exists(assets.join("banner.txt")).unwrap_or(false) {
            println!("{}", fs::read_to_string(assets.join("banner.txt")).unwrap_or(String::new()));
        }
    }
}