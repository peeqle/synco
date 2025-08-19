use crate::consts::CommonThreadError;
use crate::menu::display_menu;
use crate::utils::DirType::Action;
use crate::utils::{get_client_cert_storage, get_default_application_dir, get_server_cert_storage};
use std::error::Error;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;

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
mod tcp_utils;

#[tokio::main]
async fn main() -> Result<(), CommonThreadError> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let fresh = args.contains(&"--fresh".to_string()) || args.contains(&"-f".to_string());

    if fresh {
        let dir = get_client_cert_storage();
        fs::remove_dir_all(dir).expect("Cannot clear client cert DIR");

        fs::remove_dir_all(get_server_cert_storage())
            .expect("Cannot clear server cert DIR");

        fs::remove_dir_all(get_default_application_dir(Action))
            .expect("Cannot clear application DIR");
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