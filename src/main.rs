use crate::consts::CommonThreadError;
use crate::menu::display_menu;
use crate::utils::DirType::Action;
use crate::utils::{get_client_cert_storage, get_default_application_dir, get_server_cert_storage};
use lazy_static::lazy_static;
use log::{error, info};
use tokio::runtime::Handle;
use std::fs;
use std::path::PathBuf;
use once_cell::sync::OnceCell;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

mod broadcast;
mod challenge;
mod client;
mod consts;
mod device_manager;
mod diff;
mod keychain;
mod machine_utils;
mod menu;
mod server;
mod tcp_utils;
mod utils;

lazy_static! {
    pub static ref JoinsChannel: (
        UnboundedSender<JoinHandle<()>>,
        Mutex<UnboundedReceiver<JoinHandle<()>>>
    ) = {
        let (tx, rx) = mpsc::unbounded_channel::<JoinHandle<()>>();
        (tx, Mutex::new(rx))
    };
}
static TOKIO_HANDLE: OnceCell<Handle> = OnceCell::new();
fn get_handle() -> &'static Handle {
    TOKIO_HANDLE.get().expect("Tokio runtime handle is not initialized")
}

#[tokio::main]
async fn main() -> Result<(), CommonThreadError> {
    TOKIO_HANDLE.set(Handle::current())
        .expect("Failed to set tokio handle");

    construct();
    display_menu();

    Ok(())
}

fn construct() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let fresh = args.contains(&"--fresh".to_string()) || args.contains(&"-f".to_string());

    if fresh {
        let dir = get_client_cert_storage();
        fs::remove_dir_all(dir).expect("Cannot clear client cert DIR");

        fs::remove_dir_all(get_server_cert_storage()).expect("Cannot clear server cert DIR");

        fs::remove_dir_all(get_default_application_dir(Action))
            .expect("Cannot clear application DIR");
    }
    load_banner();

    joins_listener();
}

fn joins_listener() {
    let handle = tokio::spawn(async move {

        let mut mtx = JoinsChannel.1.lock().await;
        while let Some(handle) = mtx.recv().await {
            let handle_id = handle.id();
            info!("received handler {}", handle_id);
            if let Err(e) = handle.await {
                error!("Thread: {}, threw error: {}", handle_id, e);
            }
        }
    });

    JoinsChannel.0.clone().send(handle)
        .expect("Cannot send");
}

fn load_banner() {
    let assets = PathBuf::from("assets");
    if assets.exists() {
        if fs::exists(assets.join("banner.txt")).unwrap_or(false) {
            println!(
                "{}",
                fs::read_to_string(assets.join("banner.txt")).unwrap_or(String::new())
            );
        }
    }
}
