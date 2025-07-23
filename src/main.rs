use crate::challenge::{cleanup, DefaultChallengeManager};
use crate::client::DefaultClientManager;
use crate::consts::{DeviceId, DEFAULT_LISTENING_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::machine_utils::get_local_ip;
use crate::server::{start_server, DefaultServer};
use crate::state::InternalState;
use crate::ui::start_ui;
use log::info;
use std::error::Error;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use crate::server::tls_utils::clear_client_cert_dir;

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
mod ui;
mod utils;

type NetError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), NetError> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();
    let use_ui = args.contains(&"--ui".to_string()) || args.contains(&"-u".to_string());
    let fresh = args.contains(&"--fresh".to_string()) || args.contains(&"-f".to_string());
    
    if fresh {
        clear_client_cert_dir();
    }

    let addr = initialize();

    if use_ui {
        info!("Starting with UI mode...");
        info!("Use Ctrl+C to stop background services");

        let device_manager_arc = Arc::clone(&DefaultDeviceManager);
        let default_server = Arc::clone(&DefaultServer);
        let device_manager_arc_for_join = device_manager_arc.clone();

        let _background_services = tokio::join!(
            tokio::spawn(broadcast::start_broadcast_announcer(
                DEFAULT_LISTENING_PORT,
                addr
            )),
            tokio::spawn(broadcast::start_listener()),
            tokio::spawn(async move { start_server(default_server).await }),
            tokio::spawn(async move { device_manager_arc_for_join.start().await }),
            tokio::spawn(cleanup()),
            tokio::spawn(async move { start_ui().await })
        );
    } else {
        info!("Starting in headless mode...");
        info!("Use --ui or -u flag to start with terminal interface");

        let device_manager_arc = Arc::clone(&DefaultDeviceManager);
        let default_server = Arc::clone(&DefaultServer);
        let dv_cp = device_manager_arc.clone();
        let device_manager_arc_for_join = device_manager_arc.clone();

        let known_devices_printer_handle = tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(15)).await;

                let known_devices = {
                    let read_guard = dv_cp.known_devices.read().await;
                    read_guard.clone()
                };

                println!("\n--- Known Devices ({} total) ---", known_devices.len());
                for (id, device) in known_devices.iter() {
                    println!(
                        "  ID: {}, Addr: {}, Last Seen: {:?}",
                        id, device.connect_addr, device.last_seen
                    );
                }
                println!("---------------------------------\n");
            }
        });

        let challenge_manager = DefaultChallengeManager.clone();
        let client_manager = DefaultClientManager.clone();
        let tasks = tokio::join!(
            tokio::spawn(broadcast::start_broadcast_announcer(
                DEFAULT_LISTENING_PORT,
                addr
            )),
            tokio::spawn(broadcast::start_listener()),
            tokio::spawn(async move { server::run(default_server.clone()).await }),
            tokio::spawn(async move { challenge::run(challenge_manager.clone()).await }),
            tokio::spawn(async move { client::run(client_manager.clone()).await }),
            tokio::spawn(async move { device_manager_arc_for_join.start().await }),
            tokio::spawn(cleanup()),
            known_devices_printer_handle
        );
    }

    Ok(())
}

fn initialize() -> IpAddr {
    let internal_state = InternalState::new().with_passphrase("bonkers".to_string());

    let local_ip = get_local_ip().expect("Could not determine local IP address");

    info!("My Device ID: {}", &DeviceId[..]);
    info!("My Listening Port: {}", DEFAULT_LISTENING_PORT);
    info!("My Local IP: {}", local_ip);
    
    local_ip
}
