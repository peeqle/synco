use crate::connection::challenge_manager_listener_run;
use crate::consts::{DeviceId, DEFAULT_LISTENING_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::machine_utils::get_local_ip;
use crate::server::DefaultServer;
use crate::state::InternalState;
use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use log::info;
use tokio::time::sleep;

mod balancer;
mod broadcast;
mod client;
mod connection;
mod consts;
mod device_manager;
mod diff;
mod keychain;
mod machine_utils;
mod server;
mod state;
mod utils;

type NetError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), NetError> {
    env_logger::init();
    let internal_state = InternalState::new().with_passphrase("bonkers".to_string());

    let local_ip = get_local_ip().expect("Could not determine local IP address");

    info!("My Device ID: {}", &DeviceId[..]);
    info!("My Listening Port: {}", DEFAULT_LISTENING_PORT);
    info!("My Local IP: {}", local_ip);

    let device_manager_arc = Arc::clone(&DefaultDeviceManager);
    let default_server = Arc::clone(&DefaultServer);
    let dv_cp = device_manager_arc.clone();
    let device_manager_arc_for_join = device_manager_arc.clone();

    let known_devices_printer_handle = tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(15)).await;

            let known_devices = {
                let read_guard = dv_cp.known_devices.read().unwrap();
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

    tokio::spawn(async move {
        connection::cleanup().await;
    });

    tokio::try_join!(
        tokio::spawn(broadcast::start_broadcast_announcer(
            DEFAULT_LISTENING_PORT,
            local_ip
        )),
        tokio::spawn(broadcast::start_listener()),
        tokio::spawn(async move { default_server.start().await }),
        tokio::spawn(async move { device_manager_arc_for_join.start().await }),
        tokio::spawn(challenge_manager_listener_run()),
        known_devices_printer_handle
    );

    Ok(())
}
