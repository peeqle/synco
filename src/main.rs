use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use crate::challenge::cleanup;
use crate::consts::{DEFAULT_LISTENING_PORT, DeviceId};
use crate::device_manager::DefaultDeviceManager;
use crate::machine_utils::get_local_ip;
use crate::server::{DefaultServer, start_server};
use crate::state::InternalState;
use crate::ui::start_ui;
use tokio::time::sleep;

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
    // Check for UI flag
    let args: Vec<String> = std::env::args().collect();
    let use_ui = args.contains(&"--ui".to_string()) || args.contains(&"-u".to_string());

    let internal_state = InternalState::new().with_passphrase("bonkers".to_string());

    let local_ip = get_local_ip().expect("Could not determine local IP address");

    println!("My Device ID: {}", &DeviceId[..]);
    println!("My Listening Port: {}", DEFAULT_LISTENING_PORT);
    println!("My Local IP: {}", local_ip);

    if use_ui {
        println!("Starting with UI mode...");
        println!("Use Ctrl+C to stop background services");
        
        let device_manager_arc = Arc::clone(&DefaultDeviceManager);
        let default_server = Arc::clone(&DefaultServer);
        let device_manager_arc_for_join = device_manager_arc.clone();

        // Start background services
        let _background_services = tokio::try_join!(
            tokio::spawn(broadcast::start_broadcast_announcer(
                DEFAULT_LISTENING_PORT,
                local_ip
            )),
            tokio::spawn(broadcast::start_listener()),
            tokio::spawn(async move { start_server(default_server).await }),
            tokio::spawn(async move { device_manager_arc_for_join.start().await }),
            tokio::spawn(cleanup()),
            tokio::spawn(async move {
                // Give services time to start
                sleep(Duration::from_secs(2)).await;
                start_ui().await
            })
        );
    } else {
        println!("Starting in headless mode...");
        println!("Use --ui or -u flag to start with terminal interface");
        
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
        
        tokio::try_join!(
            tokio::spawn(broadcast::start_broadcast_announcer(
                DEFAULT_LISTENING_PORT,
                local_ip
            )),
            tokio::spawn(broadcast::start_listener()),
            tokio::spawn(async move { start_server(default_server).await }),
            tokio::spawn(async move { device_manager_arc_for_join.start().await }),
            tokio::spawn(cleanup()),
            known_devices_printer_handle
        );
    }

    Ok(())
}
