use std::error::Error;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

use crate::connection::DefaultChallengeManager;
use crate::consts::{DEFAULT_LISTENING_PORT, DeviceId};
use crate::device_manager::{DeviceManager, DeviceManagerQuery};
use crate::machine_utils::get_local_ip;
use crate::server::DefaultServer;
use crate::state::InternalState;
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
    let internal_state = InternalState::new().with_passphrase("bonkers".to_string());

    let local_ip = get_local_ip().expect("Could not determine local IP address");

    println!("My Device ID: {}", &DeviceId[..]);
    println!("My Listening Port: {}", DEFAULT_LISTENING_PORT);
    println!("My Local IP: {}", local_ip);

    let (dv_sd, dv_rc) = mpsc::channel::<DeviceManagerQuery>(100);

    let device_manager = DeviceManager::new(dv_rc);
    let known_devices = device_manager.get_known_devices();

    let device_manager_arc = Arc::new(Mutex::new(device_manager));

    let manager_handle_arc_clone = Arc::clone(&device_manager_arc);
    let manager_handle = tokio::spawn(async move {
        if let Err(e) = manager_handle_arc_clone.lock().await.run().await {
            eprintln!("Device Manager error: {}", e);
        }
    });

    let mut challenge_manager = Arc::clone(&DefaultChallengeManager);

    let challenge_manager_handle = tokio::spawn(async move { challenge_manager.run().await });

    let announcer_handle = tokio::spawn(broadcast::start_broadcast_announcer(
        DEFAULT_LISTENING_PORT,
        local_ip,
    ));

    tokio::spawn(async move {
        loop {
            let devices = known_devices.lock().await;
            println!("\n--- Known Devices ({} total) ---", devices.len());
            for (id, device) in devices.iter() {
                println!(
                    "  ID: {}, Addr: {}, Last Seen: {:?}",
                    id, device.connect_addr, device.last_seen
                );
            }
            println!("---------------------------------\n");
            sleep(Duration::from_secs(15)).await;
        }
    });

    let default_server = Arc::clone(&DefaultServer);
    tokio::spawn(async move { default_server.start().await });

    tokio::try_join!(
        tokio::spawn(broadcast::start_listener(dv_sd)),
        announcer_handle,
        manager_handle,
        challenge_manager_handle,
    );

    Ok(())
}
