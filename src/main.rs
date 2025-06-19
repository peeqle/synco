use lazy_static::lazy_static;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::connection::ChallengeManager;
use crate::device_manager::DeviceManager;
use crate::keychain::clear_keys;
use local_ip_address::list_afinet_netifas;
use tokio::time::sleep;

mod balancer;
mod broadcast;
mod connection;
mod device_manager;
mod diff;
mod keychain;
mod server;

type NetError = Box<dyn Error + Send + Sync>;

lazy_static! {
    pub static ref DEVICE_MANAGER: Arc<DeviceManager> = {
        let (found_devices_tx, discovery_rx) = mpsc::channel::<(String, SocketAddr)>(100);
        Arc::new(DeviceManager::new(discovery_rx, found_devices_tx))
    };
}

#[tokio::main]
async fn main() -> Result<(), NetError> {
    color_eyre::install()?;
    
    // clear_keys().unwrap();
    let device_id = keychain::device_id().unwrap_or_else(|| Uuid::new_v4().to_string());

    let my_listening_port: u16 = 22000;
    let local_ip = get_local_ip().expect("Could not determine local IP address");

    println!("My Device ID: {}", device_id);
    println!("My Listening Port: {}", my_listening_port);
    println!("My Local IP: {}", local_ip);

    let (found_devices_tx, discovery_rx) = mpsc::channel::<(String, SocketAddr)>(100);
    let device_manager = DeviceManager::new(discovery_rx, found_devices_tx);
    let known_devices = device_manager.get_known_devices();

    let device_manager_arc = Arc::new(tokio::sync::Mutex::new(device_manager));

    let manager_handle_arc_clone = Arc::clone(&device_manager_arc);
    let manager_handle = tokio::spawn(async move {
        if let Err(e) = manager_handle_arc_clone.lock().await.run().await {
            eprintln!("Device Manager error: {}", e);
        }
    });

    let (challenge_sender, challenge_receiver) = mpsc::channel::<(String, SocketAddr)>(100);
    let mut challenge_manager = ChallengeManager::new(challenge_receiver);

    let challenge_manager_handle = tokio::spawn(async move { challenge_manager.run().await });

    let listener_device_manager_arc_clone = Arc::clone(&device_manager_arc);
    let listener_handle = tokio::spawn(broadcast::start_listener(
        listener_device_manager_arc_clone,
        device_id.clone(),
        challenge_sender.clone(),
    ));

    let announcer_handle = tokio::spawn(broadcast::start_broadcast_announcer(
        device_id.clone(),
        my_listening_port,
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

    match tokio::try_join!(
        listener_handle,
        announcer_handle,
        manager_handle,
        challenge_manager_handle
    ) {
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(())
}

fn get_local_ip() -> Option<IpAddr> {
    let ifas = list_afinet_netifas().unwrap();

    if let Some((_, ipaddr)) = ifas
        .iter()
        .find(|(name, ipaddr)| (*name).contains("wlp") && matches!(ipaddr, IpAddr::V4(_)))
    {
        println!("Using current device WLP address: {:?}", ipaddr);
        return Some(*ipaddr);
    }

    Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
}
