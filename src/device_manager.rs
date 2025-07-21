use crate::broadcast::DiscoveredDevice;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use log::info;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::time::{Instant, sleep};

lazy_static! {
    pub static ref DefaultDeviceManager: Arc<DeviceManager> = {
        let (sender, receiver) = mpsc::channel(300);
        Arc::new(DeviceManager {
            known_devices: RwLock::new(HashMap::new()),
            bounded_channel: (sender, Mutex::new(receiver)),
        })
    };
}

pub struct DeviceManager {
    //id
    pub(crate) known_devices: RwLock<HashMap<String, DiscoveredDevice>>,
    pub(crate) bounded_channel: (
        Sender<DeviceManagerQuery>,
        Mutex<Receiver<DeviceManagerQuery>>,
    ),
}
pub enum DeviceManagerQuery {
    /**
    Add new or update existing
    */
    DiscoveredDevice {
        device_id: String,
        socket_addr: SocketAddr,
    },
}

const CLEANUP_DELAY: u64 = 15;
const MAX_DEAD: u64 = 60 * 5;

impl DeviceManager {
    pub async fn start(&self) {
        tokio::try_join!(tokio::spawn(cleanup()), tokio::spawn(run()));
    }
    pub fn get_known_devices(&self) -> Arc<&RwLock<HashMap<String, DiscoveredDevice>>> {
        Arc::new(&self.known_devices)
    }

    pub fn get_channel_sender(&self) -> Sender<DeviceManagerQuery> {
        self.bounded_channel.0.clone()
    }
}

pub async fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let device_manager_arc = Arc::clone(&DefaultDeviceManager);

    let receiver_mutex = &device_manager_arc.bounded_channel.1;
    let known_devices = &device_manager_arc.known_devices;
    loop {
        let mut r = receiver_mutex.lock().await;
        tokio::select! {
            Some(message) = r.recv() => {
                match message {
            DeviceManagerQuery::DiscoveredDevice { device_id, socket_addr } => {

                        let new_device = DiscoveredDevice::new(device_id.clone(), socket_addr);

                         let mut devices = known_devices.write().await;
                match devices.entry(device_id) {
                    std::collections::hash_map::Entry::Occupied(mut entry) => {
                        entry.get_mut().update_last_seen();
                        println!("Device Manager: Updated last seen for device {}", entry.key());
                        // self.device_updates_tx.send(DeviceUpdate::Updated(entry.get().clone())).await.ok();
                    }
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        println!("Device Manager: Discovered new device: {:?}", new_device);
                        entry.insert(new_device.clone());
                        // self.device_updates_tx.send(DeviceUpdate::Added(new_device)).await.ok();

                                }
                            }
                        }
                }
            }
            else => break
        }
    }

    Ok(())
}

pub async fn cleanup() {
    info!("Device cleaner has started");
    let device_manager = Arc::clone(&DefaultDeviceManager);
    loop {
        sleep(Duration::from_secs(CLEANUP_DELAY)).await;

        let mut devices = device_manager.known_devices.write().await;
        let now = Instant::now();
        devices.retain(|id, device| {
            if now.duration_since(device.last_seen).as_secs() > MAX_DEAD {
                info!("Removing device {} ", id);
                return false;
            }
            true
        })
    }
}

pub async fn get_device(device_id: String) -> Option<DiscoveredDevice> {
    let device_manager = Arc::new(&DefaultDeviceManager);
    match device_manager.known_devices.read().await.get(&device_id) {
        None => None,
        Some(dv) => Some(dv.clone()),
    }
}
