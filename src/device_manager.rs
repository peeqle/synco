use std::collections::hash_map::Entry;
use crate::broadcast::DiscoveredDevice;
use lazy_static::lazy_static;
use log::info;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Condvar};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{sleep, Instant};

lazy_static! {
    pub static ref DefaultDeviceManager: Arc<DeviceManager> = {
        Arc::new(DeviceManager {
            notify: Arc::new(Notify::new()),
            known_devices: RwLock::new(HashMap::new())
        })
    };
}

pub struct DeviceManager {
    pub known_devices: RwLock<HashMap<String, DiscoveredDevice>>,
    pub notify: Arc<Notify>,
}

const CLEANUP_DELAY: u64 = 15;
const MAX_DEAD: u64 = 60 * 5;

impl DeviceManager {
    pub async fn start(&self) {
        tokio::spawn(cleanup());
    }
    pub fn get_known_devices(&self) -> Arc<&RwLock<HashMap<String, DiscoveredDevice>>> {
        Arc::new(&self.known_devices)
    }
}

pub async fn add_new_device(device_id: String, socket_addr: SocketAddr) {
    let device_manager_arc = Arc::clone(&DefaultDeviceManager);

    let known_devices = &device_manager_arc.known_devices;
    let new_device = DiscoveredDevice::new(device_id.clone(), socket_addr);

    let mut devices = known_devices.write().await;
    let mut conflicting_id: Option<String> = None;
    for (id, device) in devices.iter() {
        if id != &device_id && device.connect_addr.eq(&new_device.connect_addr) {
            conflicting_id = Some(id.clone());
            break;
        }
    }
    if let Some(conflict) = conflicting_id {
        devices.remove(&conflict);
        devices.insert(device_id, new_device);
    } else {
        match devices.entry(device_id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().update_last_seen();
                println!("Device Manager: Updated last seen for device {}", entry.key());
                // self.device_updates_tx.send(DeviceUpdate::Updated(entry.get().clone())).await.ok();
            }
            Entry::Vacant(void) => {
                println!("Device Manager: Discovered new device: {:?}", new_device);
                void.insert(new_device.clone());
                // self.device_updates_tx.send(DeviceUpdate::Added(new_device)).await.ok();

            }
        }
    }
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

pub async fn get_device(device_id: &String) -> Option<DiscoveredDevice> {
    let device_manager = Arc::new(&DefaultDeviceManager);
    device_manager.known_devices.read().await.get(device_id).cloned()
}

pub async fn get_device_by_socket(socket_addr: &SocketAddr) -> Option<DiscoveredDevice> {
    let manager = Arc::clone(&DefaultDeviceManager);
    let devices = manager.known_devices.read().await;
    match devices.iter().find(|(_key, d)| d.connect_addr.ip() == socket_addr.ip()) {
        Some((_key, device)) => Some(device.clone()),
        None => None,
    }
}
