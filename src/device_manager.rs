use crate::broadcast::{DiscoveredDevice, SharedKnownDevices};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Mutex, oneshot};
use tokio::time::{Instant, sleep};

pub struct DeviceManager {
    known_devices: SharedKnownDevices,
    rx: Receiver<DeviceManagerQuery>,
}
pub enum DeviceManagerQuery {
    KnownDevices {
        response: oneshot::Sender<HashMap<String, DiscoveredDevice>>,
    },
    /**
    Add new or update existing
    */
    DiscoveredDevice {
        device_id: String,
        socket_addr: SocketAddr,
    },
}

pub async fn query_known_devices(
    device_manager_tx: &Sender<DeviceManagerQuery>,
) -> HashMap<String, DiscoveredDevice> {
    let (response_tx, response_rx) = oneshot::channel();
    let msg = DeviceManagerQuery::KnownDevices {
        response: response_tx,
    };

    if device_manager_tx.send(msg).await.is_ok() {
        if let Ok(devices) = response_rx.await {
            return devices;
        }
    }
    HashMap::new()
}

const CLEANUP_DELAY: u64 = 15;
const MAX_DEAD: u64 = 60 * 5;

impl DeviceManager {
    pub fn new(rx: Receiver<DeviceManagerQuery>) -> Self {
        DeviceManager {
            known_devices: Arc::new(Mutex::new(HashMap::new())),
            rx,
        }
    }

    pub fn get_known_devices(&self) -> SharedKnownDevices {
        Arc::clone(&self.known_devices)
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let cleanup_handle = {
            let known_devices_arc_for_cleanup = Arc::clone(&self.known_devices);
            tokio::spawn(async move {
                Self::cleanup(known_devices_arc_for_cleanup).await;
            })
        };

        loop {
            tokio::select! {
                Some(message) = self.rx.recv() => {
                    match message {
                DeviceManagerQuery::KnownDevices { response } => {
                    let device_ids = self.known_devices.lock().await.clone();
                    let _ = response.send(device_ids);
                },
                DeviceManagerQuery::DiscoveredDevice { device_id, socket_addr } => {
                            let current_devices = self.get_known_devices();
                            let new_device = DiscoveredDevice::new(device_id.clone(), socket_addr);

                    match current_devices.clone().lock().await.entry(device_id) {
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
        cleanup_handle.await.ok();
        Ok(())
    }

    async fn cleanup(_devices: SharedKnownDevices) {
        println!("Device cleaner has started");
        loop {
            sleep(Duration::from_secs(CLEANUP_DELAY)).await;

            let mut devices = _devices.lock().await;
            let now = Instant::now();
            devices.retain(|id, device| {
                if now.duration_since(device.last_seen).as_secs() > MAX_DEAD {
                    println!("Removing device {} ", id);
                    return false;
                }
                true
            })
        }
    }
}
