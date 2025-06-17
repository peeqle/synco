use crate::broadcast::{DiscoveredDevice, SharedKnownDevices};
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{Instant, sleep};

pub struct DeviceManager {
    known_devices: SharedKnownDevices,
    discovery_rx: Receiver<(String, SocketAddr)>,
    pub(crate) discovery_tx: Sender<(String, SocketAddr)>,
}

const CLEANUP_DELAY: u64 = 15;
const MAX_DEAD: u64 = 60 * 5;

impl DeviceManager {
    pub fn new(
        discovery_rx: Receiver<(String, SocketAddr)>,
        discovery_tx: Sender<(String, SocketAddr)>,
    ) -> Self {
        DeviceManager {
            known_devices: Arc::new(Mutex::new(HashMap::new())),
            discovery_rx,
            discovery_tx,
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
                Some((device_id, connect_addr)) = self.discovery_rx.recv() => {
                    println!("RECEIVED {}", device_id);
                    let mut devices = self.known_devices.lock().await;
                    let new_device = DiscoveredDevice::new(device_id.clone(), connect_addr);

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
                else => break,
            }
        }
        cleanup_handle.await.ok();
        Ok(())
    }

    async fn cleanup(_devices: SharedKnownDevices) {
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
