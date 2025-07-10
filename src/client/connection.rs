use crate::device_manager::DefaultDeviceManager;
use log::error;
use std::sync::Arc;

pub async fn connect(device_id: String) {
    let discovered_devices_arc = Arc::clone(&DefaultDeviceManager);

    {
        let known_devices = discovered_devices_arc
            .known_devices
            .read()
            .expect("Cannot read known_devices");

        match known_devices.get(&device_id) {
            None => {
                error!("Cannot find device specified for connection: {}", device_id);
            }
            Some(device) => {
                //try open session
            }
        }
    }
}
