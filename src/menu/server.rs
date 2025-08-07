use crate::challenge::DefaultChallengeManager;
use crate::client::DefaultClientManager;
use crate::consts::{CommonThreadError, DeviceId, DEFAULT_LISTENING_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::diff::{attach, Files};
use crate::keychain::server::generate_root_ca;
use crate::machine_utils::get_local_ip;
use crate::menu::{Action, Step};
use crate::server::DefaultServer;
use crate::state::InternalState;
use crate::{broadcast, challenge, client, server};
use log::{error, info};
use std::collections::LinkedList;
use std::io;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::time::sleep;

type DStep = Box<dyn Step + Send + Sync>;
pub struct ServerAction {
    current_step: Option<DStep>,
    steps: LinkedList<DStep>,
}

impl Default for ServerAction {
    fn default() -> Self {
        let start_server_step = Box::new(StartServerStep {}) as DStep;
        let steps: LinkedList<DStep> = LinkedList::from([start_server_step]);

        ServerAction {
            current_step: None,
            steps,
        }
    }
}

impl Action for ServerAction {
    fn id(&self) -> String {
        "server_action".to_string()
    }

    fn act(&self) -> Box<dyn Fn() -> Result<(), CommonThreadError> + Send + Sync> {
        Box::new(|| {
            let start_step = StartServerStep {};
            start_step.action()
        })
    }

    fn render(&self) {
        println!("Network management");
    }
}


struct StartServerStep {}
impl Step for StartServerStep {
    fn action(&self) -> Result<(), CommonThreadError> {
        let device_manager_arc = Arc::clone(&DefaultDeviceManager);
        let default_server = Arc::clone(&DefaultServer);
        let device_manager_arc_for_join = device_manager_arc.clone();

        let net_addr = initialize();

        let challenge_manager = DefaultChallengeManager.clone();
        let client_manager = DefaultClientManager.clone();

        let rt = Runtime::new().expect("Failed to create Tokio runtime");

        rt.spawn(async move {
            let _ = tokio::join!(
                tokio::spawn(broadcast::start_broadcast_announcer(
                    DEFAULT_LISTENING_PORT,
                    net_addr
                )),
                tokio::spawn(broadcast::start_listener()),
                tokio::spawn(async move { server::run(default_server.clone()).await }),
                tokio::spawn(async move { challenge::run(challenge_manager.clone()).await }),
                tokio::spawn(async move { client::run(client_manager.clone()).await }),
                tokio::spawn(async move { device_manager_arc_for_join.start().await })
            );
        });

        Ok(())
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn render(&self) {
        println!("Start server");
    }

    fn display(&self) -> &str {
        "Start server"
    }
}

struct ListKnownDevices {}
impl Step for ListKnownDevices {
    fn action(&self) -> Result<(), CommonThreadError> {
        let device_manager = Arc::clone(&DefaultDeviceManager);
        let known_devices = {
            let rt = Runtime::new().expect("Failed to create Tokio runtime");
            rt.block_on(device_manager.known_devices.read()).clone()
        };

        println!("\n--- Known Devices ({} total) ---", known_devices.len());
        for (id, device) in known_devices.iter() {
            println!(
                "  ID: {}, Addr: {}, Last Seen: {:?}",
                id, device.connect_addr, device.last_seen
            );
        }
        println!("---------------------------------\n");

        Ok(())
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn render(&self) {
        println!("List known devices");
    }

    fn display(&self) -> &str {
        "List known devices"
    }
}

fn initialize() -> IpAddr {
    let internal_state = InternalState::new().with_passphrase("bonkers".to_string());

    let local_ip = get_local_ip().expect("Could not determine local IP address");

    info!("Device ID: {}", &DeviceId[..]);
    info!("Listening Port: {}", DEFAULT_LISTENING_PORT);
    info!("Local IP: {}", local_ip);

    generate_root_ca().expect("Cannot generate CA");
    local_ip
}