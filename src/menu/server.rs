use crate::broadcast::DiscoveredDevice;
use crate::challenge::DefaultChallengeManager;
use crate::client::DefaultClientManager;
use crate::consts::{CommonThreadError, DeviceId, DEFAULT_LISTENING_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::server::generate_root_ca;
use crate::machine_utils::get_local_ip;
use crate::menu::{read_user_input, Action, Step};
use crate::server::DefaultServer;
use crate::state::InternalState;
use crate::{broadcast, challenge, client, server, JoinsChannel};
use log::info;
use std::collections::{HashMap, LinkedList};
use std::net::IpAddr;
use std::sync::Arc;
use std::thread;
use tokio::runtime::{Handle, Runtime};
use tokio::sync::oneshot::channel;
use tokio::task::{spawn_blocking, JoinHandle};

type DStep = Box<dyn Step + Send + Sync>;
pub struct ServerAction {
    current_step: Option<DStep>,
    steps: LinkedList<DStep>,
}

impl Default for ServerAction {
    fn default() -> Self {
        let steps: LinkedList<DStep> = LinkedList::from([
            Box::new(StartServerStep {}) as DStep,
            Box::new(ListKnownDevices {}) as DStep,
        ]);

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

    fn render(&self) {
        println!("Network management");
    }

    fn act(&self) -> Box<dyn Fn() -> Result<bool, CommonThreadError> + Send + Sync> {
        Box::new(|| {
            let steps: Vec<DStep> =
                vec![Box::new(StartServerStep {}), Box::new(ListKnownDevices {})];

            println!("Select option:");
            for (id, x) in steps.iter().enumerate() {
                println!("\t{} {}", id, x.display());
            }

            match read_user_input() {
                Ok(val) => match val.parse::<usize>() {
                    Ok(n) if n < steps.len() => steps[n].action(),
                    _ => {
                        println!("Unknown option");
                        Ok(false)
                    }
                },
                Err(_) => {
                    println!("Cannot read user input");
                    Ok(false)
                }
            }
        })
    }
}

struct StartServerStep {}
impl Step for StartServerStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let device_manager_arc = Arc::clone(&DefaultDeviceManager);
        let default_server = Arc::clone(&DefaultServer);
        let device_manager_arc_for_join = device_manager_arc.clone();

        let net_addr = initialize();

        let challenge_manager = DefaultChallengeManager.clone();
        let client_manager = DefaultClientManager.clone();

        let handle = tokio::spawn(async move {
            tokio::spawn(broadcast::start_broadcast_announcer(
                DEFAULT_LISTENING_PORT,
                net_addr,
            ));
            tokio::spawn(broadcast::start_listener());
            tokio::spawn(async move { server::run(default_server.clone()).await });
            tokio::spawn(async move { challenge::run(challenge_manager.clone()).await });
            tokio::spawn(async move { client::run(client_manager.clone()).await });
            tokio::spawn(async move { device_manager_arc_for_join.start().await });
        });

        JoinsChannel.0.clone().send(handle)?;
        Ok(true)
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
    fn action(&self) -> Result<bool, CommonThreadError> {
        let device_manager = Arc::clone(&DefaultDeviceManager);
        let (tx, mut rx) = channel::<HashMap<String, DiscoveredDevice>>();

         spawn_blocking(async move || {
            let devices = {
                let mtx = device_manager.known_devices.read().await;
                mtx.clone()
            };
            tx.send(devices)
                .expect("Cannot send known devices");
        });
        let known_devices = rx.try_recv().unwrap_or_default();

        println!("\n--- Known Devices ({} total) ---", known_devices.len());
        for (id, device) in known_devices.iter() {
            println!(
                "  ID: {}, Addr: {}, Last Seen: {:?}",
                id, device.connect_addr, device.last_seen
            );
        }
        println!("---------------------------------\n");

        Ok(false)
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
