use crate::broadcast::DiscoveredDevice;
use crate::challenge::{ChallengeManager, DefaultChallengeManager, DeviceChallengeStatus};
use crate::client::{get_client_sender, DefaultClientManager};
use crate::consts::data::get_device_id;
use crate::consts::{CommonThreadError, DEFAULT_LISTENING_PORT};
use crate::device_manager::DefaultDeviceManager;
use crate::keychain::server::generate_root_ca;
use crate::machine_utils::get_local_ip;
use crate::menu::{read_user_input, Action, Step};
use crate::server::data::get_default_server;
use crate::server::model::ServerRequest;
use crate::utils::encrypt_with_passphrase;
use crate::{broadcast, challenge, client, get_handle, menu_step, server, JoinsChannel};
use ::futures::executor;
use lazy_static::lazy_static;
use log::{error, info};
use std::collections::{HashMap, LinkedList};
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use tokio::sync::oneshot::{self, channel};
use tokio::task;
use tokio::task::spawn_blocking;

//todo future me create logic for handling runner state
// from the handlers to menu components state via global ?state machine?
type DStep = Box<dyn Step + Send + Sync>;
lazy_static! {
    static ref ActionSteps: Arc<LinkedList<DStep>> = Arc::new(LinkedList::from([
        Box::new(StartDefaultStep {}) as DStep,
        Box::new(StartServerStep::default()) as DStep,
        Box::new(StartClientManagerStep::default()) as DStep,
        Box::new(ListKnownDevices {}) as DStep,
        Box::new(StartBroadcastStep::default()) as DStep,
        Box::new(ListChallenges {}) as DStep,
        Box::new(CompleteChallenge {}) as DStep,
    ]));
}

pub struct ServerAction {
    current_step: Option<DStep>,
    steps: Arc<LinkedList<DStep>>,
}

impl Default for ServerAction {
    fn default() -> Self {
        ServerAction {
            current_step: None,
            steps: ActionSteps.clone(),
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
        let steps = self.steps.clone();
        Box::new(move || {
            println!("Select option:");
            for (id, x) in steps.iter().enumerate() {
                println!("\t{} {}", id, x.display());
            }

            match read_user_input() {
                Ok(val) => match val.parse::<usize>() {
                    Ok(n) if n < steps.len() => steps.iter().nth(n).unwrap().action(),
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

struct StartDefaultStep {}
impl Step for StartDefaultStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        StartBroadcastStep::default().action()?;
        StartServerStep::default().action()?;
        StartClientManagerStep::default().action()?;

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        println!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Start default(Broadcast, Server, Client)"
    }
}

menu_step!(StartBroadcastStep);
impl Step for StartBroadcastStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        if self.invoked.load(SeqCst) {
            info!("Broadcast working already ...");
            return Ok(false);
        }

        get_handle().spawn(async {
            let net_addr = initialize().await;

            let device_manager_arc = Arc::clone(&DefaultDeviceManager);
            let challenge_manager = Arc::clone(&DefaultChallengeManager);

            let handle = tokio::spawn(async move {
                tokio::spawn(broadcast::start_broadcast_announcer(
                    DEFAULT_LISTENING_PORT,
                    net_addr,
                ));
                tokio::spawn(broadcast::start_listener());
                tokio::spawn(async move { device_manager_arc.start().await });
                tokio::spawn(async move { challenge::run(challenge_manager.clone()).await });
            });

            JoinsChannel.0.clone().send(handle).expect("Cannot send");
        });

        self.invoked.store(true, SeqCst);

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        println!("{}", self.display())
    }

    fn display(&self) -> &str {
        "Allow other devices discovery"
    }
}

menu_step!(StartServerStep);
impl Step for StartServerStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        if self.invoked.load(SeqCst) {
            info!("Server working already ...");
            return Ok(false);
        }
        get_handle().spawn(async {
            let default_server = get_default_server().await;

            //гыгы thread делает скидыщ - todo
            let handle = tokio::spawn(async move {
                tokio::spawn(async move { server::run(default_server.clone()).await });
            });
            JoinsChannel.0.clone().send(handle).expect("Cannot send");
        });

        self.invoked.store(true, SeqCst);

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        println!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Start server"
    }
}

menu_step!(StartClientManagerStep);
impl Step for StartClientManagerStep {
    fn action(&self) -> Result<bool, CommonThreadError> {
        if self.invoked.load(SeqCst) {
            info!("Client manager working already ...");
            return Ok(false);
        }
        info!("Starting client manager...");

        get_handle().spawn(async {
            let client_manager = Arc::clone(&DefaultClientManager);
            let handle = tokio::spawn(async move { client::run(client_manager.clone()).await });

            JoinsChannel.0.clone().send(handle).expect("Cannot send");
        });

        self.invoked.store(true, SeqCst);

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        self.invoked.load(SeqCst)
    }

    fn render(&self) {
        println!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Enable client mode"
    }
}

struct ListKnownDevices {}
impl Step for ListKnownDevices {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let device_manager = Arc::clone(&DefaultDeviceManager);

        let devices_future = task::spawn_blocking(move || {
            get_handle().block_on(async {
                let mtx = device_manager.known_devices.read().await;
                mtx.clone()
            })
        });
        let devices = futures::executor::block_on(devices_future).expect("");

        println!("\n--- Known Devices ({} total) ---", devices.len());
        for (id, device) in devices.iter() {
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

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        println!("List known devices");
    }

    fn display(&self) -> &str {
        "List known devices"
    }
}

struct ListChallenges {}
impl Step for ListChallenges {
    fn action(&self) -> Result<bool, CommonThreadError> {
        let future = get_handle().spawn_blocking(move || {
            get_handle().block_on(async {
                let challenge_manager = Arc::clone(&DefaultChallengeManager);
                (
                    challenge_manager.current_challenges.read().await.clone(),
                    challenge_manager.challenges.read().await.clone(),
                )
            })
        });
        let (current_challenges, challeneges) = futures::executor::block_on(future).expect("Cannot block");

        if current_challenges.is_empty() {
            println!("----------------------------------");
            println!("No challenges");
            println!("----------------------------------");
        } else {
            println!("IDX\t|\t\tDEV_ID\t\t\t\tSOCKET\t\tATTEMPTS\t\tSTATUS");
            for (id, (i, ch)) in current_challenges.iter().enumerate() {
                match ch {
                    DeviceChallengeStatus::Closed { socket_addr } => {
                        println!(
                            "{}\t|\t\t{}\t\t{}\t\t{}\t\t{}",
                            id,
                            i,
                            socket_addr.ip().to_string(),
                            "-",
                            ch.name()
                        );
                    }
                    DeviceChallengeStatus::Pending { socket_addr, nonce } => {
                        println!(
                            "{}\t|\t\t{}\t\t{}\t\t{}\t\t{}",
                            id,
                            i,
                            socket_addr.ip().to_string(),
                            "-",
                            ch.name()
                        );
                    }
                    _ => {}
                }
            }
        }

        println!("Incoming requests challenges\n");
        if challeneges.is_empty() {
            println!("----------------------------------");
            println!("No challenges");
            println!("----------------------------------");
        } else {
            println!("IDX\t|\t\tDEV_ID\t\t\t\tSOCKET\t\tATTEMPTS\t\tSTATUS");
            for (id, (i, ch)) in challeneges.iter().enumerate() {
                match ch {
                    DeviceChallengeStatus::Active {
                        socket_addr,
                        nonce,
                        nonce_hash,
                        salt,
                        passphrase,
                        attempts,
                        ttl,
                    } => {
                        println!(
                            "{}\t|\t\t{}\t\t{}\t\t{}\t\t{}",
                            id,
                            i,
                            socket_addr.ip().to_string(),
                            attempts,
                            ch.name()
                        );
                    }
                    DeviceChallengeStatus::Closed { socket_addr } => {
                        println!(
                            "{}\t|\t\t{}\t\t{}\t\t{}\t\t{}",
                            id,
                            i,
                            socket_addr.ip().to_string(),
                            "-",
                            ch.name()
                        );
                    }
                    _ => {}
                }
            }
        }

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        println!("{}", self.display());
    }

    fn display(&self) -> &str {
        "List requested server challenges"
    }
}

struct CompleteChallenge {}
impl Step for CompleteChallenge {
    fn action(&self) -> Result<bool, CommonThreadError> {
        ListChallenges {}.action()?;

        let futures = task::spawn_blocking(|| {
            get_handle().block_on(async {
                let challenges = {
                    let challenge_manager = Arc::clone(&DefaultChallengeManager);
                    challenge_manager.current_challenges.read().await.clone()
                };

                challenges
            })
        });

        let challenges = futures::executor::block_on(futures).expect("");

        if !challenges.is_empty() {
            println!("Select option:");
            match read_user_input() {
                Ok(val) => match val.parse::<usize>() {
                    Ok(n) => {
                        let (device_id, challenge) = challenges
                            .into_iter()
                            .nth(n)
                            .expect(&format!("Cannot find entry at {}", n));

                        match challenge {
                            DeviceChallengeStatus::Pending { nonce, .. } => {
                                println!("Enter passphrase: ");
                                let passphrase =
                                    read_user_input().expect("Cannot read provided bytes");

                                let (ciphertext_with_tag, iv_bytes, salt) =
                                    encrypt_with_passphrase(&*nonce, passphrase.as_bytes())
                                        .expect("Cannot encrypt");

                                let futures = spawn_blocking(move || {
                                    get_handle().block_on(async {
                                        if let Some(_sender) = get_client_sender(&device_id).await {
                                            _sender
                                                .send(ServerRequest::ChallengeResponse {
                                                    iv_bytes,
                                                    salt,
                                                    ciphertext_with_tag,
                                                })
                                                .await
                                                .expect("Cannot send passphrase verification");
                                        } else {
                                            error!("Cannot send solution to the server");
                                        }
                                        //todo make connection rollback if not persist
                                    })
                                });

                                futures::executor::block_on(futures).expect("Cannot finish task");
                            }
                            _ => {
                                println!("Cannot activate that channel");
                            }
                        }
                    }
                    _ => {
                        println!("Unknown option");
                    }
                },
                Err(_) => {
                    println!("Cannot read user input");
                }
            }
        }

        Ok(false)
    }

    fn next_step(&self) -> Option<Box<dyn Step + Send + Sync>> {
        None
    }

    fn invoked(&self) -> bool {
        false
    }

    fn render(&self) {
        println!("{}", self.display());
    }

    fn display(&self) -> &str {
        "Complete selected server challenge"
    }
}

async fn initialize() -> IpAddr {
    let local_ip = get_local_ip().expect("Could not determine local IP address");

    info!("Device ID: {}", &get_device_id().await[..]);
    info!("Listening Port: {}", DEFAULT_LISTENING_PORT);
    info!("Local IP: {}", local_ip);

    generate_root_ca().expect("Cannot generate CA");
    local_ip
}
