use std::fs::File;
use std::io::BufReader;
use log::info;
use crate::{consts::CommonThreadError, utils::get_main_config_file};
use serde::{Deserialize, Serialize};
use tokio::sync::OnceCell;
use crate::consts::BROADCAST_INTERVAL_SECONDS;

static LOADED_CONFIGURATION: OnceCell<Configuration> = OnceCell::const_new();

pub fn load_configuration() {
    if let Ok(c_file) = get_main_config_file() {
        let reader = BufReader::new(c_file);
        if let Ok(configuration) = serde_yaml::from_reader::<BufReader<File>, Configuration>(reader) {
            LOADED_CONFIGURATION.set(configuration).expect("Cannot set configuration property");
        }else {
            load_default_configuration();
        }

    }
}

fn load_default_configuration() {
    info!("Loading default configuration");
    LOADED_CONFIGURATION.set(Configuration {
        autoconnect_all: Some(true),
        broadcast_delay_sec: Some(BROADCAST_INTERVAL_SECONDS)
    });
}

fn populate_configuration_files() {}

fn store_configuration() {}

#[derive(Deserialize, Serialize, Debug)]
struct Configuration {
    autoconnect_all: Option<bool>,

    broadcast_delay_sec: Option<u64>,
}
