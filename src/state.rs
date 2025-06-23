use crate::keychain::device_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct InternalState {
    device_id: String,
    is_connection_pool_opened: bool,
    passphrase: Option<String>,
}

impl InternalState {
    pub fn new() -> Self {
        let current_device_id = device_id();
        if let None = current_device_id {
            panic!("Cannot extract device id from the key, try run with [regenerate]");
        }
        InternalState {
            device_id: current_device_id.unwrap(),
            is_connection_pool_opened: false,
            passphrase: None,
        }
    }
    pub fn with_connection_pool_opened(mut self, val: bool) -> Self {
        self.is_connection_pool_opened = val;
        self
    }

    pub fn with_passphrase(mut self, passphrase: String) -> Self {
        self.passphrase = Some(passphrase.clone());
        self.is_connection_pool_opened = false;
        self
    }
}
