use crate::keychain::device_id;
use der::asn1::ObjectIdentifier;
use lazy_static::lazy_static;
use std::error::Error;
use uuid::Uuid;

lazy_static! {
    pub static ref DeviceId: String = device_id()
        .unwrap_or_else(|| Uuid::new_v4().to_string())
        .to_string();
}

pub const DEFAULT_APP_SUBDIR: &str = "synco";
pub const DEFAULT_TEST_SUBDIR: &str = "test";

pub const DEFAULT_CLIENT_CERT_STORAGE: &str = "client";
pub const DEFAULT_SERVER_CERT_STORAGE: &str = "server";
pub const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
pub const CERT_FILE_NAME: &str = "cert.pem";
pub const CA_CERT_FILE_NAME: &str = "ca.crt";
pub const CA_KEY_FILE_NAME: &str = "ca.key";
pub const SIGNING_KEY: &str = "signing_key.bin";

pub const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

pub const DEFAULT_SERVER_PORT: u16 = 21029;
pub const DEFAULT_LISTENING_PORT: u16 = 22001;

pub const BUFFER_SIZE: usize = 16 * 1024;

pub const CLEANUP_DELAY: u64 = 15;
pub const CHALLENGE_DEATH: u64 = 60;

pub type DAError = Box<dyn Error + Send + Sync>;