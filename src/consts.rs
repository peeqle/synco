use crate::utils::device_id;
use der::asn1::ObjectIdentifier;
use lazy_static::lazy_static;
use std::error::Error;
use std::io;
use std::io::ErrorKind;

lazy_static! {
    pub static ref DeviceId: String = device_id()
        .expect("Cannot create device id, try again")
        .to_string();
}

pub type CommonThreadError = Box<dyn Error + Send + Sync>;

pub fn of_type(text: &str, error_kind: ErrorKind) -> Box<io::Error> {
    Box::new(io::Error::new(error_kind, text))
}

pub const DEFAULT_APP_SUBDIR: &str = "synco";
pub const DEFAULT_FILES_SUBDIR: &str = "files";
pub const DEFAULT_TEST_SUBDIR: &str = "test";

pub const DEFAULT_CLIENT_CERT_STORAGE: &str = "client";
pub const DEFAULT_SERVER_CERT_STORAGE: &str = "server";
pub const LEAF_CERT_NAME: &str = "leaf.pem";
pub const LEAF_KEYS_NAME: &str = "leaf.key";

pub const PRIVATE_KEY_FILE_NAME: &str = "key.pem";
pub const CERT_FILE_NAME: &str = "cert.pem";
pub const CA_CERT_FILE_NAME: &str = "ca.crt";
pub const CA_KEY_FILE_NAME: &str = "ca.key";
pub const SIGNING_KEY: &str = "signing_key.bin";

pub const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

pub const DISCOVERY_PORT: u16 = 21028;
pub const DEFAULT_SERVER_PORT: u16 = 21029;
pub const DEFAULT_SIGNING_SERVER_PORT: u16 = 21030;
pub const DEFAULT_LISTENING_PORT: u16 = 22001;

pub const BUFFER_SIZE: usize = 16 * 1024;

pub const CLEANUP_DELAY: u64 = 5;
pub const CHALLENGE_DEATH: u64 = 160;
pub const BROADCAST_INTERVAL_SECONDS: u64 = 2;
