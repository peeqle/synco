use der::asn1::ObjectIdentifier;

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
