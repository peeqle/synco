use std::io::ErrorKind;
use std::path::PathBuf;
use std::{fs, io};

const DEFAULT_APP_SUBDIR: &str = "synco";
const DEFAULT_SERVER_CLIENT_CERT_STORAGE: &str = "client";
pub fn get_default_application_dir() -> PathBuf {
    let mut app_data_dir = dirs::data_dir()
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::Unsupported,
                "Could not determine application data directory for this OS.",
            )
        })
        .unwrap();
    app_data_dir.push(DEFAULT_APP_SUBDIR);

    if !fs::exists(&app_data_dir).unwrap() {
        fs::create_dir_all(app_data_dir.clone())
            .map_err(|e| {
                rustls::Error::General(format!(
                    "Failed to create directories at {}, {}",
                    app_data_dir.clone().display(),
                    e
                ))
            })
            .unwrap();
    }

    app_data_dir
}

/**
Generates client storage on SERVER side for storing signed client PEM
*/
pub fn get_client_cert_storage_server() -> PathBuf {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir.join(DEFAULT_SERVER_CLIENT_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_SERVER_CLIENT_CERT_STORAGE)
}
