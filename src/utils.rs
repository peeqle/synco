use crate::consts::{DEFAULT_APP_SUBDIR, DEFAULT_CLIENT_CERT_STORAGE, DEFAULT_SERVER_CERT_STORAGE};
use rustls::RootCertStore;
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, ErrorKind};
use std::path::{Path, PathBuf};
use std::{fs, io};

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

pub fn verify_permissions<T: AsRef<Path>>(path: T, need_write: bool) -> Result<(), Box<io::Error> > {
    if !fs::exists(path.as_ref())? {
        return Err(Box::new(io::Error::new(
            ErrorKind::NotFound,
            format!("File is not found: {}", path.as_ref().display()).as_str(),
        )));
    }

    let md = fs::metadata(path.as_ref())?;
    let permissions = md.permissions();
    let readonly = permissions.readonly();

    if readonly && need_write {
        return Err(Box::new(io::Error::new(
            ErrorKind::PermissionDenied,
            format!("Cannot reach file for write: {}", path.as_ref().display()).as_str(),
        )));
    }

    Ok(())
}

pub(crate) fn load_cas<T: AsRef<Path>>(path: T) -> io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader);
    for cert in certs {
        root_store
            .add(cert?)
            .expect("Cannot add cert to the client's RootCertStore");
    }
    Ok(root_store)
}

/**
Generates client storage on SERVER side for storing signed client PEM
*/
pub fn get_client_cert_storage_server() -> PathBuf {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir.join(DEFAULT_CLIENT_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_CLIENT_CERT_STORAGE)
}

pub fn get_server_cert_storage() -> PathBuf {
    let dir = get_default_application_dir();
    fs::create_dir_all(&dir.join(DEFAULT_SERVER_CERT_STORAGE)).unwrap();

    dir.join(DEFAULT_SERVER_CERT_STORAGE)
}

pub fn validate_server_cert_present() -> bool {
    let server_cert_path = get_server_cert_storage();
    if server_cert_path.exists() {
        let entries: Vec<_> = fs::read_dir(server_cert_path)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        if entries.is_empty() {
            return false;
        }

        println!("------------------------------");
        for path in entries.into_iter() {
            println!("Found CA: {}", path.file_name().to_str().unwrap());
        }
        return true;
    }
    false
}
