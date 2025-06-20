use crate::utils::get_client_cert_storage_server;
use rustls::RootCertStore;
use std::fs::File;
use std::io;
use std::io::BufReader;

pub(crate) fn load_client_cas() -> io::Result<RootCertStore> {
    let mut root_store = RootCertStore::empty();
    let mut reader = BufReader::new(File::open(get_client_cert_storage_server())?);
    let certs = rustls_pemfile::certs(&mut reader);
    for cert in certs {
        root_store
            .add(cert?)
            .expect("Cannot add cert to the client's RootCertStore");
    }
    Ok(root_store)
}
