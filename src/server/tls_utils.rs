use crate::utils::DirType::Action;
use crate::utils::{get_client_cert_storage, get_default_application_dir, get_server_cert_storage};
use std::fs;

pub fn clear_client_cert_dir() {
    let dir = get_client_cert_storage();
    fs::remove_dir_all(dir).expect("Cannot clear client cert DIR");

    fs::remove_dir_all(get_server_cert_storage())
        .expect("Cannot clear server cert DIR");

    fs::remove_dir_all(get_default_application_dir(Action))
        .expect("Cannot clear application DIR");
}
