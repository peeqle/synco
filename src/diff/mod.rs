mod consts;
mod util;

use crate::consts::{BUFFER_SIZE, CommonThreadError, DeviceId, of_type};
use crate::diff::SnapshotAction::Update;
use crate::diff::consts::MAX_FILE_SIZE_BYTES;
use crate::diff::util::{blake_digest, verify_file_size, verify_permissions};
use crate::utils::DirType::Cache;
use crate::utils::get_default_application_dir;
use blake3::Hash;
use lazy_static::lazy_static;
use mockall::Any;
use notify::event::{DataChange, ModifyKind, RemoveKind};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::error::Error;
use std::fs::{self, copy, remove_file};
use std::io;
use std::io::{BufRead, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;
use uuid::Uuid;

lazy_static! {
    pub static ref Files: Arc<Mutex<HashMap<String, FileEntity>>> =
        Arc::new(Mutex::new(HashMap::new()));
    pub static ref Points: Arc<Mutex<HashMap<String, SynchroPoint>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone)]
pub struct FileEntity {
    pub id: String,
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
    snapshot_path: Option<PathBuf>,
    prev_hash: Option<Hash>,
    pub current_hash: Hash,
    is_in_sync: Arc<AtomicBool>,
    //devices in-sync
    main_node: String,
    synced_with: Vec<String>,
    //
    last_update: Option<Instant>,
    notify: Arc<Notify>,
}

#[derive(Clone)]
pub struct SynchroPoint {
    pub path: PathBuf,
    pub enabled: bool,
}

pub mod point {
    use crate::consts::CommonThreadError;
    use crate::diff::{Points, SynchroPoint};
    use std::collections::hash_map::Entry;
    use std::path::PathBuf;

    pub async fn update_point(
        file_extension: String,
        path: Option<PathBuf>,
        enabled: Option<bool>,
    ) -> Result<(), CommonThreadError> {
        let points_manager = Points.clone();
        let mut mtx = points_manager.lock().await;

        match mtx.entry(file_extension.clone()) {
            Entry::Occupied(mut ent) => {
                let ent_mut = ent.get_mut();
                if let Some(path_opt) = path {
                    ent_mut.path = path_opt;
                }
                if let Some(enabled_opt) = enabled {
                    ent_mut.enabled = enabled_opt;
                }
            }
            Entry::Vacant(_) => {
                if let Some(path_opt) = path {
                    mtx.insert(
                        file_extension,
                        SynchroPoint {
                            path: path_opt,
                            enabled: enabled.unwrap_or(true),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    pub async fn remove_point(file_extension: String) -> Result<(), CommonThreadError> {
        let points_manager = Points.clone();
        let mut mtx = points_manager.lock().await;

        mtx.remove(&file_extension);
        Ok(())
    }
}

pub async fn get_seeding_files() -> Vec<String> {
    let files = Files.clone();
    let mtx = files.lock().await;

    mtx.iter().map(|(x, y)| y.id.clone()).collect()
}

pub async fn remove(file_id: &String) -> Result<(), CommonThreadError> {
    let file_manager = Files.clone();
    let mut mtx = file_manager.lock().await;

    mtx.remove_entry(file_id).expect("Cannot remove entry");
    Ok(())
}

pub async fn attach<T: AsRef<Path>>(path: T) -> Result<(), CommonThreadError> {
    let permissions = verify_permissions(&path, false);
    if permissions.is_err() {
        return Err(permissions.err().unwrap());
    }
    if !verify_file_size(&path) {
        return Err(of_type(
            &format!("File is too large, max is {}", MAX_FILE_SIZE_BYTES),
            ErrorKind::Other,
        ));
    }

    let metadata = fs::metadata(&path)?;

    let file_manager = Files.clone();
    let mut current_state = file_manager.lock().await;

    let blake_filepath_hash = blake_digest(&path)?;
    match current_state.entry(blake3::hash(path.as_ref().as_os_str().as_bytes()).to_string()) {
        Entry::Occupied(entry) => {
            println!(
                "Recalculating hashes for {}",
                path.as_ref().to_str().unwrap()
            );
        }
        Entry::Vacant(_) => {
            current_state.insert(
                blake_filepath_hash.to_string(),
                FileEntity {
                    id: Uuid::new_v4().to_string(),
                    filename: String::from(PathBuf::from(path.as_ref()).file_name().unwrap().to_str().unwrap()),
                    size: metadata.len(),
                    path: PathBuf::from(path.as_ref()),
                    is_in_sync: Arc::new(AtomicBool::new(false)),
                    snapshot_path: None,
                    prev_hash: None,
                    current_hash: blake_filepath_hash,
                    main_node: DeviceId.clone(),
                    synced_with: vec![],
                    last_update: None,
                    notify: Arc::new(Notify::new()),
                },
            );
        }
    }
    Ok(())
}

pub fn snapshot(file: &mut FileEntity, action: SnapshotAction) -> Result<(), CommonThreadError> {
    let mut clone = || -> Result<(), CommonThreadError> {
        if let Some(file_name) = file.path.file_name() {
            let dir = get_default_application_dir(Cache);

            copy(&file.path, dir.join(&file_name))?;
            file.snapshot_path = Some(dir.join(&file_name));
        }
        Ok(())
    };
    match action {
        SnapshotAction::Create => {
            clone()?;
        }
        SnapshotAction::Update => {
            clone()?;
        }
        SnapshotAction::Remove => {
            if let Some(file_path) = &file.snapshot_path {
                remove_file(file_path)?;
            }
        }
    }
    Ok(())
}

pub enum SnapshotAction {
    Create,
    Update,
    Remove,
}

pub async fn file_sync<T: AsRef<Path>>(path: T, file: &FileEntity) {
    let file_manager = Files.clone();
    let notify_future = Arc::clone(&file.notify);

    let path_arc = Arc::new(path.as_ref().to_path_buf());
    tokio::spawn(async move {
        loop {
            notify_future.notified().await;

            let mut mtx = file_manager.lock().await;
            let path_key = blake3::hash(path_arc.as_os_str().as_bytes()).to_string();

            if let Some(entry) = mtx.get_mut(&path_key) {
                //send changes to node

                snapshot(entry, Update).expect("Cannot create file snapshot");
            }
        }
    });
}

pub async fn check_file_change(file: &FileEntity) -> RecommendedWatcher {
    let notify_future = Arc::clone(&file.notify);
    let file_path = file.path.clone();
    let mut watcher =
        notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
            Ok(event) => {
                if event.paths.contains(&file_path)
                    && (matches!(
                        event.kind,
                        notify::EventKind::Modify(ModifyKind::Data(DataChange::Content))
                    ) || matches!(event.kind, notify::EventKind::Remove(RemoveKind::Any)))
                {
                    notify_future.notify_waiters();
                }
            }
            Err(e) => eprintln!("{:?}", e),
        })
        .expect("Cannot build watcher");

    watcher
        .watch(&file.path.clone(), RecursiveMode::NonRecursive)
        .expect("Cannot watch");

    watcher
}

/**
For now consider that a bullshit, cause idk how to efficiently compare two+ distinct, fairly similar, but completely different files in the network
*/
///Called if only hashes on both sides are different
/// 1. Read line from reader while reader line [i] == internal file line [i]
/// 2. If reader line [i] != internal file line [i] - set flag
/// 3. Start from the bottom
///
/// 3.1. Read line from reader while reader line [j] == internal file line [j]
///
/// 3.2 if reader line [j] != internal file line [j] - set flag
///
/// 4. Request content from the *synchronizing* point for the [flag_top, flag_bottom]
/// 5. Load changes, update hashes on both sides

pub fn process<T: AsRef<Path>>(path: T, mut reader: TcpStream) -> Result<(), CommonThreadError> {
    //create file synchronization stats - here - ???
    //assuming that file is loaded on instant (test only)
    //file hash deviation considered to load instantly

    let mut buf = [0u8; 65536];
    while reader.try_read(&mut buf)? > 0 {}

    let mut buffer = vec![0; BUFFER_SIZE];
    let mut total_bytes_received = 0;

    Ok(())
}

mod diff_test {
    use crate::consts::DEFAULT_TEST_SUBDIR;
    use crate::diff::util::blake_digest;
    use crate::utils::DirType::Action;
    use crate::utils::get_default_application_dir;
    use std::fs;
    use std::fs::File;
    use std::io::{BufWriter, Write};

    #[test]
    fn calculate_hash() {
        let dir_path = get_default_application_dir(Action).join(&DEFAULT_TEST_SUBDIR);
        let _ = fs::remove_dir_all(&dir_path);

        fs::create_dir_all(dir_path.as_path()).unwrap();
        let file_path = dir_path.join("diff_test.txt");
        let file = File::create_new(&file_path).unwrap();

        let mut writer = BufWriter::new(&file);
        writer.write_all(b"Lorem Ipsum is simply dummy text of the printing and typesetting industry.\
         Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,\
          when an unknown printer took a galley of type and scrambled it to make a type specimen book. \
          It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged.\
           It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently \
           with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.").unwrap();

        drop(writer);

        let hash = blake_digest(file_path);
        if hash.is_err() {
            panic!(
                "Cannot extract test file hash: {}",
                hash.err().unwrap().to_string()
            );
        }
        let _ = fs::remove_dir_all(&dir_path);

        assert_eq!(
            "ee68bba0464d5a3aa3af7778d1bdea395f9705f5186dc74e2343a9c9263734e3",
            hash.unwrap().to_string()
        );
    }
}
