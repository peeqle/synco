//todo implement lcs for files
//create file holder structure

mod util;

use crate::consts::{of_type, CommonThreadError, DeviceId, BUFFER_SIZE};
use crate::diff::util::{blake_digest, verify_permissions};
use crate::utils::device_id;
use blake3::Hash;
use lazy_static::lazy_static;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufRead, ErrorKind, Read};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;
use FileManagerOperations::*;

lazy_static! {
    pub static ref ProcessedFiles: Arc<Mutex<HashMap<String, FileEntity>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, PartialEq)]
pub struct FileEntity {
    id: String,
    prev_hash: Option<Hash>,
    current_hash: Hash,
    //devices in-sync
    main_node: String,
    synced_with: Vec<String>,
    //
    last_update: Option<Instant>,
}

pub struct FileManager {
    attached_files: Arc<Mutex<Vec<FileEntity>>>,
    rx: FileReceiverRx,
}

pub enum FileManagerOperations {
    InsertRequired {
        file_entity: FileEntity,
    },
    InsertSystem {
        path: Box<Path>,
    },
    Delete {
        id: String,
    },
    Update {
        id: String,
        file_entity_mergeable: FileEntity,
    },
}

pub type FileReceiverRx = Receiver<FileManagerOperations>;
impl FileManager {
    pub fn new(file_reader_rx: FileReceiverRx) -> Self {
        FileManager {
            attached_files: Arc::new(Mutex::new(vec![])),
            rx: file_reader_rx,
        }
    }
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let handle = |query: &FileManagerOperations| -> Result<(), Box<dyn Error>> {
            match query {
                InsertRequired { file_entity } => {
                    Ok(())
                }
                InsertSystem { path } => {
                    let err = verify_permissions(path.as_ref(), false).err();
                    if let Some(file_error) = err {
                        match file_error.kind() {
                            ErrorKind::NotFound => {
                                return Err(of_type(&format!("Cannot find specified file at: {}", path.to_str().unwrap()), ErrorKind::Other));
                            }
                            _ => {}
                        }
                    }

                    let mut lck = self.attached_files.try_lock()?;


                    let hash = blake_digest(&path)?;
                    if let Some(current_device_id) = device_id() {
                        lck.push(
                            FileEntity {
                                id: Uuid::new_v4().to_string(),
                                prev_hash: None,
                                current_hash: hash,
                                main_node: current_device_id,
                                synced_with: vec![],
                                last_update: Some(Instant::now()),
                            });

                        println!("Added new file to the space: {}", path.to_str().unwrap());
                    }
                    Ok(())
                }
                Delete { id } => {
                    let mut lck = self.attached_files.try_lock()?;
                    lck.retain(|x| !x.id.eq(id));
                    Ok(())
                }
                Update { id, file_entity_mergeable } => {
                    let mut lck = self.attached_files.try_lock()?;
                    if let Some(ent) = lck.iter()
                        .find(|x| x.id.eq(id)).as_mut() {}
                    Ok(())
                }
            }
        };
        loop {
            tokio::select! {
                Some(query) = self.rx.recv()  => {

                },
                else => break
            }
        }
        Ok(())
    }
}

pub async fn attach<T: AsRef<Path>>(path: T) -> Result<(), Box<dyn Error>> {
    let permissions = verify_permissions(&path, false);
    if permissions.is_err() {
        return Err(permissions.err().unwrap());
    }
    let mut current_state = ProcessedFiles.lock().await;

    let blake_filepath_hash = blake_digest(&path)?;
    match current_state.entry(blake_filepath_hash.to_string()) {
        Entry::Occupied(entry) => {
            println!("Recalculating hashes for {}", path.as_ref().to_str().unwrap());
        }
        Entry::Vacant(_) => {
            current_state.insert(blake_filepath_hash.to_string(), FileEntity {
                id: Uuid::new_v4().to_string(),
                prev_hash: None,
                current_hash: blake_filepath_hash,
                main_node: DeviceId.clone(),
                synced_with: vec![],
                last_update: None,
            });
        }
    }
    Ok(())
}

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
    use crate::utils::get_default_application_dir;
    use std::fs;
    use std::fs::File;
    use std::io::{BufWriter, Write};

    #[test]
    fn calculate_hash() {
        let dir_path = get_default_application_dir().join(&DEFAULT_TEST_SUBDIR);
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
