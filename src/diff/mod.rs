//todo implement lcs for files
//create file holder structure

mod util;

use crate::consts::BUFFER_SIZE;
use crate::diff::util::is_file_binary_utf8;
use crate::keychain::device_id;
use crate::utils::verify_permissions;
use FileManagerOperations::*;
use blake3::{Hash, Hasher};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

lazy_static! {
    pub static ref ProcessedFiles: Arc<Mutex<HashMap<String, FileEntity>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, PartialEq)]
pub struct FileEntity {
    id: u64,
    prev_hash: Option<Hash>,
    current_hash: Hash,
    //devices in-sync
    main_node: String,
    synced_with: Vec<String>,
    //
    last_update: Instant,
}

pub struct FileManager {
    attached_files: Arc<Mutex<Vec<FileEntity>>>,
    rx: FileReceiverRx,
}

enum FileManagerOperations {
    InsertRequired {
        file_entity: FileEntity,
    },
    InsertSystem {
        path: Box<Path>,
    },
    Delete {
        id: u64,
    },
    Update {
        id: u64,
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
        loop {
            tokio::select! {
                Some(query) = self.rx.recv()  => {
                    match query {

                    InsertRequired{ file_entity } => {}
                        InsertSystem{ path } => {
                            let err = verify_permissions(path.as_ref(), false).err();
                            if let Some(file_error) = err {
                                match file_error.kind() {
                                    ErrorKind::NotFound => {
                                        println!("Cannot find specified file at: {}", path.to_str().unwrap());
                                        break;
                                    }
                                    _ => {break;}
                                }
                            }


                            let mut lck = self.attached_files.try_lock()?;

                            let mut next_id = 1;
                            if !lck.is_empty() {
                            let last_entity = lck.last();
                                if let Some(ent) = last_entity {
                                    next_id = ent.id + 1;
                                }
                            }

                            let hash = blake_digest(&path)?;
                            if let Some(current_device_id) =device_id() {
                             lck.push(
                                FileEntity {
                                id: next_id,
                            prev_hash: None,
                                current_hash: hash,
                                main_node: current_device_id,
                                synced_with: vec![],
                                    last_update: Instant::now()});

                            println!("Added new file to the space: {}", path.to_str().unwrap());
                            }
                        }
                        Delete{ id } => {
                            let mut lck = self.attached_files.try_lock()?;
                            lck.retain(|x| x.id != id);
                        }
                        Update{ .. } => {}}
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
    let filepath = path
        .as_ref()
        .to_str()
        .expect("Cannot extract filepath")
        .as_bytes();

    let blake_filepath_hash = blake3::hash(filepath);
    // match current_state.entry(blake_filepath_hash.to_string()) {
    //     Entry::Occupied(entry) => {
    //         println!("Recalculating hashes for {}", path.as_ref().to_str().unwrap());
    //     }
    //     Entry::Vacant(_) => {
    //         current_state.insert(blake_filepath_hash.to_string(), FileEntity {
    //             prev_hash: None,
    //             current_hash:,
    //         })
    //     }
    // }
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

pub fn process<T: AsRef<Path>>(path: T, mut reader: TcpStream) {
    //create file synchronization stats - here - ???
    //assuming that file is loaded on instant (test only)
    //file hash deviation considered to load instantly

    let mut buffer = vec![0; BUFFER_SIZE];
    let mut total_bytes_received = 0;
}

pub fn blake_digest<T: AsRef<Path>>(path: T) -> Result<Hash, Box<dyn Error>> {
    let mut hasher = Hasher::new();

    let file = File::open(path.as_ref())?;
    let md = file.metadata()?;
    let file_size = md.len() / 1024;

    let mut reader = BufReader::new(file);
    if is_file_binary_utf8(path.as_ref())? {
        let mut buff = [0; 65536];

        loop {
            let bytes_read = reader.read(&mut buff)?;
            if bytes_read == 0 {
                break;
            }

            hasher.update_rayon(&buff[..bytes_read]);
        }
    } else {
        let mut holder = String::new();

        if file_size > 128 {
            while reader.read_line(&mut holder)? > 0 {
                hasher.update_rayon(holder.as_bytes());
                holder.clear();
            }
        } else {
            while reader.read_line(&mut holder)? > 0 {
                hasher.update(holder.as_bytes());
                holder.clear();
            }
        }
    }

    Ok(hasher.finalize())
}

mod diff_test {
    use crate::consts::DEFAULT_TEST_SUBDIR;
    use crate::diff::blake_digest;
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
