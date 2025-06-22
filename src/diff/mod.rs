//todo implement lcs for files
//create file holder structure

use crate::consts::BUFFER_SIZE;
use blake3::{Hash, Hasher};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind};
use std::path::Path;
use std::sync::Arc;
use std::{fs, io};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::Instant;

lazy_static! {
    pub static ref ProcessedFiles: Arc<Mutex<HashMap<String, FileEntity>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, PartialEq)]
pub struct FileEntity {
    prev_hash: Option<Hash>,
    current_hash: Hash,
    //devices in-sync
    main_node: String,
    synced_with: Box<Vec<String>>,
    //
    last_update: Instant,
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

pub fn verify_permissions<T: AsRef<Path>>(path: T, need_write: bool) -> Result<(), Box<dyn Error>> {
    let md = fs::metadata(&path)?;
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

pub fn blake_digest<T: AsRef<Path>>(path: T) -> Result<Hash, Box<dyn Error>> {
    let mut hasher = Hasher::new();

    let file = File::open(path)?;
    let file_size = file.metadata().unwrap().len() / 1024;

    let mut reader = BufReader::new(file);
    let mut holder = String::new();

    if file_size > 128 {
        while reader.read_line(&mut holder).unwrap() > 0 {
            hasher.update_rayon(holder.as_bytes());
            holder.clear();
        }
    } else {
        while reader.read_line(&mut holder).unwrap() > 0 {
            hasher.update(holder.as_bytes());
            holder.clear();
        }
    }

    Ok(hasher.finalize())
}

mod diff_test {
    use crate::diff::{blake_digest, verify_permissions};
    use std::fs;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::path::Path;
    use crate::consts::DEFAULT_TEST_SUBDIR;
    use crate::utils::get_default_application_dir;

    #[test]
    fn calculate_hash() {
        let dir_path =get_default_application_dir().join(&DEFAULT_TEST_SUBDIR);
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
        
        assert_eq!("ee68bba0464d5a3aa3af7778d1bdea395f9705f5186dc74e2343a9c9263734e3", hash.unwrap().to_string());
    }
}
