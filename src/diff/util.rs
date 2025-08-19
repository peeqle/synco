use crate::consts::CommonThreadError;
use crate::diff::consts;
use blake3::{Hash, Hasher};
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::path::Path;
use std::str::from_utf8;
use std::{fs, io};

pub fn verify_file_size<T: AsRef<Path>>(file_path: T) -> bool {
    if let Ok(meta) = fs::metadata(file_path) {
        return meta.len() <= consts::MAX_FILE_SIZE_BYTES
    }
    false
}

pub fn is_file_binary_utf8<T: AsRef<Path>>(path: T) -> Result<bool, CommonThreadError> {
    let mut file = File::open(&path)?;
    let mut buffer = vec![0; 4096];
    let bytes_read = file.read(&mut buffer)?;

    if bytes_read == 0 {
        return Ok(false);
    }

    if buffer[..bytes_read].contains(&0x00) {
        return Ok(true);
    }

    match from_utf8(&buffer[..bytes_read]) {
        Ok(_) => Ok(false),
        Err(_) => Ok(true),
    }
}

pub fn verify_permissions<T: AsRef<Path>>(path: T, need_write: bool) -> Result<bool, CommonThreadError> {
    let metadata = fs::metadata(path.as_ref())?;

    if metadata.is_dir() {
        return Ok(false);
    }

    if need_write {
        Ok(!metadata.permissions().readonly())
    } else {
        Ok(true)
    }
}

pub fn blake_digest<T: AsRef<Path>>(path: T) -> Result<Hash, CommonThreadError> {
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
