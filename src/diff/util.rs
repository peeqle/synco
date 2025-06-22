use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::from_utf8;

pub fn is_file_binary_utf8<T: AsRef<Path>>(path: T) -> Result<bool, Box<dyn Error>> {
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
