use std::fs::File;
use serde_json::json;
use std::io::{self, Read};
use std::io::ErrorKind;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::consts::CommonThreadError;
use crate::diff::FileEntity;

pub async fn send_file_chunked<T>(
    connection: Arc<Mutex<T>>,
    file_entity: &FileEntity,
) -> Result<(), CommonThreadError>
where
    T: AsyncWrite + Unpin + Send + 'static,
{
    let mut file = File::open(&file_entity.path)?;
    let metadata = json!({
        "filename": file_entity.filename,
        "size": file_entity.size
    });

    let serialized_metadata = serde_json::to_vec(&metadata)?;

    let mut mtx = connection.lock().await;
    mtx.write_all(&(serialized_metadata.len() as u64).to_ne_bytes()).await?;
    mtx.write_all(&serialized_metadata).await?;

    let mut buffer_chunk = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer_chunk)?;
        if bytes_read == 0 {
            break;
        }

        mtx.write_all(&(bytes_read as u64).to_le_bytes()).await?;
        mtx.write_all(&buffer_chunk[..bytes_read]).await?;
    }

    Ok(())
}
pub async fn send_framed<T>(
    connection: Arc<Mutex<T>>,
    request: Vec<u8>,
) -> Result<(), CommonThreadError>
where
    T: AsyncWrite + Unpin + Send + 'static,
{
    let mut mtx = connection.lock().await;

    mtx.write_all(&(request.len() as u64).to_ne_bytes()).await?;
    mtx.write_all(&request).await?;

    Ok(())
}

pub async fn receive_frame<T>(connection: Arc<Mutex<T>>) -> Result<(), CommonThreadError>
where
    T: AsyncRead + Unpin + Send + 'static,
{
    let mut mtx = connection.lock().await;

    let mut len_bytes = [0u8; 8];
    mtx.read_exact(&mut len_bytes).await?;

    let len = u64::from_ne_bytes(len_bytes) as usize;

    if len > 10 * 1024 * 1024 {
        return Err(Box::new(io::Error::new(
            ErrorKind::InvalidData,
            "Received message length is too large",
        )));
    }

    let mut buffer = vec![0u8; len];
    mtx.read_exact(&mut buffer).await?;

    Ok(())
}
