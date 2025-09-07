use log::debug;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read};
use std::io::{ErrorKind, Write};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::consts::CommonThreadError;
use crate::diff::model::FileEntity;
use crate::server::model::ServerRequest;
use crate::server::model::ServerResponse::{self, FileMetadata};

pub const FILE_CHUNK_SIZE: usize = 8192;
pub async fn receive_file_chunked<T, W>(
    connection: &mut T,
    size: u64,
    mut writer: W,
) -> Result<(), CommonThreadError>
where
    T: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let mut received_bytes: u64 = 0;
    let mut buffer = vec![0u8; FILE_CHUNK_SIZE];

    while received_bytes < size {
        let bytes_to_read = std::cmp::min(FILE_CHUNK_SIZE, (size - received_bytes) as usize);
        buffer.resize(bytes_to_read, 0);

        connection.read_exact(&mut buffer).await?;
        writer.write_all(&buffer).await?;

        received_bytes += bytes_to_read as u64;
    }

    writer.flush().await?;

    Ok(())
}

pub async fn send_file_chunked<T>(
    connection: &mut T,
    file_entity: &FileEntity,
) -> Result<(), CommonThreadError>
where
    T: AsyncWrite + Unpin + Send + 'static,
{
    let mut file = File::open(&file_entity.path)?;
    let metadata = FileMetadata {
        file_id: file_entity.id.clone(),
        size: file_entity.size,
    };

    let serialized_metadata = serde_json::to_vec(&metadata)?;

    connection
        .write_all(&(serialized_metadata.len() as u64).to_le_bytes())
        .await?;
    connection.write_all(&serialized_metadata).await?;

    connection.flush().await?;

    let mut buffer_chunk = [0u8; FILE_CHUNK_SIZE];

    loop {
        let bytes_read = file.read(&mut buffer_chunk)?;
        if bytes_read == 0 {
            debug!("File read end");
            break;
        }

        debug!("Sending file bytes");
        connection
            .write_all(&(bytes_read as u64).to_le_bytes())
            .await?;
        connection.write_all(&buffer_chunk[..bytes_read]).await?;
    }
    connection.flush().await?;
    Ok(())
}
pub async fn send_framed<T>(connection: &mut T, request: Vec<u8>) -> Result<(), CommonThreadError>
where
    T: AsyncWrite + Unpin + Send + 'static,
{
    connection
        .write_all(&(request.len() as u64).to_le_bytes())
        .await?;
    connection.write_all(&request).await?;

    connection.flush().await?;
    Ok(())
}

pub async fn receive_frame<T, X>(connection: &mut T) -> Result<X, CommonThreadError>
where
    T: AsyncRead + Unpin + Send + 'static,
    X: DeserializeOwned,
{
    let mut len_bytes = [0u8; 8];
    connection.read_exact(&mut len_bytes).await?;

    let len = u64::from_le_bytes(len_bytes) as usize;

    debug!("Received message, len: {}", len);

    if len > 10 * 1024 * 1024 {
        return Err(Box::new(io::Error::new(
            ErrorKind::InvalidData,
            "Received message length is too large",
        )));
    }

    let mut buffer = vec![0u8; len];
    connection.read_exact(&mut buffer).await?;

    let req = serde_json::from_slice::<X>(&buffer)?;

    Ok(req)
}
