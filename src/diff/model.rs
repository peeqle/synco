use blake3::Hash;
use log::error;
use serde::{Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::Notify;
use tokio::time::Instant;
use vis::vis;

use crate::consts::DeviceId;

#[derive(Clone)]
#[vis::vis(pub)]
pub struct FileEntity {
    id: String,
    path: PathBuf,
    filename: String,
    size: u64,
    snapshot_path: Option<PathBuf>,
    prev_hash: Option<Hash>,
    current_hash: Hash,
    is_in_sync: bool,
    //devices in-sync
    main_node: String,
    synced_with: Vec<String>,
    notify: Arc<Notify>,
}

impl FileEntity {
    pub fn to_dto(&self) -> FileEntityDto {
        FileEntityDto {
            id: self.id.clone(),
            filename: self.filename.clone(),
            size: self.size,
            current_hash: self.current_hash.clone().as_bytes().into(),
            node_id: DeviceId.clone(),
        }
    }
}

pub fn from_dto(dto: FileEntityDto) -> Option<FileEntity> {
    match Hash::from_slice(&dto.current_hash) {
        Ok(hash) => {
            return Some(FileEntity {
                id: dto.id,
                path: Default::default(),
                filename: dto.filename,
                size: dto.size,
                snapshot_path: None,
                prev_hash: None,
                current_hash: hash,
                is_in_sync: false,
                main_node: dto.node_id,
                synced_with: vec![],
                notify: Arc::new(Default::default()),
            });
        }
        Err(e) => {
            error!("Cannot create new FileEntity from provided DTO: {}", e);
        }
    }
    None
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[vis(pub)]
pub struct FileEntityDto {
    id: String,
    filename: String,
    size: u64,
    current_hash: Vec<u8>,
    node_id: String,
}

#[derive(Clone)]
pub struct SynchroPoint {
    pub path: PathBuf,
    pub enabled: bool,
}
