use blake3::Hash;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;
use tokio::time::Instant;
use vis::vis;

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
    is_in_sync: Arc<AtomicBool>,
    //devices in-sync
    main_node: String,
    synced_with: Vec<String>,
    last_update: Option<Instant>,
    notify: Arc<Notify>,
}

impl FileEntity {
    pub fn to_dto(&self) -> FileEntityDto{
        FileEntityDto {
            id: self.id.clone(),
            filename: self.filename.clone(),
            size: self.size,
            current_hash: self.current_hash.clone().as_bytes().into(),
        }
    }
}

#[derive(Clone,Debug,Serialize, Deserialize)]
#[vis(pub)]
pub struct FileEntityDto {
    id: String,
    filename: String,
    size: u64,
    current_hash: Vec<u8>
}

#[derive(Clone)]
pub struct SynchroPoint {
    pub path: PathBuf,
    pub enabled: bool,
}
