use blake3::Hash;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;
use tokio::time::Instant;

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

#[derive(Clone)]
pub struct SynchroPoint {
    pub path: PathBuf,
    pub enabled: bool,
}
