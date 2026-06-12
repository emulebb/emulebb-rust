use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_kad_proto::{Ed2kHash, NodeId};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

pub fn node_id(byte: u8) -> NodeId {
    NodeId::from_bytes([byte; 16])
}

pub fn file_hash(byte: u8) -> Ed2kHash {
    Ed2kHash::from_bytes([byte; 16])
}

pub fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = rust_test_tmp_root().join(format!(
        "emulebb-rust-{name}-{}-{stamp}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create test directory");
    path
}

fn rust_test_tmp_root() -> PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
