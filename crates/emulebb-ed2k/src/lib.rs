pub mod config;
#[allow(dead_code)]
pub mod ed2k_server;
#[allow(dead_code)]
pub mod ed2k_tcp;
#[allow(dead_code)]
pub mod ed2k_transfer;
pub mod kad_firewall;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Ed2k(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopularHash {
    pub hash: HashType,
    pub canonical_name: String,
    pub size: u64,
    pub source_count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NatStatus {
    pub observed_external_addresses: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NatManager;

impl NatManager {
    pub async fn status(&self) -> NatStatus {
        NatStatus::default()
    }
}

#[cfg(test)]
pub(crate) mod paths {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn unique_test_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emulebb-rust-{name}-{}-{stamp}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create test directory");
        path
    }
}
