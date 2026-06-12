use std::path::Path;

use anyhow::Result;
use emulebb_metadata::{
    MetadataIndexedFile, MetadataSharedDirectoryRoot, MetadataStore, normalize_search_text,
};
use serde::{Deserialize, Serialize};

mod kad_search_expr;
mod kad_store;
mod snoop_model;
mod snoop_queue;

pub use kad_search_expr::matches_restrictive_keyword_payload;
pub use kad_store::{KadLocalStore, KadLocalStoreConfig};
pub use snoop_model::{SnoopEntry, SnoopQueueConfig};
pub use snoop_queue::{
    ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts, SnoopRecordOutcome,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedFile {
    pub ed2k_hash: String,
    pub name: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub availability_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedSharedDirectoryRoot {
    pub path: String,
    pub recursive: bool,
    pub monitor_owned: bool,
    pub shareable: bool,
    pub accessible: bool,
}

#[derive(Debug)]
pub struct FileIndex {
    store: MetadataStore,
}

impl FileIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: MetadataStore::open(path)?,
        })
    }

    pub fn in_memory() -> Result<Self> {
        Ok(Self {
            store: MetadataStore::in_memory()?,
        })
    }

    pub fn from_metadata_store(store: MetadataStore) -> Self {
        Self { store }
    }

    pub fn metadata_store(&self) -> MetadataStore {
        self.store.clone()
    }

    pub fn upsert_file(&mut self, file: &IndexedFile) -> Result<()> {
        self.store.upsert_indexed_file(&MetadataIndexedFile {
            ed2k_hash: file.ed2k_hash.clone(),
            name: file.name.clone(),
            size_bytes: file.size_bytes,
            content_type: file.content_type.clone(),
            availability_score: file.availability_score,
        })
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<IndexedFile>> {
        self.store
            .search_index(query, limit)?
            .into_iter()
            .map(indexed_file_from_metadata)
            .collect()
    }

    pub fn find_by_hash(&self, ed2k_hash: &str) -> Result<Option<IndexedFile>> {
        self.store
            .find_indexed_file_by_hash(ed2k_hash)?
            .map(indexed_file_from_metadata)
            .transpose()
    }

    pub fn replace_shared_directory_roots(
        &mut self,
        roots: &[IndexedSharedDirectoryRoot],
    ) -> Result<()> {
        let metadata_roots = roots
            .iter()
            .map(|root| MetadataSharedDirectoryRoot {
                path: root.path.clone(),
                recursive: root.recursive,
                monitor_owned: root.monitor_owned,
                shareable: root.shareable,
                accessible: root.accessible,
            })
            .collect::<Vec<_>>();
        self.store.replace_shared_directory_roots(&metadata_roots)
    }

    pub fn shared_directory_roots(&self) -> Result<Vec<IndexedSharedDirectoryRoot>> {
        self.store
            .shared_directory_roots()?
            .into_iter()
            .map(|root| {
                Ok(IndexedSharedDirectoryRoot {
                    path: root.path,
                    recursive: root.recursive,
                    monitor_owned: root.monitor_owned,
                    shareable: root.shareable,
                    accessible: root.accessible,
                })
            })
            .collect()
    }
}

pub fn normalize_file_name(value: &str) -> String {
    normalize_search_text(value)
}

fn indexed_file_from_metadata(file: MetadataIndexedFile) -> Result<IndexedFile> {
    Ok(IndexedFile {
        ed2k_hash: file.ed2k_hash,
        name: file.name,
        size_bytes: file.size_bytes,
        content_type: file.content_type,
        availability_score: file.availability_score,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fts_search_returns_indexed_file() {
        let mut index = FileIndex::in_memory().unwrap();
        index
            .upsert_file(&IndexedFile {
                ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
                name: "Example.Movie.2026.1080p.mkv".to_string(),
                size_bytes: 1024,
                content_type: "video".to_string(),
                availability_score: 7,
            })
            .unwrap();

        let results = index.search("example movie", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ed2k_hash, "00112233445566778899aabbccddeeff");
    }

    #[test]
    fn duplicate_normalized_name_updates_one_row() {
        let mut index = FileIndex::in_memory().unwrap();
        let first = IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Example.Movie.mkv".to_string(),
            size_bytes: 1024,
            content_type: "video".to_string(),
            availability_score: 1,
        };
        index.upsert_file(&first).unwrap();
        index.upsert_file(&first).unwrap();

        let results = index.search("example movie", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn shared_directory_roots_persist_through_file_index() {
        let mut index = FileIndex::in_memory().unwrap();
        index
            .replace_shared_directory_roots(&[IndexedSharedDirectoryRoot {
                path: "/tmp/sample".to_string(),
                recursive: true,
                monitor_owned: false,
                shareable: true,
                accessible: true,
            }])
            .unwrap();

        let roots = index.shared_directory_roots().unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, "/tmp/sample");
        assert!(roots[0].recursive);
    }
}
