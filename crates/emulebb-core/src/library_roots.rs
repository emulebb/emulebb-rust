//! Cached library root resources; reads never inspect the filesystem.
use crate::{EmulebbCore, LibraryReply};
use anyhow::{Result, ensure};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryRoot {
    pub id: String,
    pub path: String,
    pub watch_enabled: bool,
    pub scan_required: bool,
    pub managed: bool,
    pub accessible: bool,
    pub shareable: bool,
    /// Last completed scan as Unix seconds, independent of current accessibility.
    pub last_scanned_at: Option<i64>,
}

impl From<emulebb_metadata::MetadataLibraryRoot> for LibraryRoot {
    fn from(root: emulebb_metadata::MetadataLibraryRoot) -> Self {
        Self {
            id: root.id.to_string(),
            path: emulebb_metadata::NativePath::from(root.path).display_path(),
            watch_enabled: root.watch_enabled,
            scan_required: root.scan_required,
            managed: root.managed,
            accessible: root.accessible,
            shareable: root.shareable,
            last_scanned_at: root.last_scanned_at_ms.map(|value| value / 1000),
        }
    }
}

pub struct LibraryRootPage {
    pub roots: Vec<LibraryRoot>,
    pub total: u64,
    pub next_id: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryScan {
    pub hashing_count: i64,
    pub reload_progress: crate::SharedDirectoryReloadProgress,
}

pub(crate) enum Query {
    Get(i64),
    Page { after: i64, limit: usize },
}
pub(crate) enum Value {
    Root(Option<LibraryRoot>),
    Page(LibraryRootPage),
}

impl EmulebbCore {
    /// Bounded cached scan status, independent of the configured root collection.
    pub fn library_scan(&self) -> LibraryScan {
        LibraryScan {
            hashing_count: crate::shared_directories::hashing_count_snapshot(self),
            reload_progress: self.shared_directory_reload_progress(),
        }
    }
    pub async fn library_root(&self, id: i64) -> Result<LibraryReply<Option<LibraryRoot>>> {
        ensure!(id > 0, "root id must be positive");
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        let reply = owner.read_library_roots(Query::Get(id)).await?;
        ensure!(
            matches!(reply.value(), Value::Root(_)),
            "unexpected root read response"
        );
        Ok(reply.map(|value| match value {
            Value::Root(root) => root,
            _ => unreachable!(),
        }))
    }

    pub async fn library_root_page(
        &self,
        after: i64,
        limit: usize,
    ) -> Result<LibraryReply<LibraryRootPage>> {
        ensure!(after >= 0, "root continuation must be nonnegative");
        ensure!(
            (1..=100).contains(&limit),
            "root page limit must be between 1 and 100"
        );
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        let reply = owner
            .read_library_roots(Query::Page { after, limit })
            .await?;
        ensure!(
            matches!(reply.value(), Value::Page(_)),
            "unexpected root page response"
        );
        Ok(reply.map(|value| match value {
            Value::Page(page) => page,
            _ => unreachable!(),
        }))
    }
}
