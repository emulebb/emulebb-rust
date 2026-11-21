//! Typed library summaries retain the admitted Native read's backing ownership.

use anyhow::Result;
use emulebb_ed2k::ed2k_transfer::RetainedRead;
use serde::Serialize;

use crate::{EmulebbCore, LocalMutationError, PersistenceError};
pub use emulebb_metadata::{
    LibraryFileQuery, LibraryFileSort, LibraryFileView, MetadataLibraryCursorExpired,
};

pub const LIBRARY_FILE_PAGE_BYTES: usize = emulebb_metadata::LIBRARY_READ_MAX_BYTES;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LibraryFile {
    pub hash: String,
    pub display_name: String,
    pub size_bytes: Option<u64>,
    pub present: bool,
    pub sharing_enabled: bool,
    pub session_uploaded_bytes: u64,
    pub session_upload_requests: u64,
    pub session_accepted_uploads: u64,
    pub lifetime_uploaded_bytes: u64,
    pub lifetime_upload_requests: u64,
    pub lifetime_accepted_uploads: u64,
    pub last_upload_requested_at: Option<i64>,
    pub last_uploaded_at: Option<i64>,
}

impl From<emulebb_metadata::MetadataLibraryFile> for LibraryFile {
    fn from(file: emulebb_metadata::MetadataLibraryFile) -> Self {
        let stats = file.statistics;
        Self {
            hash: file.file_hash,
            display_name: file.display_name,
            size_bytes: file.size_bytes,
            present: file.present,
            sharing_enabled: file.sharing_enabled,
            session_uploaded_bytes: stats.session_uploaded_bytes,
            session_upload_requests: stats.session_upload_requests,
            session_accepted_uploads: stats.session_accepted_uploads,
            lifetime_uploaded_bytes: stats.lifetime.uploaded_bytes,
            lifetime_upload_requests: stats.lifetime.upload_requests,
            lifetime_accepted_uploads: stats.lifetime.accepted_sessions,
            last_upload_requested_at: stats.lifetime.last_requested_at_s,
            last_uploaded_at: stats.lifetime.last_uploaded_at_s,
        }
    }
}

pub struct LibraryFilePage {
    pub files: Vec<LibraryFile>,
    pub next_after: Option<[u8; 16]>,
    pub total: Option<u64>,
}

fn read_error(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<LocalMutationError>().is_some()
        || error
            .downcast_ref::<MetadataLibraryCursorExpired>()
            .is_some()
    {
        return error;
    }
    // WHY: validated reads can still fail on storage. Do not turn their SQL or
    // encoding failures into invalid-user-input responses at the REST boundary.
    tracing::warn!(%error,"library metadata read failed");
    PersistenceError::Storage("library metadata read failed".into()).into()
}

impl EmulebbCore {
    /// Convert one bounded page while retaining source and conversion backing.
    pub async fn library_file_page(
        &self,
        query: LibraryFileQuery,
    ) -> Result<RetainedRead<LibraryFilePage>> {
        self.ed2k_transfers
            .library_file_page(query)
            .await
            .map_err(read_error)?
            .try_project(LIBRARY_FILE_PAGE_BYTES, |page| {
                Ok(LibraryFilePage {
                    files: page.files.into_iter().map(Into::into).collect(),
                    next_after: page.next_after,
                    total: page.total,
                })
            })
            .map_err(read_error)
    }

    /// The same summary facts as the collection, independent of current presence.
    pub async fn library_file(&self, hash: &str) -> Result<Option<RetainedRead<LibraryFile>>> {
        crate::library_policy::validate_hash(hash)?;
        let Some(file) = self
            .ed2k_transfers
            .library_file(hash)
            .await
            .map_err(read_error)?
        else {
            return Ok(None);
        };
        file.try_project(LIBRARY_FILE_PAGE_BYTES, |file| Ok(file.into()))
            .map(Some)
            .map_err(read_error)
    }
}
