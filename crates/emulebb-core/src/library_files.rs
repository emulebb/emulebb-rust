//! Typed library summaries retain the admitted Native read's backing ownership.

use anyhow::Result;
use emulebb_ed2k::ed2k_transfer::RetainedRead;
use serde::Serialize;

use crate::{EmulebbCore, LocalMutationError, PersistenceError};
pub use emulebb_metadata::{
    LibraryFileQuery, LibraryFileSort, LibraryFileView, MetadataLibraryCursorExpired,
};

pub const LIBRARY_FILE_PAGE_BYTES: usize = emulebb_metadata::LIBRARY_READ_MAX_BYTES;
// Both maximum-length name and comment, including escaped output/link text,
// fit independently of the thin page allowance. This is a retained read charge.
pub const LIBRARY_FILE_DETAIL_BYTES: usize = 2 * 1024 * 1024;

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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryFileDetail {
    #[serde(flatten)]
    pub file: LibraryFile,
    pub upload_priority: String,
    pub comment: String,
    pub rating: u8,
    /// A link requires an accepted content size; provisional job sizes do not
    /// become identity merely because the user browses the library.
    pub ed2k_link: Option<String>,
    pub publication: crate::SharedFilePublicationStatus,
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
    /// One hash detail with retained storage/conversion ownership. All facts are
    /// cached metadata; unavailable copies never cause a filesystem probe.
    pub async fn library_file_detail(
        &self,
        hash: &str,
    ) -> Result<Option<RetainedRead<LibraryFileDetail>>> {
        crate::library_policy::validate_hash(hash)?;
        self.persistence_owner.check_coherent_state()?;
        let detail = self
            .ed2k_transfers
            .library_file_detail(hash)
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        let Some(detail) = detail else {
            return Ok(None);
        };
        let detail = detail
            .try_project_async(LIBRARY_FILE_DETAIL_BYTES, |detail| async move {
                let publication = self
                    .library_file_publication(
                        &detail.file.file_hash,
                        &detail.file.display_name,
                        detail.file.present && detail.file.sharing_enabled,
                    )
                    .await;
                let ed2k_link = detail.file.size_bytes.map(|size| {
                    let root = detail.aich_root.map(hex::encode);
                    crate::views::format_ed2k_file_link(
                        &detail.file.display_name,
                        size,
                        &detail.file.file_hash,
                        root.as_deref(),
                    )
                });
                Ok(LibraryFileDetail {
                    file: detail.file.into(),
                    upload_priority: if detail.auto_upload_priority {
                        "auto".to_owned()
                    } else {
                        detail.upload_priority
                    },
                    comment: detail.comment,
                    rating: detail.rating,
                    ed2k_link,
                    publication,
                })
            })
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        Ok(Some(detail))
    }

    /// Convert one bounded page while retaining source and conversion backing.
    pub async fn library_file_page(
        &self,
        query: LibraryFileQuery,
    ) -> Result<RetainedRead<LibraryFilePage>> {
        self.persistence_owner.check_coherent_state()?;
        let page = self
            .ed2k_transfers
            .library_file_page(query)
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        page.try_project(LIBRARY_FILE_PAGE_BYTES, |page| {
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
        self.persistence_owner.check_coherent_state()?;
        let file = self
            .ed2k_transfers
            .library_file(hash)
            .await
            .map_err(read_error)?;
        self.persistence_owner.check_coherent_state()?;
        let Some(file) = file else {
            return Ok(None);
        };
        file.try_project(LIBRARY_FILE_PAGE_BYTES, |file| Ok(file.into()))
            .map(Some)
            .map_err(read_error)
    }
}
