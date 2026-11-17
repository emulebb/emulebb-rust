//! Explicit complete-library sharing changes, ordered by the profile owner.
use crate::{EmulebbCore, LibraryReply, PersistenceError};
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct LibrarySharingRequest {
    pub enabled: bool,
    pub hashes: Vec<String>,
}
impl LibrarySharingRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        crate::library_policy::validate_hashes(&self.hashes)
    }
    pub(crate) fn payload_bytes(&self) -> Option<usize> {
        self.hashes
            .capacity()
            .checked_mul(std::mem::size_of::<String>())?
            .checked_add(
                self.hashes
                    .iter()
                    .try_fold(0usize, |sum, hash| sum.checked_add(hash.capacity()))?,
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryFileChange {
    Changed,
    Unchanged,
    NotFound,
}

#[derive(Debug)]
pub struct LibrarySharingOutcome {
    pub hash: String,
    pub outcome: std::result::Result<LibraryFileChange, PersistenceError>,
}

impl EmulebbCore {
    /// Validate before admission; admitted batches remain owned through commit,
    /// publication and all request-order outcomes after caller disconnect.
    pub async fn set_library_sharing(
        &self,
        request: &LibrarySharingRequest,
    ) -> Result<LibraryReply<Vec<LibrarySharingOutcome>>> {
        request.validate()?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .library_sharing(request, || Arc::clone(&self.ed2k_transfers))
            .await?)
    }
}
