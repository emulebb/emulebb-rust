//! Cached copy resources, independent of upload permission and file execution.

use crate::EmulebbCore;
use anyhow::Result;
use emulebb_ed2k::ed2k_transfer::RetainedRead;
use serde::Serialize;

/// Includes path conversion and conservative JSON encoding headroom.
pub const LIBRARY_LOCATION_PAGE_BYTES: usize = emulebb_metadata::LIBRARY_READ_MAX_BYTES;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryLocation {
    pub path: String,
    /// Cached verification under an accessible configured root. Sharing policy
    /// remains independent, and this observation never grants payload access.
    pub present: bool,
}

pub struct LibraryLocationPage {
    pub locations: Vec<LibraryLocation>,
    pub next_after: Option<i64>,
}

impl EmulebbCore {
    /// Return retained path observations without filesystem probes or hydration.
    /// None means the hash is outside the client library; a copyless hash has
    /// an empty page, including unfinished accepted downloads.
    pub async fn library_locations(
        &self,
        hash: &str,
        after: i64,
        limit: usize,
    ) -> Result<Option<RetainedRead<LibraryLocationPage>>> {
        self.persistence_owner.check_coherent_state()?;
        let page = self
            .ed2k_transfers
            .library_locations(hash, after, limit)
            .await?;
        // WHY: an unrelated profile commit can fault while this worker reads.
        // Preserve the common fault outcome even for an absent hash, rather
        // than presenting an unreconciled profile as authoritative library data.
        self.persistence_owner.check_coherent_state()?;
        let Some(page) = page else {
            return Ok(None);
        };
        page.try_project(LIBRARY_LOCATION_PAGE_BYTES, |page| {
            let locations = page
                .locations
                .into_iter()
                .map(|location| {
                    let present = location.verified_in_session
                        && location.root_configured
                        && location.root_accessible
                        && !location.identity_excluded;
                    LibraryLocation {
                        path: emulebb_metadata::NativePath::from(location.path).display_path(),
                        present,
                    }
                })
                .collect();
            Ok(LibraryLocationPage {
                locations,
                next_after: page.next_after,
            })
        })
        .map(Some)
    }
}
