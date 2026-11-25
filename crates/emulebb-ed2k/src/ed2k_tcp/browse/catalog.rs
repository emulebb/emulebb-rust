//! Connection-local virtual directories over verified complete and partial shares.

use std::ops::RangeInclusive;

use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::MetadataPeerBrowseView;
use sha2::{Digest, Sha256};

use crate::ed2k_tcp::codec::shared_browse::{
    BROWSE_MAX_PAYLOAD, BrowseReplyTooLarge, PeerBrowseEncoding, PeerBrowseFile,
    browse_file_entry_len,
};
use crate::ed2k_transfer::{ED2K_LEGACY_FILE_SIZE_MAX, Ed2kTransferRuntime};

const MAX_FILES: usize = 131_072;
const MAX_DIRECTORIES: usize = 8192;
const MAX_FILES_PER_DIRECTORY: usize = 512;
const DIRECTORY_LABEL_BYTES: usize = b"Shared 0001".len();
const DIRECTORY_HEADER_BYTES: usize = 2 + DIRECTORY_LABEL_BYTES + 4;
const INCOMPLETE_FILES: &[u8] = b"!Incomplete Files";

fn size_ceiling(peer: PeerBrowseEncoding) -> u64 {
    if peer.supports_large_files {
        u64::MAX
    } else {
        ED2K_LEGACY_FILE_SIZE_MAX
    }
}

fn browse_file(hash: [u8; 16], name: String, size: u64) -> PeerBrowseFile {
    // A backslash can be a literal Unix basename character but is a path
    // separator to Windows peers. Keep such a share browsable by its hash.
    let display_name =
        if name.is_empty() || name.contains(['/', '\\', '\0']) || name == "." || name == ".." {
            hex::encode(hash)
        } else {
            name
        };
    PeerBrowseFile {
        file_hash: Ed2kHash(hash),
        display_name,
        file_size: size,
    }
}

/// Collect a whole flat reply or report that the peer must use directories.
pub(super) async fn flat_files(
    runtime: &Ed2kTransferRuntime,
    peer: PeerBrowseEncoding,
) -> Result<Vec<PeerBrowseFile>> {
    let ((files, _), _) = runtime
        .read_peer_browse_catalog(
            MetadataPeerBrowseView::Flat,
            0..=i64::MAX,
            size_ceiling(peer),
            (Vec::new(), 4usize),
            move |(files, bytes), row| {
                let file = browse_file(row.hash, row.name, row.size);
                *bytes += browse_file_entry_len(&file, peer)?;
                if *bytes > BROWSE_MAX_PAYLOAD {
                    return Err(BrowseReplyTooLarge.into());
                }
                files.push(file);
                Ok(true)
            },
        )
        .await?;
    Ok(files)
}

struct Directory {
    ids: RangeInclusive<i64>,
    digest: [u8; 32],
}

#[derive(Default)]
pub(super) struct BrowseDirectories {
    labels: Vec<Vec<u8>>,
    directories: Vec<Directory>,
    incomplete: Option<IncompleteDirectory>,
}

enum IncompleteDirectory {
    Snapshot([u8; 32]),
    Oversized,
}

#[derive(Default)]
struct DirectoryBuilder {
    plan: BrowseDirectories,
    current: Option<RangeInclusive<i64>>,
    digest: Sha256,
    count: usize,
    bytes: usize,
    total_files: usize,
    partial_digest: Sha256,
    partial_bytes: usize,
}

// The digest is internal. Include all published data, with a length prefix
// for the variable field, so a changed name or membership invalidates the view.
fn observe(digest: &mut Sha256, file: &PeerBrowseFile) {
    digest.update(file.file_hash.0);
    digest.update(file.file_size.to_le_bytes());
    digest.update((file.display_name.len() as u64).to_le_bytes());
    digest.update(file.display_name.as_bytes());
}

impl DirectoryBuilder {
    fn add_partial(&mut self, file: &PeerBrowseFile, bytes: usize) -> bool {
        self.partial_bytes += bytes;
        if self.partial_bytes + 2 + INCOMPLETE_FILES.len() + 4 > BROWSE_MAX_PAYLOAD {
            // The partial stream is last. The magic label has one reply and
            // may be explicitly denied without discarding complete groups.
            self.plan.incomplete = Some(IncompleteDirectory::Oversized);
            return false;
        }
        observe(&mut self.partial_digest, file);
        true
    }

    fn finish(mut self, has_queue: bool) -> Result<BrowseDirectories> {
        self.finish_directory()?;
        if has_queue {
            if self.plan.labels.len() == MAX_DIRECTORIES {
                return Err(BrowseReplyTooLarge.into());
            }
            self.plan.labels.insert(0, INCOMPLETE_FILES.to_vec());
            if self.plan.incomplete.is_none() {
                self.plan.incomplete = Some(IncompleteDirectory::Snapshot(
                    self.partial_digest.finalize().into(),
                ));
            }
        }
        Ok(self.plan)
    }

    fn add(&mut self, id: i64, file: &PeerBrowseFile, bytes: usize) -> Result<()> {
        if self.total_files == MAX_FILES || DIRECTORY_HEADER_BYTES + bytes > BROWSE_MAX_PAYLOAD {
            return Err(BrowseReplyTooLarge.into());
        }
        if self.count == MAX_FILES_PER_DIRECTORY
            || DIRECTORY_HEADER_BYTES + self.bytes + bytes > BROWSE_MAX_PAYLOAD
        {
            self.finish_directory()?;
        }
        let first = self.current.as_ref().map_or(id, |ids| *ids.start());
        self.current = Some(first..=id);
        self.count += 1;
        self.total_files += 1;
        self.bytes += bytes;
        observe(&mut self.digest, file);
        Ok(())
    }

    fn finish_directory(&mut self) -> Result<()> {
        let Some(ids) = self.current.take() else {
            return Ok(());
        };
        let index = self.plan.directories.len() + 1;
        if index > MAX_DIRECTORIES {
            return Err(BrowseReplyTooLarge.into());
        }
        self.plan
            .labels
            .push(format!("Shared {index:04}").into_bytes());
        self.plan.directories.push(Directory {
            ids,
            digest: self.digest.finalize_reset().into(),
        });
        self.bytes = 0;
        self.count = 0;
        Ok(())
    }
}

impl BrowseDirectories {
    /// Build labels and bounded cursors from one verified SQLite snapshot.
    pub(super) async fn build(
        runtime: &Ed2kTransferRuntime,
        peer: PeerBrowseEncoding,
    ) -> Result<Self> {
        let (builder, has_queue) = runtime
            .read_peer_browse_catalog(
                MetadataPeerBrowseView::DirectoryList,
                0..=i64::MAX,
                size_ceiling(peer),
                DirectoryBuilder::default(),
                move |builder, row| {
                    let file = browse_file(row.hash, row.name, row.size);
                    let bytes = browse_file_entry_len(&file, peer)?;
                    if row.partial {
                        return Ok(builder.add_partial(&file, bytes));
                    }
                    builder.add(row.id, &file, bytes)?;
                    Ok(true)
                },
            )
            .await?;
        builder.finish(has_queue)
    }

    pub(super) fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// Recheck the selected range in a fresh verified snapshot. Additions,
    /// removals or renames inside this label require a new directory listing.
    pub(super) async fn files(
        &self,
        runtime: &Ed2kTransferRuntime,
        raw_label: &[u8],
        peer: PeerBrowseEncoding,
    ) -> Result<Option<Vec<PeerBrowseFile>>> {
        let (view, ids, expected, max_files) = if raw_label == INCOMPLETE_FILES {
            match self.incomplete.as_ref() {
                None => return Ok(None),
                Some(IncompleteDirectory::Oversized) => return Err(BrowseReplyTooLarge.into()),
                Some(IncompleteDirectory::Snapshot(digest)) => (
                    MetadataPeerBrowseView::IncompleteDirectory,
                    0..=i64::MAX,
                    digest,
                    MAX_FILES,
                ),
            }
        } else {
            let labels = &self.labels[usize::from(self.incomplete.is_some())..];
            let Ok(index) = labels.binary_search_by(|label| label.as_slice().cmp(raw_label)) else {
                return Ok(None);
            };
            let directory = &self.directories[index];
            (
                MetadataPeerBrowseView::CompleteDirectory,
                directory.ids.clone(),
                &directory.digest,
                MAX_FILES_PER_DIRECTORY,
            )
        };
        let ((files, digest, bytes), _) = runtime
            .read_peer_browse_catalog(
                view,
                ids,
                size_ceiling(peer),
                (Vec::new(), Sha256::new(), 2 + raw_label.len() + 4),
                move |(files, digest, bytes), row| {
                    let file = browse_file(row.hash, row.name, row.size);
                    *bytes += browse_file_entry_len(&file, peer)?;
                    if *bytes > BROWSE_MAX_PAYLOAD || files.len() == max_files {
                        // Mark stale even if the accepted prefix happens to match.
                        *bytes = BROWSE_MAX_PAYLOAD + 1;
                        return Ok(false);
                    }
                    observe(digest, &file);
                    files.push(file);
                    Ok(true)
                },
            )
            .await?;
        let actual: [u8; 32] = digest.finalize().into();
        Ok((bytes <= BROWSE_MAX_PAYLOAD && &actual == expected).then_some(files))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hundred_thousand_files_have_bounded_exactly_addressable_groups() {
        let mut builder = DirectoryBuilder::default();
        for id in 1..=100_000i64 {
            let mut hash = [0; 16];
            hash[..8].copy_from_slice(&id.to_le_bytes());
            let file = browse_file(hash, format!("Sample {id}.bin"), 42);
            builder.add(id, &file, 70).unwrap();
        }
        builder.finish_directory().unwrap();
        assert_eq!(builder.plan.labels.len(), 196);
        assert_eq!(builder.plan.labels[195], b"Shared 0196");
        assert_eq!(builder.plan.directories[0].ids, 1..=512);
        assert_eq!(builder.plan.directories[195].ids, 99841..=100000);
    }

    #[test]
    fn directory_byte_boundary_includes_raw_label_and_count() {
        let mut builder = DirectoryBuilder::default();
        let file = browse_file([1; 16], "Sample.bin".into(), 42);
        builder
            .add(1, &file, BROWSE_MAX_PAYLOAD - DIRECTORY_HEADER_BYTES)
            .unwrap();
        builder.add(2, &file, 70).unwrap();
        builder.finish_directory().unwrap();
        assert_eq!(builder.plan.labels[0], b"Shared 0001");
        assert_eq!(builder.plan.labels[1], b"Shared 0002");
        assert_eq!(builder.plan.directories[0].ids, 1..=1);
        assert_eq!(builder.plan.directories[1].ids, 2..=2);
    }

    #[test]
    fn incomplete_label_follows_queue_presence_even_when_empty() {
        assert!(
            DirectoryBuilder::default()
                .finish(false)
                .unwrap()
                .labels
                .is_empty()
        );
        let plan = DirectoryBuilder::default().finish(true).unwrap();
        assert_eq!(plan.labels(), &[INCOMPLETE_FILES.to_vec()]);
        assert!(matches!(
            plan.incomplete,
            Some(IncompleteDirectory::Snapshot(_))
        ));
    }

    #[test]
    fn oversized_incomplete_folder_preserves_the_complete_directory_plan() {
        let file = browse_file([1; 16], "Partial Sample.bin".into(), 64);
        let mut builder = DirectoryBuilder::default();
        builder.add(1, &file, 70).unwrap();
        let remaining = BROWSE_MAX_PAYLOAD - 2 - INCOMPLETE_FILES.len() - 4;
        assert!(builder.add_partial(&file, remaining));
        assert!(!builder.add_partial(&file, 1));
        let plan = builder.finish(true).unwrap();
        assert_eq!(
            plan.labels(),
            &[INCOMPLETE_FILES.to_vec(), b"Shared 0001".to_vec()]
        );
        assert!(matches!(
            plan.incomplete,
            Some(IncompleteDirectory::Oversized)
        ));
    }
}
