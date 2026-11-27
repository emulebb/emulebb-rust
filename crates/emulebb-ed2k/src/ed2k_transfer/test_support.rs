use std::path::Path;

use emulebb_metadata::MetadataSharedDirectoryRoot;

use super::Ed2kTransferRuntime;

impl Ed2kTransferRuntime {
    pub(crate) fn recovery_payload_reads(&self) -> usize {
        self.raw_part_read_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Mark manually staged corrupt bytes as recovery-eligible, as a failed
    /// piece flush does in a live session.
    pub(super) async fn mark_fixture_part_corrupt(
        &self,
        token: emulebb_metadata::JobToken,
        part: u16,
    ) {
        let guard = self.lock_manifest(token).await;
        let mut manifest = self
            .load_manifest_unlocked(token)
            .await
            .unwrap()
            .edit()
            .unwrap();
        manifest.pieces[usize::from(part)].ich_corrupted = true;
        self.store_manifest_unlocked(&manifest, guard)
            .await
            .unwrap();
    }

    /// Run the ordinary reservation-to-commit path in a storage fixture.
    pub(super) async fn begin_part_salvage(
        &self,
        token: emulebb_metadata::JobToken,
        part: u16,
        master: [u8; 20],
        body: &[u8],
    ) -> anyhow::Result<Option<super::salvage::PartSalvageOutcome>> {
        let peer = std::net::SocketAddr::from(([192, 0, 2, 1], 4662));
        let Some(request) = self.reserve_aich_recovery(token, part, peer, None).await? else {
            return Ok(None);
        };
        if request.master() != master {
            return Ok(None);
        }
        self.salvage_requested_part(request, body).await
    }
}

/// Construct a stock recovery response from synthetic sharer-side bytes.
pub(crate) fn recovery_answer_for_part(data: &[u8], part: u64) -> ([u8; 20], Vec<u8>) {
    let mut tree = super::aich_recovery::AichRecoveryHashSet::new(data.len() as u64);
    tree.build_from_data(data).unwrap();
    (
        tree.master_hash(),
        tree.create_part_recovery_data(part).unwrap(),
    )
}

/// Admit a fully hashed fixture through a real root and refresh its live offer.
pub(crate) async fn admit_local_share(runtime: &Ed2kTransferRuntime, root: &Path, path: &Path) {
    let mut metadata = runtime.metadata.clone();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            watch_enabled: false,
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let path = crate::long_path::long_path(path);
    let fingerprint = metadata
        .local_file_instance(&path)
        .unwrap()
        .expect("fixture must be fully hashed before root admission")
        .verified_fingerprint;
    let relative = path
        .strip_prefix(crate::long_path::long_path(root))
        .unwrap();
    assert!(
        metadata
            .admit_local_path_to_root(root, &path, relative, &fingerprint)
            .unwrap()
    );
    runtime.refresh_complete_shared_catalog().await.unwrap();
}

/// Allocate a real job ID/generation and persist its selected temp before the
/// runtime fixture creates storage. This never reintroduces a hash-keyed API.
pub(crate) fn admit_download_job(
    runtime: &Ed2kTransferRuntime,
    hash: emulebb_kad_proto::Ed2kHash,
    display_name: String,
    size: u64,
) -> super::Ed2kTransferJob {
    admit_download_job_with_piece_size(runtime, hash, display_name, size, super::ED2K_PART_SIZE)
}

/// Admit compact geometry for private reconciliation tests without inventing tokens.
pub(crate) fn admit_download_job_with_piece_size(
    runtime: &Ed2kTransferRuntime,
    hash: emulebb_kad_proto::Ed2kHash,
    display_name: String,
    size: u64,
    piece_size: u64,
) -> super::Ed2kTransferJob {
    let admitted = runtime
        .metadata
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: hash.to_string(),
            display_name,
            expected_size_bytes: Some(size),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size,
        })
        .unwrap()
        .job;
    let current = if admitted.storage.is_some() {
        admitted
    } else {
        runtime
            .metadata
            .start_download_job(admitted.token, &runtime.root_dir)
            .unwrap()
            .unwrap()
    };
    let mut job = super::new_transfer_job(current.token, hash, current.display_name, size);
    job.piece_size = piece_size;
    job
}

/// Give pure protocol fixtures a real profile-scoped job without allocating payload storage.
/// Keep the returned store alive for the lifetime of the callbacks under test.
pub(crate) fn admit_protocol_job(
    hash: emulebb_kad_proto::Ed2kHash,
) -> (emulebb_metadata::MetadataStore, emulebb_metadata::JobToken) {
    let (store, job) = admit_unallocated_job(hash, "protocol.bin".into(), 16);
    (store, job.token)
}

/// Real admission for pure model/codec tests that never touch payload storage.
/// Zero-sized codec cases use an unknown claim and are never executable jobs.
pub(crate) fn admit_unallocated_job(
    hash: emulebb_kad_proto::Ed2kHash,
    display_name: String,
    size: u64,
) -> (emulebb_metadata::MetadataStore, super::Ed2kTransferJob) {
    let store = emulebb_metadata::MetadataStore::in_memory().unwrap();
    let row = store
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: hash.to_string(),
            display_name,
            expected_size_bytes: (size != 0).then_some(size),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Started,
            piece_size: super::ED2K_PART_SIZE,
        })
        .unwrap()
        .job;
    let job = super::new_transfer_job(row.token, hash, row.display_name, size);
    (store, job)
}

/// Synthetic catalog membership for queue-algorithm fixtures. This grants no
/// physical payload authority; protocol-serving fixtures use verified files.
pub(crate) async fn seed_upload_queue_catalog(
    runtime: &Ed2kTransferRuntime,
    hashes: &[emulebb_kad_proto::Ed2kHash],
) {
    let mut catalog = runtime.shared_catalog.write().await;
    for hash in hashes {
        catalog.upsert_verified(
            *hash,
            Some(super::Ed2kSharedEntry {
                file_hash: hash.to_string(),
                display_name: "Sample Queue.bin".into(),
                file_size: 1024,
                verified_complete: true,
                verified_ranges: Vec::new(),
                compatibility_hint: false,
                source_count_hint: None,
                aich_root: None,
                upload_priority: "normal".into(),
                auto_upload_priority: false,
                comment: String::new(),
                rating: 0,
                media: Default::default(),
                all_time_uploaded_bytes: 0,
                complete_parts: Vec::new(),
                publish: Default::default(),
            }),
        );
    }
}
