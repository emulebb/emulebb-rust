//! Finished-file delivery wiring (core side).
//!
//! When a transfer completes, the eD2K runtime materializes its internal piece
//! store into an operator-facing file by name (see
//! `emulebb_ed2k::ed2k_transfer::deliver`). This module resolves WHERE that file
//! lands — a per-category download path when set, otherwise the global incoming
//! directory (eMule per-category Incoming override, else the global Incoming
//! folder) — and drives delivery at completion, on a confirming recheck, and as
//! a startup sweep for transfers that finished before delivery ran.

use std::path::{Path, PathBuf};

use emulebb_ed2k::ed2k_transfer::{Ed2kDeliveryOutcome, Ed2kResumeManifest};

use crate::EmulebbCore;

impl EmulebbCore {
    /// Override the default finished-file delivery directory (eMule global
    /// Incoming folder). The daemon calls this with the resolved `incomingDir`
    /// config path before wrapping the core in an `Arc`.
    #[must_use]
    pub fn with_incoming_dir(mut self, incoming_dir: PathBuf) -> Self {
        self.incoming_dir = incoming_dir;
        self
    }

    /// The configured finished-file delivery directory.
    #[must_use]
    pub fn incoming_dir(&self) -> &Path {
        &self.incoming_dir
    }

    /// Resolve the delivery destination directory for one completed transfer:
    /// its category's path when set, otherwise the global incoming directory.
    async fn delivery_destination_dir(&self, manifest: &Ed2kResumeManifest) -> PathBuf {
        if manifest.category_id != 0 {
            let state = self.state.lock().await;
            if let Some(path) = state
                .categories
                .get(&manifest.category_id)
                .and_then(|category| category.path.clone())
                .filter(|path| !path.trim().is_empty())
            {
                return PathBuf::from(path);
            }
        }
        self.incoming_dir.clone()
    }

    /// Materialize one completed transfer's payload into its destination by name
    /// (eMule move-to-Incoming). Idempotent: a no-op once delivered. Logs and
    /// swallows errors so a delivery failure never aborts the download task; the
    /// next completion/startup pass retries while `delivered_path` stays unset.
    pub(crate) async fn deliver_completed_transfer(&self, hash: &str) {
        let manifest = match self.ed2k_transfers.manifest(hash).await {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(%error, "delivery skipped: no manifest for {hash}");
                return;
            }
        };
        if !manifest.completed {
            return;
        }
        // A shared, already-complete file is seeded IN PLACE from its original
        // on-disk path; it was never downloaded, so it must NEVER be delivered
        // (copied) into the incoming dir. Delivery is download-only.
        if manifest.source_path.is_some() {
            return;
        }
        let dest_dir = self.delivery_destination_dir(&manifest).await;
        match self
            .ed2k_transfers
            .materialize_completed_payload(hash, &dest_dir)
            .await
        {
            Ok(Ed2kDeliveryOutcome::Delivered(path)) => {
                tracing::info!("delivered completed transfer {hash} to {}", path.display());
            }
            Ok(Ed2kDeliveryOutcome::AlreadyDelivered(_) | Ed2kDeliveryOutcome::NotCompleted) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to deliver completed transfer {hash}");
            }
        }
    }

    /// Deliver every completed-but-undelivered transfer (startup sweep). Covers
    /// transfers that completed before this build added delivery, and the
    /// crash-after-complete-before-deliver window. Best-effort per transfer.
    pub async fn deliver_pending_completed_transfers(&self) {
        let manifests = match self.ed2k_transfers.manifests().await {
            Ok(manifests) => manifests,
            Err(error) => {
                tracing::warn!(%error, "startup delivery sweep skipped: failed to list transfers");
                return;
            }
        };
        for manifest in manifests {
            // Skip share-in-place files (seeded from their original path, never
            // downloaded): they are not delivery candidates.
            if manifest.completed
                && manifest.delivered_path.is_none()
                && manifest.source_path.is_none()
            {
                self.deliver_completed_transfer(&manifest.file_hash).await;
            }
        }
    }
}
