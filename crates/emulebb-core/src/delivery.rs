//! Finished-file delivery wiring (core side).
//!
//! When a transfer completes, the eD2K runtime materializes its internal piece
//! store into an operator-facing file by name (see
//! `emulebb_ed2k::ed2k_transfer::deliver`). This module resolves WHERE that file
//! lands — a per-category download path when set, otherwise the global incoming
//! directory (eMule per-category Incoming override, else the global Incoming
//! folder) — and drives delivery at completion, on a confirming recheck, and as
//! a startup sweep for transfers that finished before delivery ran.

use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use emulebb_ed2k::ed2k_transfer::{Ed2kDeliveryOutcome, Ed2kResumeManifest};

use crate::EmulebbCore;

const DELIVERY_RETRY_INITIAL: Duration = Duration::from_secs(30);
const DELIVERY_RETRY_MAX: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone)]
pub(crate) struct DeliveryFailure {
    pub(crate) message: String,
    attempts: u32,
    retry_at: Instant,
}

impl DeliveryFailure {
    fn next(message: String, previous: Option<&Self>) -> Self {
        let attempts = previous.map_or(1, |failure| failure.attempts.saturating_add(1));
        let shift = attempts.saturating_sub(1).min(5);
        let delay = DELIVERY_RETRY_INITIAL
            .checked_mul(1u32 << shift)
            .unwrap_or(DELIVERY_RETRY_MAX)
            .min(DELIVERY_RETRY_MAX);
        Self {
            message,
            attempts,
            retry_at: Instant::now() + delay,
        }
    }

    fn is_due(&self) -> bool {
        Instant::now() >= self.retry_at
    }
}

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
    /// records errors so a delivery failure never aborts the verified payload;
    /// the retry worker keeps the transfer in `completing` until it succeeds.
    pub(crate) async fn deliver_completed_transfer(&self, hash: &str) {
        let manifest = match self.ed2k_transfers.manifest(hash).await {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(%error, "delivery skipped: no manifest for {hash}");
                return;
            }
        };
        if !manifest.completed || manifest.final_rehash_pending {
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
                self.delivery_failures.lock().unwrap().remove(hash);
                tracing::info!("delivered completed transfer {hash} to {}", path.display());
                if let Ok(Some(transfer)) = self.refresh_transfer_from_manifest_default(hash).await
                {
                    self.publish_transfer_updated(transfer);
                }
            }
            Ok(Ed2kDeliveryOutcome::AlreadyDelivered(_)) => {
                self.delivery_failures.lock().unwrap().remove(hash);
                if let Ok(Some(transfer)) = self.refresh_transfer_from_manifest_default(hash).await
                {
                    self.publish_transfer_updated(transfer);
                }
            }
            Ok(Ed2kDeliveryOutcome::NotCompleted) => {}
            Err(error) => {
                let message = format!("{error:#}");
                {
                    let mut failures = self.delivery_failures.lock().unwrap();
                    let failure = DeliveryFailure::next(message, failures.get(hash));
                    failures.insert(hash.to_string(), failure);
                }
                tracing::warn!(%error, "failed to deliver completed transfer {hash}");
                let _ = self
                    .refresh_transfer_from_manifest(hash, "completing")
                    .await;
            }
        }
    }

    /// Deliver every completed-but-undelivered transfer (startup sweep). Covers
    /// transfers that completed before this build added delivery, and the
    /// crash-after-complete-before-deliver window. Best-effort per transfer.
    pub async fn deliver_pending_completed_transfers(&self) {
        let hashes = match self
            .ed2k_transfers
            .pending_completed_delivery_hashes()
            .await
        {
            Ok(hashes) => hashes,
            Err(error) => {
                tracing::warn!(%error, "startup delivery sweep skipped: failed to list candidates");
                return;
            }
        };
        for hash in hashes {
            let due = self
                .delivery_failures
                .lock()
                .unwrap()
                .get(&hash)
                .is_none_or(DeliveryFailure::is_due);
            if !due {
                continue;
            }
            self.deliver_completed_transfer(&hash).await;
            tokio::task::yield_now().await;
        }
    }
}
