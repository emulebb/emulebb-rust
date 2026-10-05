//! Aggregate protected-volume download free-space policy.
//!
//! Before a download attempt engages sources, check that the transfer-root
//! volume can hold the remaining payload. If it cannot, active downloads enter
//! the explicit `insufficient` state
//! instead of running and failing late mid-write with a disk-full error (which
//! would otherwise churn-retry). Best-effort: an unknowable free space or
//! manifest never pauses (the write path stays the final authority).

use std::{collections::HashMap, path::PathBuf};

use emulebb_ed2k::{disk_space, ed2k_transfer::Ed2kResumeManifest};
use emulebb_settings::Ed2kSettings;

use crate::{EmulebbCore, physical_disk::volume_key};

#[derive(Debug)]
struct ProtectedVolume {
    probe_path: PathBuf,
    reserved_bytes: u64,
    free_floor_bytes: u64,
}

fn reserve_on_volume(
    volumes: &mut HashMap<String, ProtectedVolume>,
    path: PathBuf,
    bytes: u64,
    floor: u64,
) {
    let key = volume_key(&path);
    let volume = volumes.entry(key).or_insert_with(|| ProtectedVolume {
        probe_path: path,
        reserved_bytes: 0,
        free_floor_bytes: 0,
    });
    volume.reserved_bytes = volume.reserved_bytes.saturating_add(bytes);
    volume.free_floor_bytes = volume.free_floor_bytes.max(floor);
}

fn volume_is_insufficient(available: Option<u64>, reserved: u64, floor: u64) -> bool {
    available.is_some_and(|available| available < reserved.saturating_add(floor))
}

impl EmulebbCore {
    async fn mark_active_downloads_insufficient(&self) {
        let (updated, cancellations) = {
            let mut state = self.state.lock().await;
            let mut updated = Vec::new();
            for transfer in state.transfers.values_mut() {
                if matches!(transfer.state.as_str(), "downloading" | "queued") && !transfer.stopped
                {
                    transfer.state = "insufficient".to_string();
                    updated.push(transfer.clone());
                }
            }
            let cancellations = state
                .download_cancels
                .values()
                .map(|(_, cancel)| cancel.clone())
                .collect::<Vec<_>>();
            (updated, cancellations)
        };
        for cancel in cancellations {
            cancel.cancel();
        }
        for transfer in updated {
            self.publish_transfer_updated(transfer);
        }
    }

    /// Requeue downloads held by the aggregate free-space guard once all
    /// protected volumes can satisfy their reservations again.
    pub async fn retry_insufficient_downloads(&self) -> usize {
        let candidates = {
            let state = self.state.lock().await;
            state
                .transfers
                .values()
                .filter(|transfer| transfer.state == "insufficient" && !transfer.stopped)
                .cloned()
                .collect::<Vec<_>>()
        };
        let Some(first) = candidates.first() else {
            return 0;
        };
        if self.should_pause_download_for_disk_space(&first.hash).await {
            return 0;
        }

        let mut requeued = 0usize;
        for candidate in candidates {
            let transfer = {
                let mut state = self.state.lock().await;
                let Some(transfer) = state.transfers.get_mut(&candidate.hash) else {
                    continue;
                };
                if transfer.state != "insufficient" || transfer.stopped {
                    continue;
                }
                transfer.state = "downloading".to_string();
                transfer.clone()
            };
            self.publish_transfer_updated(transfer.clone());
            self.queue_ed2k_download_attempt(transfer);
            requeued = requeued.saturating_add(1);
        }
        requeued
    }

    /// Whether any protected volume cannot satisfy all incomplete downloads
    /// plus its configured free-space floor. This is intentionally global:
    /// files sharing one volume are stopped as a group instead of each one
    /// independently believing the same free bytes are available.
    pub(crate) async fn should_pause_download_for_disk_space(&self, _file_hash: &str) -> bool {
        let Ok(manifests) = self.ed2k_transfers.incomplete_manifests().await else {
            return false;
        };
        let settings = self
            .app_settings()
            .await
            .map(|settings| settings.ed2k)
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "failed to load disk-space settings; using defaults");
                Ed2kSettings::default()
            });
        let categories = self.state.lock().await.categories.clone();
        let transfer_volume = volume_key(&self.transfer_root);
        let mut volumes = HashMap::new();

        for manifest in &manifests {
            self.reserve_incomplete_manifest(
                &mut volumes,
                manifest,
                &settings,
                &categories,
                &transfer_volume,
            );
        }

        let insufficient = volumes.into_iter().any(|(key, volume)| {
            let available = disk_space::available_space(&volume.probe_path);
            let insufficient =
                volume_is_insufficient(available, volume.reserved_bytes, volume.free_floor_bytes);
            if insufficient {
                tracing::warn!(
                    volume = %key,
                    available_bytes = available.unwrap_or(0),
                    reserved_bytes = volume.reserved_bytes,
                    free_floor_bytes = volume.free_floor_bytes,
                    "protected download volume has insufficient free space"
                );
            }
            insufficient
        });
        if insufficient {
            self.mark_active_downloads_insufficient().await;
        }
        insufficient
    }

    fn reserve_incomplete_manifest(
        &self,
        volumes: &mut HashMap<String, ProtectedVolume>,
        manifest: &Ed2kResumeManifest,
        settings: &Ed2kSettings,
        categories: &std::collections::BTreeMap<u32, crate::Category>,
        transfer_volume: &str,
    ) {
        if manifest.completed || manifest.source_path.is_some() {
            return;
        }
        let remaining = manifest
            .file_size
            .saturating_sub(manifest.durable_present_bytes());
        reserve_on_volume(
            volumes,
            self.transfer_root.clone(),
            remaining,
            settings.min_free_transfer_space_bytes,
        );

        let destination = categories
            .get(&manifest.category_id)
            .and_then(|category| category.path.as_deref())
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| self.incoming_dir.clone());
        if volume_key(&destination) == transfer_volume {
            // Same-volume delivery is a no-copy hard link, but the volume must
            // still honor the stricter of the two operator floors.
            reserve_on_volume(
                volumes,
                self.transfer_root.clone(),
                0,
                settings.min_free_incoming_space_bytes,
            );
        } else {
            // Cross-volume delivery needs a second full payload while the
            // verified part file remains the upload authority.
            reserve_on_volume(
                volumes,
                destination,
                manifest.file_size,
                settings.min_free_incoming_space_bytes,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppSettingsUpdate, FileIndex, TransferCreate, unique_runtime_dir};
    use emulebb_settings::Ed2kSettingsUpdate;

    #[test]
    fn aggregate_reservation_honors_floor_and_unknown_space_is_best_effort() {
        assert!(!volume_is_insufficient(None, u64::MAX, u64::MAX));
        assert!(!volume_is_insufficient(Some(150), 100, 50));
        assert!(volume_is_insufficient(Some(149), 100, 50));
        assert!(volume_is_insufficient(Some(u64::MAX - 1), u64::MAX, 1));
    }

    #[tokio::test]
    async fn insufficient_volume_stops_all_active_downloads() {
        let root = unique_runtime_dir("emulebb-disk-stop-all");
        let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), &root).unwrap();
        let hashes = [
            "00112233445566778899aabbccddeeff",
            "ffeeddccbbaa99887766554433221100",
        ];
        for (index, hash) in hashes.iter().enumerate() {
            let transfer = core
                .create_transfer(TransferCreate {
                    link: Some(format!("ed2k://|file|disk-{index}.bin|1024|{hash}|/")),
                    links: None,
                    category_id: None,
                    category_name: None,
                    paused: Some(true),
                })
                .await
                .unwrap();
            core.set_transfer_state(&transfer.hash, "downloading").await;
        }
        core.update_app_settings(AppSettingsUpdate {
            ed2k: Some(Ed2kSettingsUpdate {
                min_free_transfer_space_bytes: Some(u64::MAX),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .unwrap();

        assert!(core.should_pause_download_for_disk_space(hashes[0]).await);
        for hash in hashes {
            assert_eq!(core.transfer(hash).await.unwrap().state, "insufficient");
        }
    }
}
