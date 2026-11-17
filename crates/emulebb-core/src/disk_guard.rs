//! Aggregate protected-volume policy for the bounded selected cohort.
use crate::{EmulebbCore, physical_disk::volume_key};
use anyhow::Result;
use emulebb_ed2k::{disk_space, ed2k_transfer::StorageSpaceReservation};
use emulebb_metadata::{DownloadIntent, DownloadJobStorageFailure, JobToken};
use std::{collections::HashMap, path::PathBuf};

#[derive(Debug)]
struct ProtectedVolume {
    probe_path: PathBuf,
    reserved_bytes: u64,
    free_floor_bytes: u64,
    required: bool,
}
fn reserve_on_volume_key(
    volumes: &mut HashMap<String, ProtectedVolume>,
    key: String,
    path: PathBuf,
    bytes: u64,
    floor: u64,
) {
    let volume = volumes.entry(key).or_insert(ProtectedVolume {
        probe_path: path,
        reserved_bytes: 0,
        free_floor_bytes: 0,
        required: false,
    });
    volume.reserved_bytes = volume.reserved_bytes.saturating_add(bytes);
    volume.free_floor_bytes = volume.free_floor_bytes.max(floor);
}
fn volume_is_insufficient(available: Option<u64>, reserved: u64, floor: u64) -> bool {
    available.is_none_or(|available| available < reserved.saturating_add(floor))
}
/// Runs only inside the native filesystem owner. Volume identification may
/// touch unavailable mounts, so it cannot execute on an async Core worker.
fn sufficient_storage(input: &[StorageSpaceReservation]) -> bool {
    let mut volumes = HashMap::new();
    for item in input {
        let key = volume_key(&item.path);
        reserve_on_volume_key(
            &mut volumes,
            key.clone(),
            item.path.clone(),
            item.bytes,
            item.floor,
        );
        if item.required {
            volumes.get_mut(&key).expect("inserted volume").required = true;
        }
    }
    volumes
        .values()
        .filter(|volume| volume.required)
        .all(|volume| {
            !volume_is_insufficient(
                disk_space::available_space(&volume.probe_path),
                volume.reserved_bytes,
                volume.free_floor_bytes,
            )
        })
}
impl EmulebbCore {
    #[must_use]
    pub fn with_profile_dir(mut self, profile_dir: PathBuf) -> Self {
        self.profile_dir = profile_dir;
        self
    }

    /// Reserve only selected jobs, including their delivery copies. A storage
    /// failure is durable and can be cleared only by an explicit start.
    pub(crate) async fn check_download_storage_space(&self, token: JobToken) -> Result<bool> {
        let settings = self.app_settings().await?.ed2k;
        let mut tokens: Vec<_> = self
            .download_attempts
            .snapshot()
            .into_iter()
            .map(|(token, _)| token)
            .collect();
        if !tokens.contains(&token) {
            tokens.push(token);
        }
        let mut input = Vec::with_capacity(1 + 2 * tokens.len());
        input.push(StorageSpaceReservation {
            path: self.profile_dir.clone(),
            bytes: 0,
            floor: settings.min_free_config_space_bytes,
            required: true,
        });
        let mut current = false;
        for selected in tokens {
            let Some(job) = self.ed2k_transfers.download_job(selected.job_id).await? else {
                continue;
            };
            if job.token != selected
                || job.removed_at_s.is_some()
                || job.completed_at_s.is_some()
                || job.storage_failure.is_some()
                || job.intent != DownloadIntent::Started
            {
                continue;
            }
            let required = selected == token;
            current |= required;
            let state = self.state.lock().await;
            let category = job.category_id.and_then(|id| state.categories.get(&id));
            let temp = job
                .selected_temp
                .clone()
                .or_else(|| {
                    category
                        .and_then(|category| category.temp_dir.as_ref())
                        .map(PathBuf::from)
                })
                .unwrap_or_else(|| self.transfer_root.clone());
            let incoming = category
                .and_then(|category| category.destination_dir.as_ref())
                .map(PathBuf::from)
                .unwrap_or_else(|| self.incoming_dir.clone());
            input.push(StorageSpaceReservation {
                path: temp,
                bytes: job
                    .expected_size_bytes
                    .unwrap_or(0)
                    .saturating_sub(job.checkpointed_bytes),
                floor: settings.min_free_transfer_space_bytes,
                required,
            });
            input.push(StorageSpaceReservation {
                path: incoming,
                bytes: job.expected_size_bytes.unwrap_or(0),
                floor: settings.min_free_incoming_space_bytes,
                required,
            });
        }
        if !current {
            return Ok(false);
        }
        if self
            .ed2k_transfers
            .inspect_storage_space(&input, sufficient_storage)
            .await?
        {
            return Ok(true);
        }
        let failure = DownloadJobStorageFailure::new(
            "STORAGE_SPACE_UNAVAILABLE",
            "protected storage is unavailable or cannot satisfy the free-space reservation",
            chrono::Utc::now().timestamp(),
        )?;
        let outcome = self
            .ed2k_transfers
            .fail_download_job_storage(token, &failure)
            .await?;
        if outcome.applied {
            self.download_attempts.cancel_execution(token);
        }
        Ok(false)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_reservation_honors_floor_and_unknown_space_fails_closed() {
        assert!(volume_is_insufficient(None, u64::MAX, u64::MAX));
        assert!(!volume_is_insufficient(Some(150), 100, 50));
        assert!(volume_is_insufficient(Some(149), 100, 50));
        assert!(volume_is_insufficient(Some(u64::MAX - 1), u64::MAX, 1));
    }

    #[test]
    fn reservations_sum_payloads_and_keep_the_largest_shared_volume_floor() {
        let mut volumes = HashMap::new();
        reserve_on_volume_key(
            &mut volumes,
            "shared".to_string(),
            PathBuf::from("profile"),
            0,
            10,
        );
        reserve_on_volume_key(
            &mut volumes,
            "shared".to_string(),
            PathBuf::from("transfers"),
            100,
            50,
        );
        reserve_on_volume_key(
            &mut volumes,
            "incoming".to_string(),
            PathBuf::from("incoming"),
            200,
            40,
        );

        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes["shared"].reserved_bytes, 100);
        assert_eq!(volumes["shared"].free_floor_bytes, 50);
        assert_eq!(volumes["incoming"].reserved_bytes, 200);
        assert_eq!(volumes["incoming"].free_floor_bytes, 40);
    }

    #[test]
    fn storage_inspection_fails_closed_at_an_unattainable_floor() {
        let input = [StorageSpaceReservation {
            path: std::env::temp_dir(),
            bytes: 1,
            floor: u64::MAX,
            required: true,
        }];
        assert!(!sufficient_storage(&input));
    }
}
