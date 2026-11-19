//! Bounded filesystem execution for Core's aggregate free-space policy.
use super::*;
use crate::ed2k_transfer as transfer;
use std::path::PathBuf;

/// One protected path. Core owns reservation/floor policy; the native owner
/// owns blocking filesystem execution, admission, cancellation and shutdown.
#[derive(Debug, Clone)]
pub struct StorageSpaceReservation {
    pub path: PathBuf,
    pub bytes: u64,
    pub floor: u64,
    pub required: bool,
}
const INPUT_BYTES: usize = 512 * 1024;
const WORKSPACE: usize = 2 * 1024 * 1024;
impl LocalMutationRegistry {
    fn submit_storage_inspection(
        &self,
        input: &[StorageSpaceReservation],
        evaluate: fn(&[StorageSpaceReservation]) -> bool,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        ensure!(
            (1..=37).contains(&input.len()),
            LocalMutationError::TooLarge
        );
        let bytes = input
            .iter()
            .try_fold(std::mem::size_of_val(input), |bytes, value| {
                ensure!(
                    value.path.is_absolute(),
                    "storage probe path must be absolute"
                );
                bytes
                    .checked_add(value.path.capacity())
                    .ok_or_else(|| anyhow::anyhow!(LocalMutationError::TooLarge))
            })?;
        ensure!(bytes <= INPUT_BYTES, LocalMutationError::TooLarge);
        let mut state = self.state.lock().map_err(|_| LocalMutationError::Unknown)?;
        LocalMutationRegistry::reap(&mut state);
        let lease = LocalMutationRegistry::reserve_unit(
            &mut state,
            INPUT_BYTES * 2 + WORKSPACE,
            true,
            false,
        )?;
        let input = input.to_vec();
        let (sender, receipt) = oneshot::channel();
        LocalMutationRegistry::spawn_unit(&mut state, lease, move |lease| {
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool> {
                    lease.enter_filesystem(bytes, WORKSPACE)?;
                    let sufficient = evaluate(&input);
                    #[cfg(test)]
                    lease.pause_after_probe();
                    Ok(sufficient)
                }));
            let (result, outcome) = match result {
                Ok(result) => (result, 0),
                Err(_) => (Err(LocalMutationError::Unknown.into()), 2),
            };
            let _ = sender.send(result);
            outcome
        });
        Ok(receipt)
    }
}
impl transfer::Ed2kTransferRuntime {
    /// Execute a static policy function under the existing filesystem owner.
    /// The evaluator must stay within WORKSPACE, cannot capture Core/runtime
    /// handles and must not wait for another admission. A disconnected caller
    /// does not release capacity while native filesystem work is still running.
    pub async fn inspect_storage_space(
        &self,
        input: &[StorageSpaceReservation],
        evaluate: fn(&[StorageSpaceReservation]) -> bool,
    ) -> Result<bool> {
        self.local_mutations
            .submit_storage_inspection(input, evaluate)?
            .await
            .map_err(|_| LocalMutationError::Unknown)?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn probe_caller_disconnect_retains_filesystem_capacity_until_owner_finishes() {
        let root = tempfile::tempdir().unwrap();
        let runtime = Arc::new(transfer::Ed2kTransferRuntime::load_or_create(root.path()).unwrap());
        let capacity = Arc::clone(&runtime.local_mutations.state.lock().unwrap().capacity);
        let (reached, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        capacity.install_probe_gate(reached, gate);
        let input = vec![StorageSpaceReservation {
            path: root.path().to_owned(),
            bytes: 0,
            floor: 0,
            required: true,
        }];
        let worker_runtime = Arc::clone(&runtime);
        let mut caller =
            tokio::spawn(
                async move { worker_runtime.inspect_storage_space(&input, |_| true).await },
            );
        tokio::select! {
            result=&mut caller => panic!("probe finished before reaching the filesystem gate: {result:?}"),
            result=ready => result.unwrap(),
        }
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(capacity.usage().long_fs_units, 1);
        assert_eq!(capacity.usage().long_fs_bytes, WORKSPACE);
        release.send(()).unwrap();
        runtime.local_mutations.seal_and_drain().await.unwrap();
        assert_eq!(capacity.usage().bytes, 0);
        assert_eq!(capacity.usage().long_fs_units, 0);
    }
}
