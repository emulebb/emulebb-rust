//! Selected execution backing, owned independently of cache membership and tasks.
use super::{Ed2kResumeManifest, LocalMutationError};
use anyhow::{Result, ensure};
use std::sync::{Arc, Mutex};

mod bytes;
pub(super) use bytes::ResidentBytes;

// WHY: maximum supported geometry for 18 selected jobs plus four existing
// mutation slots exceeds 64 MiB. The qualified fixed cap includes overlapping
// reader-pinned replacements; it never expands at runtime.
const MAX_BYTES: usize = 128 * 1024 * 1024;
pub(super) const MANIFEST_BYTES: usize = 6 * 1024 * 1024;

#[derive(Debug, Default)]
pub(super) struct ResidentControl {
    usage: Mutex<Usage>,
    capacity: Arc<super::local_mutation::capacity::CapacityControl>,
}
#[derive(Debug, Default)]
struct Usage {
    bytes: usize,
}
#[derive(Debug)]
pub(super) struct Reservation {
    control: Arc<ResidentControl>,
    job: emulebb_metadata::JobId,
    bytes: usize,
}
impl ResidentControl {
    pub(super) fn budget_snapshot(&self) -> (usize, usize, usize) {
        let used = self.usage.lock().map_or(MAX_BYTES, |usage| usage.bytes);
        (used, MAX_BYTES, MANIFEST_BYTES)
    }
    #[cfg(test)]
    pub(super) fn used_bytes(&self) -> usize {
        self.usage.lock().unwrap().bytes
    }

    pub(super) fn new(capacity: Arc<super::local_mutation::capacity::CapacityControl>) -> Self {
        Self {
            usage: Mutex::default(),
            capacity,
        }
    }

    /// Admit both budgets before constructing input or exposing a reservation.
    /// A rejected combined admission releases no credit and creates no wake.
    pub(super) fn reserve_with<T>(
        self: &Arc<Self>,
        job: emulebb_metadata::JobId,
        admit: impl FnOnce() -> Result<T>,
    ) -> Result<(Reservation, T)> {
        self.reserve_sized_with(job, MANIFEST_BYTES, admit)
    }

    /// Fixed bookkeeping backing uses its exact size, without taking a mutable
    /// manifest allowance. The shared resident ceiling owns its whole lifetime.
    pub(super) fn reserve_bookkeeping(
        self: &Arc<Self>,
        job: emulebb_metadata::JobId,
        bytes: usize,
    ) -> Result<Reservation> {
        self.reserve_sized_with(job, bytes, || Ok(()))
            .map(|(reservation, ())| reservation)
    }

    fn reserve_sized_with<T>(
        self: &Arc<Self>,
        job: emulebb_metadata::JobId,
        bytes: usize,
        admit: impl FnOnce() -> Result<T>,
    ) -> Result<(Reservation, T)> {
        ensure!(bytes <= MANIFEST_BYTES, LocalMutationError::TooLarge);
        let mut usage = self.usage.lock().map_err(|_| LocalMutationError::Unknown)?;
        ensure!(usage.bytes + bytes <= MAX_BYTES, LocalMutationError::Busy);
        let admission = admit()?;
        usage.bytes += bytes;
        Ok((
            Reservation {
                control: Arc::clone(self),
                job,
                bytes,
            },
            admission,
        ))
    }
    /// Admission precedes constructing the private streamed representation.
    pub(super) fn reserve(self: &Arc<Self>, job: emulebb_metadata::JobId) -> Result<Reservation> {
        self.reserve_with(job, || Ok(()))
            .map(|(reservation, ())| reservation)
    }

    /// Category copies cannot grow payload geometry. Prepare and settle this
    /// immutable replacement completely before the owning SQL transaction.
    pub(super) fn copy_category(
        self: &Arc<Self>,
        manifest: &Ed2kResumeManifest,
        category_id: Option<i64>,
    ) -> Result<ResidentManifest> {
        let (credit, ()) =
            self.reserve_sized_with(manifest.token.job_id, backing_bytes(manifest)?, || Ok(()))?;
        let mut copy = manifest.clone();
        copy.category_id = category_id;
        credit.publish(copy)
    }
    #[cfg(test)]
    pub(super) fn copy_manifest(
        self: &Arc<Self>,
        manifest: &Ed2kResumeManifest,
    ) -> Result<ResidentManifest> {
        let reservation = self.reserve(manifest.token.job_id)?;
        reservation.publish(manifest.clone())
    }
}
impl Reservation {
    fn copy(&self) -> Result<Self> {
        let mut usage = self
            .control
            .usage
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        ensure!(
            usage.bytes + MANIFEST_BYTES <= MAX_BYTES,
            LocalMutationError::Busy
        );
        usage.bytes += MANIFEST_BYTES;
        Ok(Self {
            control: Arc::clone(&self.control),
            job: self.job,
            bytes: MANIFEST_BYTES,
        })
    }
    /// Keep immutable backing charged at its retained capacity. Before any
    /// mutable access, restore the construction allowance so subsequent growth
    /// cannot spend bytes that have already been returned to the owner.
    fn resize(&mut self, bytes: usize) -> Result<()> {
        ensure!(bytes <= MANIFEST_BYTES, LocalMutationError::TooLarge);
        let mut usage = self
            .control
            .usage
            .lock()
            .map_err(|_| LocalMutationError::Unknown)?;
        let next = usage
            .bytes
            .checked_sub(self.bytes)
            .and_then(|current| current.checked_add(bytes))
            .ok_or(LocalMutationError::TooLarge)?;
        ensure!(next <= MAX_BYTES, LocalMutationError::Busy);
        let released = bytes < self.bytes;
        usage.bytes = next;
        self.bytes = bytes;
        drop(usage);
        if released {
            self.control.capacity.wake();
        }
        Ok(())
    }
    fn transfer_write_allowance(&mut self, credit: &mut Self) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.control, &credit.control) && self.job == credit.job,
            "resident write credit belongs to another job"
        );
        let growth = MANIFEST_BYTES - self.bytes;
        ensure!(
            credit.bytes >= growth,
            "resident write credit is incomplete"
        );
        // Both reservations already contribute to the same owner's usage.
        // Transfer the charge without another capacity admission after commit.
        self.bytes += growth;
        credit.bytes -= growth;
        Ok(())
    }
    pub(super) fn publish(mut self, manifest: Ed2kResumeManifest) -> Result<ResidentManifest> {
        self.resize(backing_bytes(&manifest)?)?;
        Ok(ResidentManifest(Arc::new(Allocation {
            manifest,
            reservation: self,
        })))
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.control
            .usage
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .bytes -= self.bytes;
        // WHY: readers may outlive cache eviction and task completion. Their
        // actual backing release must wake the existing admission waiters.
        self.control.capacity.wake();
    }
}
#[derive(Debug)]
struct Allocation {
    // Backing is dropped before its byte reservation.
    manifest: Ed2kResumeManifest,
    reservation: Reservation,
}

/// Cheap read pin. Eviction cannot release bytes still owned by any reader.
#[derive(Debug, Clone)]
pub struct ResidentManifest(Arc<Allocation>);
impl std::ops::Deref for ResidentManifest {
    type Target = Ed2kResumeManifest;
    fn deref(&self) -> &Self::Target {
        &self.0.manifest
    }
}
impl ResidentManifest {
    /// Apply a synchronous delta with credit admitted before durable mutation.
    /// Readers acquired during SQL cannot force a new post-commit admission.
    pub(super) fn write_with(
        &mut self,
        permit: Reservation,
        update: impl FnOnce(&mut Ed2kResumeManifest) -> Result<()>,
    ) -> Result<()> {
        let mut credit = Some(permit);
        if let Some(allocation) = Arc::get_mut(&mut self.0) {
            allocation
                .reservation
                .transfer_write_allowance(credit.as_mut().unwrap())?;
        } else {
            let reservation = credit.take().unwrap();
            ensure!(
                Arc::ptr_eq(&self.0.reservation.control, &reservation.control)
                    && self.0.reservation.job == reservation.job,
                "resident write credit belongs to another job"
            );
            self.0 = Arc::new(Allocation {
                manifest: self.0.manifest.clone(),
                reservation,
            });
        }
        let allocation = Arc::get_mut(&mut self.0).expect("unique admitted resident writer");
        let result = update(&mut allocation.manifest);
        // Settle even a rejected delta; unused credit remains live until this
        // synchronous update has finished and its replacement backing is charged.
        allocation
            .reservation
            .resize(backing_bytes(&allocation.manifest)?)?;
        result
    }
    pub(super) fn edit(self) -> Result<ResidentDraft> {
        self.try_edit_owned().map_err(|(_, error)| error)
    }
    pub(super) fn try_edit_owned(
        self,
    ) -> std::result::Result<ResidentDraft, (Self, anyhow::Error)> {
        let allocation = match Arc::try_unwrap(self.0) {
            Ok(allocation) => allocation,
            Err(allocation) => {
                let reservation = match allocation.reservation.copy() {
                    Ok(reservation) => reservation,
                    Err(error) => return Err((Self(allocation), error)),
                };
                Allocation {
                    manifest: allocation.manifest.clone(),
                    reservation,
                }
            }
        };
        Self::edit_unwrapped(allocation)
    }

    fn edit_unwrapped(
        mut allocation: Allocation,
    ) -> std::result::Result<ResidentDraft, (Self, anyhow::Error)> {
        // WHY: a reader can disappear before unwrap succeeds. Unique ownership
        // does not imply mutable credit; restore it at the owned frontier and
        // return an intact immutable pin if capacity cannot be admitted.
        if let Err(error) = allocation.reservation.resize(MANIFEST_BYTES) {
            return Err((Self(Arc::new(allocation)), error));
        }
        Ok(ResidentDraft(allocation))
    }
}
impl PartialEq for ResidentManifest {
    fn eq(&self, other: &Self) -> bool {
        self.0.manifest == other.0.manifest
    }
}
impl Eq for ResidentManifest {}
impl PartialEq<Ed2kResumeManifest> for ResidentManifest {
    fn eq(&self, other: &Ed2kResumeManifest) -> bool {
        self.0.manifest == *other
    }
}
impl serde::Serialize for ResidentManifest {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.0.manifest.serialize(serializer)
    }
}

#[derive(Debug)]
pub struct ResidentDraft(Allocation);
impl PartialEq for ResidentDraft {
    fn eq(&self, other: &Self) -> bool {
        self.0.manifest == other.0.manifest
    }
}
impl Eq for ResidentDraft {}
impl PartialEq<ResidentDraft> for ResidentManifest {
    fn eq(&self, other: &ResidentDraft) -> bool {
        self.0.manifest == other.0.manifest
    }
}
impl PartialEq<ResidentManifest> for ResidentDraft {
    fn eq(&self, other: &ResidentManifest) -> bool {
        self.0.manifest == other.0.manifest
    }
}

impl PartialEq<Ed2kResumeManifest> for ResidentDraft {
    fn eq(&self, other: &Ed2kResumeManifest) -> bool {
        self.0.manifest == *other
    }
}
impl serde::Serialize for ResidentDraft {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&self.0.manifest, serializer)
    }
}
impl std::ops::Deref for ResidentDraft {
    type Target = Ed2kResumeManifest;
    fn deref(&self) -> &Self::Target {
        &self.0.manifest
    }
}
impl std::ops::DerefMut for ResidentDraft {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0.manifest
    }
}
impl ResidentDraft {
    /// The admitted ordinary workspace now owns the compact command proposal.
    /// Retire full geometry before handing its existing credit to publication.
    pub(super) fn into_write_credit(self) -> Reservation {
        let Allocation {
            manifest,
            reservation,
        } = self.0;
        drop(manifest);
        reservation
    }
    pub(super) fn freeze(mut self) -> Result<ResidentManifest> {
        self.0
            .reservation
            .resize(backing_bytes(&self.0.manifest)?)?;
        Ok(ResidentManifest(Arc::new(self.0)))
    }
}

fn backing_bytes(manifest: &Ed2kResumeManifest) -> Result<usize> {
    let mut bytes = std::mem::size_of::<Allocation>() + 64;
    let mut add = |value: usize| -> Result<()> {
        bytes = bytes
            .checked_add(value)
            .ok_or(LocalMutationError::TooLarge)?;
        Ok(())
    };
    for text in [
        &manifest.file_hash,
        &manifest.display_name,
        &manifest.upload_priority,
        &manifest.comment,
    ] {
        add(text.capacity())?;
    }
    if let Some(root) = &manifest.aich_root {
        add(root.capacity())?;
    }
    for hashes in [&manifest.md4_hashset, &manifest.aich_hashset] {
        add(hashes
            .capacity()
            .checked_mul(std::mem::size_of::<String>())
            .ok_or(LocalMutationError::TooLarge)?)?;
        for hash in hashes {
            add(hash.capacity())?;
        }
    }
    add(manifest
        .pieces
        .capacity()
        .checked_mul(std::mem::size_of::<super::Ed2kPieceState>())
        .ok_or(LocalMutationError::TooLarge)?)?;
    for piece in &manifest.pieces {
        if let Some(bitmap) = &piece.block_bitmap {
            add(bitmap.capacity())?;
        }
    }
    add(manifest
        .verified_ranges
        .capacity()
        .checked_mul(std::mem::size_of::<super::Ed2kSharedRange>())
        .ok_or(LocalMutationError::TooLarge)?)?;
    if let Some(path) = &manifest.delivered_path {
        add(path.capacity())?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
