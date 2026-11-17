//! Shared bounded library selections and retained public replies.
use crate::persistence_owner::ByteLease;
use anyhow::{Result, ensure};
use serde::{Serialize, Serializer};

pub(crate) const RESULT_BYTES: usize = 64 * 1024;

pub(crate) fn validate_hash(hash: &str) -> Result<()> {
    ensure!(
        hash.len() == 32
            && !hash.bytes().any(|b| b.is_ascii_uppercase())
            && hex::decode_to_slice(hash, &mut [0u8; 16]).is_ok(),
        "hash must be 32 lowercase hexadecimal characters"
    );
    Ok(())
}

pub(crate) fn validate_hashes(hashes: &[String]) -> Result<()> {
    ensure!(
        (1..=100).contains(&hashes.len()),
        "library changes require 1..100 hashes"
    );
    let mut seen = std::collections::HashSet::with_capacity(hashes.len());
    for hash in hashes {
        validate_hash(hash)?;
        ensure!(seen.insert(hash), "library changes require distinct hashes");
    }
    Ok(())
}

/// The existing owner charges backing storage until serialization or caller drop.
pub struct LibraryReply<T> {
    pub(crate) value: T,
    pub(crate) lease: ByteLease,
}

impl<T> LibraryReply<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Project a bounded response without releasing its retained owner charge.
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> LibraryReply<U> {
        LibraryReply {
            value: project(self.value),
            lease: self.lease,
        }
    }
}

impl<T: Serialize> Serialize for LibraryReply<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}
