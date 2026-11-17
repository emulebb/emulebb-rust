//! Bounded tag resources; public identities are names, never SQL row IDs.
use crate::{EmulebbCore, persistence_owner::ByteLease};
use anyhow::{Result, ensure};
use serde::{Serialize, Serializer};

#[derive(Debug, Clone)]
pub enum LibraryTagRequest {
    Create(String),
    Get(String),
    Delete(String),
    Page {
        hash: Option<String>,
        after: Option<String>,
        limit: usize,
    },
    Change {
        tag: String,
        hashes: Vec<String>,
        assigned: bool,
    },
}

impl LibraryTagRequest {
    pub(crate) fn validate(&self) -> Result<()> {
        let name = |name: &str| -> Result<()> {
            if !crate::valid_category_name(name) {
                return Err(emulebb_metadata::LibraryTagError::InvalidName.into());
            }
            Ok(())
        };
        let hash = |hash: &str| -> Result<()> {
            ensure!(
                hash.len() == 32
                    && !hash.bytes().any(|b| b.is_ascii_uppercase())
                    && hex::decode_to_slice(hash, &mut [0u8; 16]).is_ok(),
                "hash must be 32 lowercase hexadecimal characters"
            );
            Ok(())
        };
        match self {
            Self::Create(value) | Self::Get(value) | Self::Delete(value) => name(value),
            Self::Page {
                hash: value,
                after,
                limit,
            } => {
                ensure!((1..=200).contains(limit), "tag page limit must be 1..200");
                if let Some(value) = value {
                    hash(value)?;
                }
                if let Some(value) = after {
                    name(value)?;
                }
                Ok(())
            }
            Self::Change { tag, hashes, .. } => {
                name(tag)?;
                ensure!(
                    (1..=100).contains(&hashes.len()),
                    "tag changes require 1..100 hashes"
                );
                let mut seen = std::collections::HashSet::with_capacity(hashes.len());
                for value in hashes {
                    hash(value)?;
                    ensure!(seen.insert(value), "tag changes require distinct hashes");
                }
                Ok(())
            }
        }
    }

    pub(crate) fn writes(&self) -> bool {
        matches!(
            self,
            Self::Create(_) | Self::Delete(_) | Self::Change { .. }
        )
    }

    pub(crate) fn payload_bytes(&self) -> Option<usize> {
        match self {
            Self::Create(value) | Self::Get(value) | Self::Delete(value) => Some(value.capacity()),
            Self::Page { hash, after, .. } => hash
                .as_ref()
                .map_or(0, String::capacity)
                .checked_add(after.as_ref().map_or(0, String::capacity)),
            Self::Change { tag, hashes, .. } => hashes
                .capacity()
                .checked_mul(std::mem::size_of::<String>())?
                .checked_add(tag.capacity())?
                .checked_add(
                    hashes
                        .iter()
                        .try_fold(0usize, |sum, hash| sum.checked_add(hash.capacity()))?,
                ),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LibraryTag {
    pub name: String,
}

#[derive(Debug)]
pub struct LibraryTagPage {
    pub tags: Vec<LibraryTag>,
    pub next_after: Option<String>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryTagChange {
    Changed,
    Unchanged,
    NotFound,
    StorageFailed,
}

#[derive(Debug)]
pub struct LibraryTagAssignment {
    pub hash: String,
    pub change: LibraryTagChange,
}

#[derive(Debug)]
pub enum LibraryTagValue {
    Tag(Option<LibraryTag>),
    Deleted(bool),
    Page(Option<LibraryTagPage>),
    Assignments(Vec<LibraryTagAssignment>),
}

/// The existing owner charges backing storage until serialization or caller drop.
pub struct LibraryTagReply<T = LibraryTagValue> {
    pub(crate) value: T,
    pub(crate) lease: ByteLease,
}

impl<T> LibraryTagReply<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Project a bounded response without releasing its retained owner charge.
    pub fn map<U>(self, project: impl FnOnce(T) -> U) -> LibraryTagReply<U> {
        LibraryTagReply {
            value: project(self.value),
            lease: self.lease,
        }
    }
}

impl<T: Serialize> Serialize for LibraryTagReply<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.value.serialize(serializer)
    }
}

impl EmulebbCore {
    /// Validate before admission; the profile owner completes admitted SQL work.
    pub async fn library_tags(&self, request: &LibraryTagRequest) -> Result<LibraryTagReply> {
        request.validate()?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner.library_tags(request).await??)
    }
}
