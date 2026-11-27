//! Process-local ownership of outstanding stock AICH recovery requests.

use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Duration,
};

use anyhow::Result;
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::JobToken;
use parking_lot::Mutex;
use tokio::time::Instant;

use super::{Ed2kPieceState, Ed2kTransferRuntime, Ed2kTransferState, decode_aich_hash_hex};

#[derive(Debug)]
pub(super) struct RecoveryRequest {
    pub(super) token: JobToken,
    pub(super) file: Ed2kHash,
    pub(super) size: u64,
    pub(super) master: [u8; 20],
    pub(super) generation: u64,
    pub(super) piece: Ed2kPieceState,
    peer: SocketAddr,
    peer_hash: Option<[u8; 16]>,
    pub(super) deadline: Instant,
}

#[derive(Debug, Default)]
pub(super) struct AichRequestRegistry(Mutex<Vec<Weak<RecoveryRequest>>>);

/// Non-cloneable session-owned reservation. Dropping the sole strong reference
/// releases both the peer and the part, including on cancellation or failed send.
#[derive(Debug)]
pub(crate) struct AichRecoveryPermit(pub(super) Arc<RecoveryRequest>);

impl AichRecoveryPermit {
    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= self.0.deadline
    }

    pub(crate) fn master(&self) -> [u8; 20] {
        self.0.master
    }

    pub(crate) fn matches(
        &self,
        file: Ed2kHash,
        part: Option<u16>,
        master: Option<[u8; 20]>,
    ) -> bool {
        self.0.file == file
            && match (part, master) {
                (Some(part), Some(master)) => {
                    u32::from(part) == self.0.piece.piece_index && master == self.0.master
                }
                (None, None) => true,
                _ => false,
            }
    }
}

impl Ed2kTransferRuntime {
    /// Reserve recovery for the current corrupt bytes and accepted identity.
    /// Other sessions may continue normal block downloading while waiting.
    pub(crate) async fn reserve_aich_recovery(
        &self,
        token: JobToken,
        part: u16,
        peer: SocketAddr,
        peer_hash: Option<[u8; 16]>,
    ) -> Result<Option<AichRecoveryPermit>> {
        let _guard = self.lock_manifest(token).await;
        let manifest = self.load_aich_manifest_unlocked(token).await?;
        let Some(piece) = manifest.pieces.get(usize::from(part)) else {
            return Ok(None);
        };
        let Some(root) = manifest.aich_root.as_deref() else {
            return Ok(None);
        };
        if !piece.ich_corrupted
            || piece.state == Ed2kTransferState::Verified
            || manifest.aich_root_origin.is_none()
            || manifest.file_size
                <= u64::from(part) * super::ED2K_PART_SIZE + super::ED2K_EMBLOCK_SIZE
        {
            return Ok(None);
        }
        let now = Instant::now();
        let record = Arc::new(RecoveryRequest {
            token,
            file: manifest.file_hash.parse()?,
            size: manifest.file_size,
            master: decode_aich_hash_hex(root)?,
            generation: manifest.aich_trust_generation,
            piece: piece.clone(),
            peer,
            peer_hash,
            deadline: now + Duration::from_secs(60),
        });
        let mut active = self.aich_requests.0.lock();
        active.retain(|weak| weak.upgrade().is_some_and(|entry| entry.deadline > now));
        if active.iter().filter_map(Weak::upgrade).any(|entry| {
            (entry.token == token && entry.piece.piece_index == u32::from(part))
                || entry.peer == peer
                || (peer_hash.is_some() && peer_hash == entry.peer_hash)
        }) {
            return Ok(None);
        }
        active.push(Arc::downgrade(&record));
        Ok(Some(AichRecoveryPermit(record)))
    }
}
