//! Whole-file AICH recovery hash set (`CAICHRecoveryHashSet`) and the ICH
//! block-level salvage computation.
//!
//! Built on the block-level node tree in `aich_tree.rs`. Provides:
//!  - `build_from_data`: compute the full tree + master hash from file bytes
//!    (sharer side, to answer OP_AICHREQUEST),
//!  - `create_part_recovery_data` / `read_recovery_data`: emit/verify the
//!    OP_AICHANSWER recovery body for one part, and
//!  - `compute_part_recovery`: the per-180 KB-block good/corrupt verdict that
//!    drives ICH salvage (which blocks are kept vs re-downloaded).
//!
//! Arithmetic mirrors eMule `srchybrid/SHAHashSet.cpp` exactly.

use anyhow::{Result, bail};

use super::aich_tree::{AichHashTree, sha1_block};
use super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE};

const HASHSIZE: usize = 20;

/// Number of parts for a file size (`(size + PARTSIZE - 1) / PARTSIZE`).
fn part_count(file_size: u64) -> u64 {
    file_size.div_ceil(ED2K_PART_SIZE)
}

/// Size in bytes of part `n` for a file of `file_size`.
fn part_size(file_size: u64, part: u64) -> u64 {
    let start = part * ED2K_PART_SIZE;
    (file_size - start).min(ED2K_PART_SIZE)
}

/// A whole-file AICH recovery hash set, mirroring `CAICHRecoveryHashSet`.
/// `data_size` is the file size; the root node hash is the AICH master hash.
#[derive(Debug)]
pub(super) struct AichRecoveryHashSet {
    root: AichHashTree,
    file_size: u64,
}

impl AichRecoveryHashSet {
    /// New set sized for `file_size` with no hashes yet.
    /// Mirrors `CAICHRecoveryHashSet::SetFileSize`.
    pub(super) fn new(file_size: u64) -> Self {
        let base = if file_size <= ED2K_PART_SIZE {
            ED2K_EMBLOCK_SIZE
        } else {
            ED2K_PART_SIZE
        };
        AichRecoveryHashSet {
            root: AichHashTree::new(file_size, true, base),
            file_size,
        }
    }

    /// The AICH master (root) hash, valid only once the tree is built/verified.
    pub(super) fn master_hash(&self) -> [u8; 20] {
        self.root.hash
    }

    pub(super) fn master_hash_valid(&self) -> bool {
        self.root.hash_valid
    }

    /// Set a known trusted master hash (`SetMasterHash`).
    pub(super) fn set_master_hash(&mut self, hash: [u8; 20]) {
        self.root.hash = hash;
        self.root.hash_valid = true;
    }

    /// Build the full block-level tree from `file_data` (entire file bytes) and
    /// compute the master hash. This is the data path used by a sharer to
    /// answer OP_AICHREQUEST. Mirrors `CKnownFile::CreateAICHHashSetOnly` +
    /// `CreateHash` feeding `SetBlockHash` then `ReCalculateHash`.
    pub(super) fn build_from_data(&mut self, file_data: &[u8]) -> Result<()> {
        if self.file_size == 0 {
            bail!("cannot build AICH tree for zero-sized file");
        }
        if file_data.len() as u64 != self.file_size {
            bail!(
                "AICH build_from_data: data len {} != file size {}",
                file_data.len(),
                self.file_size
            );
        }
        let parts = part_count(self.file_size);
        for part in 0..parts {
            let p_start = part * ED2K_PART_SIZE;
            let p_size = part_size(self.file_size, part);
            let mut pos = 0u64;
            while pos < p_size {
                let block = (p_size - pos).min(ED2K_EMBLOCK_SIZE);
                let s = (p_start + pos) as usize;
                let e = s + block as usize;
                let hash = sha1_block(&file_data[s..e]);
                self.root.set_block_hash(p_start + pos, block, hash)?;
                pos += block;
            }
        }
        if !self.root.recalculate_hash(false) {
            bail!("AICH build_from_data: ReCalculateHash failed");
        }
        Ok(())
    }

    /// Number of hashes a recovery packet for `part` must carry, mirroring
    /// `(nLevel - 1) + nPartSize/EMBLOCKSIZE + (nPartSize%EMBLOCKSIZE != 0)`.
    fn recovery_hash_count(&mut self, part: u64) -> Result<u16> {
        let p_start = part * ED2K_PART_SIZE;
        let p_size = part_size(self.file_size, part);
        let mut level = 0u8;
        self.root.find_hash_mut(p_start, p_size, &mut level);
        let blocks = p_size / ED2K_EMBLOCK_SIZE + u64::from(p_size % ED2K_EMBLOCK_SIZE != 0);
        let count = u64::from(level - 1) + blocks;
        u16::try_from(count).map_err(|_| anyhow::anyhow!("AICH recovery hash count overflow"))
    }

    /// Build the OP_AICHANSWER recovery payload body (the part after the 16-byte
    /// file hash + 2-byte part + 20-byte master hash). Mirrors
    /// `CAICHRecoveryHashSet::CreatePartRecoveryData` (16-bit ident form):
    /// `<count1 u16> (ident u16, hash[20])[count1] <count2 u16 = 0>`.
    pub(super) fn create_part_recovery_data(&mut self, part: u64) -> Result<Vec<u8>> {
        if self.root.data_size <= ED2K_EMBLOCK_SIZE {
            bail!("AICH CreatePartRecoveryData: file too small for recovery");
        }
        let p_start = part * ED2K_PART_SIZE;
        if p_start >= self.file_size {
            bail!("AICH CreatePartRecoveryData: part out of range");
        }
        let p_size = part_size(self.file_size, part);
        let hashes_to_write = self.recovery_hash_count(part)?;
        let mut out = Vec::new();
        out.extend_from_slice(&hashes_to_write.to_le_bytes());
        let body_start = out.len();
        self.root
            .create_part_recovery_data(p_start, p_size, &mut out, 0)?;
        let written = out.len() - body_start;
        if written != usize::from(hashes_to_write) * (HASHSIZE + 2) {
            bail!(
                "AICH recovery data wrong length: {written} != {}",
                usize::from(hashes_to_write) * (HASHSIZE + 2)
            );
        }
        // no 32-bit hashes
        out.extend_from_slice(&0u16.to_le_bytes());
        Ok(out)
    }

    /// Read a peer's recovery data body into the tree (requires a trusted master
    /// hash already set) and verify it. Mirrors
    /// `CAICHRecoveryHashSet::ReadRecoveryData`.
    pub(super) fn read_recovery_data(&mut self, part: u64, body: &[u8]) -> Result<()> {
        if !self.root.hash_valid {
            bail!("AICH ReadRecoveryData: no trusted master hash");
        }
        let p_start = part * ED2K_PART_SIZE;
        let p_size = part_size(self.file_size, part);
        let mut level = 0u8;
        self.root.find_hash_mut(p_start, p_size, &mut level);
        let blocks = p_size / ED2K_EMBLOCK_SIZE + u64::from(p_size % ED2K_EMBLOCK_SIZE != 0);
        let hashes_to_read = (u64::from(level - 1) + blocks) as usize;

        let mut cur = Reader::new(body);
        let n16 = cur.read_u16()?;
        let available16 = usize::from(n16);
        if available16 != 0 && available16 != hashes_to_read {
            bail!("AICH ReadRecoveryData: 16-bit hash count mismatch");
        }
        if available16 != 0 {
            if cur.remaining() < available16 * (HASHSIZE + 2) {
                bail!("AICH ReadRecoveryData: short 16-bit hash data");
            }
            for _ in 0..available16 {
                let ident = u32::from(cur.read_u16()?);
                let hash = cur.read_hash()?;
                if ident == 1 {
                    bail!("AICH ReadRecoveryData: master hash overwrite rejected");
                }
                self.root.set_hash(&hash, ident, -1, false)?;
            }
        } else {
            // 32-bit ident form (large files)
            let n32 = cur.read_u16()?;
            let available32 = usize::from(n32);
            if available32 != hashes_to_read {
                bail!("AICH ReadRecoveryData: 32-bit hash count mismatch");
            }
            if cur.remaining() < available32 * (HASHSIZE + 4) {
                bail!("AICH ReadRecoveryData: short 32-bit hash data");
            }
            for _ in 0..available32 {
                let ident = cur.read_u32()?;
                let hash = cur.read_hash()?;
                if ident == 1 || ident > 0x40_0000 {
                    bail!("AICH ReadRecoveryData: invalid 32-bit ident");
                }
                self.root.set_hash(&hash, ident, -1, false)?;
            }
        }

        if !self.root.verify_hash_tree(true) {
            bail!("AICH ReadRecoveryData: hash tree verification failed");
        }
        // final check: all lowest-level block hashes for the part are present
        let mut pos = 0u64;
        while pos < p_size {
            let block = (p_size - pos).min(ED2K_EMBLOCK_SIZE);
            if self.root.existing(p_start + pos, block).is_none() {
                bail!("AICH ReadRecoveryData: missing lowest-level block hash");
            }
            pos += block;
        }
        Ok(())
    }

    /// Return the trusted (verified) per-block hashes for `part`, left to right.
    /// Requires `read_recovery_data` (or `build_from_data`) to have populated
    /// the part's block hashes. Used to drive ICH salvage.
    pub(super) fn part_block_hashes(&self, part: u64) -> Result<Vec<[u8; 20]>> {
        let p_start = part * ED2K_PART_SIZE;
        let p_size = part_size(self.file_size, part);
        let mut hashes = Vec::new();
        let mut pos = 0u64;
        while pos < p_size {
            let block = (p_size - pos).min(ED2K_EMBLOCK_SIZE);
            let node = self
                .root
                .existing(p_start + pos, block)
                .ok_or_else(|| anyhow::anyhow!("AICH part_block_hashes: missing block hash"))?;
            hashes.push(node.hash);
            pos += block;
        }
        Ok(hashes)
    }
}

/// Result of an ICH recovery pass over one corrupt part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AichRecoveryOutcome {
    /// Byte ranges (relative to file start) of blocks that verified OK and can
    /// be salvaged (kept), one per recovered block.
    pub(super) recovered_ranges: Vec<(u64, u64)>,
    /// Byte ranges (relative to file start) of blocks that failed verification
    /// and must be re-downloaded.
    pub(super) corrupt_ranges: Vec<(u64, u64)>,
}

impl AichRecoveryOutcome {
    pub(super) fn recovered_bytes(&self) -> u64 {
        self.recovered_ranges.iter().map(|(s, e)| e - s).sum()
    }
}

/// Compute which 180 KB blocks of `part` are good vs corrupt by comparing the
/// freshly hashed local part bytes against the trusted block hashes. Mirrors
/// the comparison loop of `CPartFile::AICHRecoveryDataAvailable`.
///
/// `part_data` is the current (possibly corrupt) bytes of the part as stored
/// locally; `trusted_block_hashes` come from `part_block_hashes` after the
/// peer recovery data was verified against the master hash.
pub(super) fn compute_part_recovery(
    file_size: u64,
    part: u64,
    part_data: &[u8],
    trusted_block_hashes: &[[u8; 20]],
) -> Result<AichRecoveryOutcome> {
    let p_start = part * ED2K_PART_SIZE;
    let p_size = part_size(file_size, part);
    if part_data.len() as u64 != p_size {
        bail!(
            "AICH compute_part_recovery: data len {} != part size {p_size}",
            part_data.len()
        );
    }
    let mut recovered_ranges = Vec::new();
    let mut corrupt_ranges = Vec::new();
    let mut pos = 0u64;
    let mut idx = 0usize;
    while pos < p_size {
        let block = (p_size - pos).min(ED2K_EMBLOCK_SIZE);
        let s = pos as usize;
        let e = s + block as usize;
        let our = sha1_block(&part_data[s..e]);
        let trusted = trusted_block_hashes
            .get(idx)
            .ok_or_else(|| anyhow::anyhow!("AICH compute_part_recovery: missing trusted hash"))?;
        let abs = (p_start + pos, p_start + pos + block);
        if &our == trusted {
            recovered_ranges.push(abs);
        } else {
            corrupt_ranges.push(abs);
        }
        pos += block;
        idx += 1;
    }
    Ok(AichRecoveryOutcome {
        recovered_ranges,
        corrupt_ranges,
    })
}

/// Minimal little-endian reader over a recovery-data body.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn read_u16(&mut self) -> Result<u16> {
        if self.remaining() < 2 {
            bail!("AICH reader: short u16");
        }
        let v = u16::from_le_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }
    fn read_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            bail!("AICH reader: short u32");
        }
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn read_hash(&mut self) -> Result<[u8; 20]> {
        if self.remaining() < HASHSIZE {
            bail!("AICH reader: short hash");
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&self.buf[self.pos..self.pos + HASHSIZE]);
        self.pos += HASHSIZE;
        Ok(h)
    }
}
