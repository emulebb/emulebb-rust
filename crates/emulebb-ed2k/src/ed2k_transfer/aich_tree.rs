//! Block-level AICH hash tree node (`CAICHHashTree`) for ICH recovery.
//!
//! This is a faithful, allocation-backed port of eMule's
//! `srchybrid/SHAHashSet.cpp` `CAICHHashTree`. It keeps every intermediate
//! node so the whole-file set in `aich_recovery.rs` can build the tree,
//! emit/verify OP_AICHREQUEST recovery data, and drive ICH salvage.
//!
//! Constants and arithmetic mirror the master exactly so the resulting hashes
//! are byte-for-byte identical. PARTSIZE = 9_728_000, EMBLOCKSIZE = 184_320.

use anyhow::{Result, bail};
use sha1::{Digest, Sha1};

use super::{ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE};

/// SHA1 over the concatenation of two 20-byte child hashes (master inner node).
fn sha1_pair(left: &[u8; 20], right: &[u8; 20]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// SHA1 over a single block of data (master lowest-level leaf hash).
pub(super) fn sha1_block(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// A node in the AICH hash tree. Mirrors `CAICHHashTree`.
#[derive(Debug)]
pub(super) struct AichHashTree {
    pub(super) data_size: u64,
    pub(super) is_left_branch: bool,
    /// Base (block) size this node's lowest hashes are based on: PARTSIZE or
    /// EMBLOCKSIZE. Mirrors `CAICHHashTree::GetBaseSize`.
    base_size: u64,
    pub(super) hash: [u8; 20],
    pub(super) hash_valid: bool,
    left: Option<Box<AichHashTree>>,
    right: Option<Box<AichHashTree>>,
}

impl AichHashTree {
    /// Mirrors `CAICHHashTree::CAICHHashTree(nDataSize, bLeftBranch, nBaseSize)`.
    pub(super) fn new(data_size: u64, is_left_branch: bool, base_size: u64) -> Self {
        debug_assert!(base_size == ED2K_PART_SIZE || base_size == ED2K_EMBLOCK_SIZE);
        AichHashTree {
            data_size,
            is_left_branch,
            base_size: if base_size >= ED2K_PART_SIZE {
                ED2K_PART_SIZE
            } else {
                ED2K_EMBLOCK_SIZE
            },
            hash: [0u8; 20],
            hash_valid: false,
            left: None,
            right: None,
        }
    }

    fn base_size(&self) -> u64 {
        self.base_size
    }

    /// Child split sizes for this node, mirroring the master's `nLeft`/`nRight`:
    /// `nLeft = (nBlocks + isLeftBranch) / 2 * GetBaseSize()`.
    fn child_sizes(&self) -> (u64, u64) {
        let base = self.base_size();
        let blocks = self.data_size / base + u64::from(!self.data_size.is_multiple_of(base));
        let left = (blocks + u64::from(self.is_left_branch)) / 2 * base;
        let right = self.data_size - left;
        (left, right)
    }

    /// Recursive find/create of the node covering `[start, start+size)`.
    /// Mirrors `CAICHHashTree::FindHash` (creates missing branches). Returns the
    /// descent level reached (number of edges, matching the master's `*nLevel`).
    pub(super) fn find_hash_mut(
        &mut self,
        start: u64,
        size: u64,
        level: &mut u8,
    ) -> Option<&mut AichHashTree> {
        *level += 1;
        if *level > 22 || start + size > self.data_size || size > self.data_size {
            return None;
        }
        if start == 0 && size == self.data_size {
            return Some(self);
        }
        if self.data_size <= self.base_size() {
            return None;
        }
        let (left_size, right_size) = self.child_sizes();
        if start < left_size {
            if start + size > left_size {
                return None;
            }
            if self.left.is_none() {
                let base = if left_size <= ED2K_PART_SIZE {
                    ED2K_EMBLOCK_SIZE
                } else {
                    ED2K_PART_SIZE
                };
                self.left = Some(Box::new(AichHashTree::new(left_size, true, base)));
            }
            return self
                .left
                .as_mut()
                .unwrap()
                .find_hash_mut(start, size, level);
        }
        let start = start - left_size;
        if start + size > right_size {
            return None;
        }
        if self.right.is_none() {
            let base = if right_size <= ED2K_PART_SIZE {
                ED2K_EMBLOCK_SIZE
            } else {
                ED2K_PART_SIZE
            };
            self.right = Some(Box::new(AichHashTree::new(right_size, false, base)));
        }
        self.right
            .as_mut()
            .unwrap()
            .find_hash_mut(start, size, level)
    }

    /// Read-only find of an existing valid hash. Mirrors `FindExistingHash`.
    fn find_existing_hash(&self, start: u64, size: u64, level: &mut u8) -> Option<&AichHashTree> {
        *level += 1;
        if *level > 22 || start + size > self.data_size || size > self.data_size {
            return None;
        }
        if start == 0 && size == self.data_size {
            return if self.hash_valid { Some(self) } else { None };
        }
        if self.data_size <= self.base_size() {
            return None;
        }
        let (left_size, right_size) = self.child_sizes();
        if start < left_size {
            if start + size > left_size {
                return None;
            }
            let left = self.left.as_ref()?;
            if !left.hash_valid {
                return None;
            }
            return left.find_existing_hash(start, size, level);
        }
        let start = start - left_size;
        if start + size > right_size {
            return None;
        }
        let right = self.right.as_ref()?;
        if !right.hash_valid {
            return None;
        }
        right.find_existing_hash(start, size, level)
    }

    /// Convenience wrapper around `find_existing_hash`.
    pub(super) fn existing(&self, start: u64, size: u64) -> Option<&AichHashTree> {
        let mut level = 0u8;
        self.find_existing_hash(start, size, &mut level)
    }

    /// Set the lowest-level (block) hash for `[start, start+size)`.
    /// Mirrors `CAICHHashTree::SetBlockHash`.
    pub(super) fn set_block_hash(&mut self, start: u64, size: u64, hash: [u8; 20]) -> Result<()> {
        if size > ED2K_EMBLOCK_SIZE {
            bail!("AICH SetBlockHash: block size {size} exceeds EMBLOCKSIZE");
        }
        let mut level = 0u8;
        let node = self
            .find_hash_mut(start, size, &mut level)
            .ok_or_else(|| anyhow::anyhow!("AICH SetBlockHash: FindHash failed"))?;
        if node.base_size() != ED2K_EMBLOCK_SIZE || node.data_size != size {
            bail!("AICH SetBlockHash: logical error on node values");
        }
        node.hash = hash;
        node.hash_valid = true;
        Ok(())
    }

    /// Recalculate missing inner hashes from existing children.
    /// Mirrors `CAICHHashTree::ReCalculateHash`.
    pub(super) fn recalculate_hash(&mut self, dont_replace: bool) -> bool {
        let has_left = self.left.is_some();
        let has_right = self.right.is_some();
        if has_left ^ has_right {
            // incomplete children: drop both, keep our hash (the stock seam
            // keeps the node hash valid when only one child is present).
            self.left = None;
            self.right = None;
            return false;
        }
        if has_left && has_right {
            let left_ok = self.left.as_mut().unwrap().recalculate_hash(dont_replace);
            let right_ok = self.right.as_mut().unwrap().recalculate_hash(dont_replace);
            if !left_ok || !right_ok {
                return false;
            }
            if dont_replace && self.hash_valid {
                return true;
            }
            let l = self.left.as_ref().unwrap();
            let r = self.right.as_ref().unwrap();
            if l.hash_valid && r.hash_valid {
                self.hash = sha1_pair(&l.hash, &r.hash);
                self.hash_valid = true;
                return true;
            }
            return self.hash_valid;
        }
        true
    }

    /// Verify the tree against `self.hash`, optionally pruning bad/empty trees.
    /// Mirrors `CAICHHashTree::VerifyHashTree`.
    pub(super) fn verify_hash_tree(&mut self, delete_bad: bool) -> bool {
        if !self.hash_valid {
            if delete_bad {
                self.left = None;
                self.right = None;
            }
            return false;
        }
        if let Some(left) = self.left.as_mut()
            && !left.hash_valid
        {
            left.recalculate_hash(true);
        }
        if let Some(right) = self.right.as_mut()
            && !right.hash_valid
        {
            right.recalculate_hash(true);
        }
        let left_valid = self.left.as_ref().is_some_and(|n| n.hash_valid);
        let right_valid = self.right.as_ref().is_some_and(|n| n.hash_valid);
        if left_valid ^ right_valid {
            if delete_bad {
                self.left = None;
                self.right = None;
            }
            return false;
        }
        if left_valid && right_valid {
            let cmp = sha1_pair(
                &self.left.as_ref().unwrap().hash,
                &self.right.as_ref().unwrap().hash,
            );
            if self.hash != cmp {
                if delete_bad {
                    self.left = None;
                    self.right = None;
                }
                return false;
            }
            return self.left.as_mut().unwrap().verify_hash_tree(delete_bad)
                && self.right.as_mut().unwrap().verify_hash_tree(delete_bad);
        }
        // last hash in branch - prune empty children
        if delete_bad {
            if self.left.as_ref().is_some_and(|n| !n.hash_valid) {
                self.left = None;
            }
            if self.right.as_ref().is_some_and(|n| !n.hash_valid) {
                self.right = None;
            }
        }
        true
    }

    /// Append one node's hash with its ident. Mirrors `WriteHash`: a 16-bit
    /// ident for normal files, a 32-bit ident for large (>4GB) files
    /// (`b32BitIdent`).
    fn write_hash(&self, out: &mut Vec<u8>, mut hash_ident: u32, use_32bit: bool) {
        hash_ident <<= 1;
        hash_ident |= u32::from(self.is_left_branch);
        if use_32bit {
            out.extend_from_slice(&hash_ident.to_le_bytes());
        } else {
            out.extend_from_slice(&(hash_ident as u16).to_le_bytes());
        }
        out.extend_from_slice(&self.hash);
    }

    /// Append the lowest-level hashes left-to-right. Mirrors
    /// `WriteLowestLevelHashes` (identifiers always written here; 16- or 32-bit
    /// per `b32BitIdent`).
    fn write_lowest_level_hashes(
        &self,
        out: &mut Vec<u8>,
        mut hash_ident: u32,
        use_32bit: bool,
    ) -> Result<()> {
        hash_ident <<= 1;
        hash_ident |= u32::from(self.is_left_branch);
        if self.left.is_none() && self.right.is_none() {
            if self.data_size <= self.base_size() && self.hash_valid {
                if use_32bit {
                    out.extend_from_slice(&hash_ident.to_le_bytes());
                } else {
                    out.extend_from_slice(&(hash_ident as u16).to_le_bytes());
                }
                out.extend_from_slice(&self.hash);
                return Ok(());
            }
            bail!("AICH WriteLowestLevelHashes: leaf without valid hash");
        }
        let (Some(left), Some(right)) = (self.left.as_ref(), self.right.as_ref()) else {
            bail!("AICH WriteLowestLevelHashes: incomplete inner node");
        };
        left.write_lowest_level_hashes(out, hash_ident, use_32bit)?;
        right.write_lowest_level_hashes(out, hash_ident, use_32bit)
    }

    /// Emit the recovery data for one part. Mirrors
    /// `CAICHHashTree::CreatePartRecoveryData`: at each level above the part it
    /// writes the *sibling* hash, then descends; at the part it writes all the
    /// part's block hashes.
    pub(super) fn create_part_recovery_data(
        &self,
        start: u64,
        size: u64,
        out: &mut Vec<u8>,
        mut hash_ident: u32,
        use_32bit: bool,
    ) -> Result<()> {
        if start + size > self.data_size || size > self.data_size {
            bail!("AICH CreatePartRecoveryData: range out of bounds");
        }
        if start == 0 && size == self.data_size {
            return self.write_lowest_level_hashes(out, hash_ident, use_32bit);
        }
        if self.data_size <= self.base_size() {
            bail!("AICH CreatePartRecoveryData: cannot descend below base size");
        }
        hash_ident <<= 1;
        hash_ident |= u32::from(self.is_left_branch);
        let base = self.base_size();
        let blocks = self.data_size / base + u64::from(!self.data_size.is_multiple_of(base));
        let left_size = (if self.is_left_branch {
            blocks + 1
        } else {
            blocks
        }) / 2
            * base;
        let right_size = self.data_size - left_size;
        let (Some(left), Some(right)) = (self.left.as_ref(), self.right.as_ref()) else {
            bail!("AICH CreatePartRecoveryData: missing child trees");
        };
        if start < left_size {
            if start + size > left_size || !right.hash_valid {
                bail!("AICH CreatePartRecoveryData: invalid left descent");
            }
            right.write_hash(out, hash_ident, use_32bit);
            return left.create_part_recovery_data(start, size, out, hash_ident, use_32bit);
        }
        let start = start - left_size;
        if start + size > right_size || !left.hash_valid {
            bail!("AICH CreatePartRecoveryData: invalid right descent");
        }
        left.write_hash(out, hash_ident, use_32bit);
        right.create_part_recovery_data(start, size, out, hash_ident, use_32bit)
    }

    /// Insert a hash addressed by `hash_ident` (16-bit path). Mirrors
    /// `CAICHHashTree::SetHash` with `bAllowOverwrite = false`.
    pub(super) fn set_hash(
        &mut self,
        data: &[u8; 20],
        mut hash_ident: u32,
        mut level: i32,
        allow_overwrite: bool,
    ) -> Result<()> {
        if level == -1 {
            level = 31;
            while level >= 0 && (hash_ident & 0x8000_0000) == 0 {
                hash_ident <<= 1;
                level -= 1;
            }
            if level < 0 {
                bail!("AICH SetHash: invalid hash ident (0)");
            }
        }
        if level == 0 {
            if self.hash_valid && !allow_overwrite {
                return Ok(());
            }
            self.hash = *data;
            self.hash_valid = true;
            return Ok(());
        }
        if self.data_size <= self.base_size() {
            bail!("AICH SetHash: cannot descend below base size");
        }
        hash_ident <<= 1;
        level -= 1;
        let (left_size, right_size) = self.child_sizes();
        if (hash_ident & 0x8000_0000) > 0 {
            if self.left.is_none() {
                let base = if left_size <= ED2K_PART_SIZE {
                    ED2K_EMBLOCK_SIZE
                } else {
                    ED2K_PART_SIZE
                };
                self.left = Some(Box::new(AichHashTree::new(left_size, true, base)));
            }
            return self
                .left
                .as_mut()
                .unwrap()
                .set_hash(data, hash_ident, level, allow_overwrite);
        }
        if self.right.is_none() {
            let base = if right_size <= ED2K_PART_SIZE {
                ED2K_EMBLOCK_SIZE
            } else {
                ED2K_PART_SIZE
            };
            self.right = Some(Box::new(AichHashTree::new(right_size, false, base)));
        }
        self.right
            .as_mut()
            .unwrap()
            .set_hash(data, hash_ident, level, allow_overwrite)
    }
}
