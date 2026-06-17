//! Per-part block presence bitmap at the eMule block granularity
//! (`EMBLOCKSIZE` = 184320 bytes within one 9.28 MB part).
//!
//! This mirrors the per-file gap-list semantics of `CPartFile::m_gaplist`
//! (`FillGap`/`GetNextEmptyBlockInPart`/`IsComplete(start,end)`), but tracks
//! presence at block granularity for a single part so a part can hold a
//! non-contiguous set of present blocks while the AICH/ICH salvage path
//! re-downloads only the bad blocks.
//!
//! A part is split into `ceil(part_len / EMBLOCKSIZE)` blocks. The trailing
//! block may be shorter than `EMBLOCKSIZE`. Presence is a packed little-endian
//! bit set persisted as a lowercase hex string in the manifest, so an existing
//! on-disk manifest without the bitmap field still loads: callers derive a
//! contiguous-prefix bitmap from `bytes_written` in that case.

use super::ED2K_EMBLOCK_SIZE;

/// Presence bitmap over the eMule blocks of one part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PartBlockBitmap {
    /// Length in bytes of the part this bitmap covers.
    part_len: u64,
    /// Number of blocks (`ceil(part_len / EMBLOCKSIZE)`).
    block_count: usize,
    /// One bit per block, packed LSB-first into bytes.
    bits: Vec<u8>,
}

impl PartBlockBitmap {
    /// Number of eMule blocks in a part of `part_len` bytes.
    pub(super) fn block_count_for(part_len: u64) -> usize {
        if part_len == 0 {
            return 0;
        }
        usize::try_from(part_len.div_ceil(ED2K_EMBLOCK_SIZE)).unwrap_or(0)
    }

    /// An empty bitmap (no blocks present) for a part of `part_len` bytes.
    pub(super) fn empty(part_len: u64) -> Self {
        let block_count = Self::block_count_for(part_len);
        let bytes = block_count.div_ceil(8);
        PartBlockBitmap {
            part_len,
            block_count,
            bits: vec![0u8; bytes],
        }
    }

    /// A bitmap with the first `bytes_written` bytes of the part marked present
    /// as a contiguous prefix of whole blocks. The legacy contiguous fast path
    /// and resume-manifest backward compatibility both rely on this so an
    /// existing on-disk manifest without a stored bitmap still loads.
    pub(super) fn contiguous_prefix(part_len: u64, bytes_written: u64) -> Self {
        let mut map = Self::empty(part_len);
        let present = bytes_written.min(part_len);
        let mut pos = 0u64;
        let mut idx = 0usize;
        while pos < present {
            let block = (part_len - pos).min(ED2K_EMBLOCK_SIZE);
            if pos + block > present {
                // Only whole, fully written blocks count as present.
                break;
            }
            map.set_present(idx);
            pos += block;
            idx += 1;
        }
        map
    }

    /// Total number of blocks in the part.
    pub(super) fn block_count(&self) -> usize {
        self.block_count
    }

    /// Byte range `[start, end)` (relative to the part start) of block `idx`.
    pub(super) fn block_range(&self, idx: usize) -> (u64, u64) {
        let start = (idx as u64) * ED2K_EMBLOCK_SIZE;
        let end = (start + ED2K_EMBLOCK_SIZE).min(self.part_len);
        (start, end)
    }

    /// Whether block `idx` is marked present.
    pub(super) fn is_present(&self, idx: usize) -> bool {
        if idx >= self.block_count {
            return false;
        }
        (self.bits[idx / 8] >> (idx % 8)) & 1 == 1
    }

    /// Mark block `idx` present.
    pub(super) fn set_present(&mut self, idx: usize) {
        if idx >= self.block_count {
            return;
        }
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    /// Mark block `idx` missing.
    pub(super) fn set_missing(&mut self, idx: usize) {
        if idx >= self.block_count {
            return;
        }
        self.bits[idx / 8] &= !(1 << (idx % 8));
    }

    /// Whether every block in the part is present (`IsComplete(start,end)` over
    /// the whole part range).
    pub(super) fn all_present(&self) -> bool {
        (0..self.block_count).all(|idx| self.is_present(idx))
    }

    /// Number of present blocks.
    pub(super) fn present_count(&self) -> usize {
        (0..self.block_count)
            .filter(|&idx| self.is_present(idx))
            .count()
    }

    /// The summed byte length of all present blocks. Mirrors the
    /// `bytes_written`-style progress accounting used by the manifest, but is
    /// exact even when presence is non-contiguous.
    pub(super) fn present_bytes(&self) -> u64 {
        (0..self.block_count)
            .filter(|&idx| self.is_present(idx))
            .map(|idx| {
                let (s, e) = self.block_range(idx);
                e - s
            })
            .sum()
    }

    /// The index of the first block whose presence covers a contiguous prefix
    /// gap, i.e. the count of leading present blocks. Used to retain the
    /// existing contiguous fast path semantics (`bytes_written`).
    pub(super) fn contiguous_prefix_bytes(&self) -> u64 {
        let mut total = 0u64;
        for idx in 0..self.block_count {
            if !self.is_present(idx) {
                break;
            }
            let (s, e) = self.block_range(idx);
            total += e - s;
        }
        total
    }

    /// Encode the packed bits as a lowercase hex string for persistence.
    pub(super) fn to_hex(&self) -> String {
        hex::encode(&self.bits)
    }

    /// Decode a persisted hex bitmap for a part of `part_len` bytes. An empty
    /// string yields an empty bitmap. A wrong-length payload is rejected so the
    /// caller can fall back to the contiguous-prefix derivation.
    pub(super) fn from_hex(part_len: u64, hex_str: &str) -> Option<Self> {
        if hex_str.is_empty() {
            return Some(Self::empty(part_len));
        }
        let bits = hex::decode(hex_str).ok()?;
        let block_count = Self::block_count_for(part_len);
        if bits.len() != block_count.div_ceil(8) {
            return None;
        }
        Some(PartBlockBitmap {
            part_len,
            block_count,
            bits,
        })
    }
}
