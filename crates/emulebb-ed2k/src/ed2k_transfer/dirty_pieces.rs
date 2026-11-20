//! Geometry-sized checkpoint membership; acknowledgment never allocates.
use super::{
    Ed2kResumeManifest, LocalMutationError,
    resident::{Reservation, ResidentControl},
};
use anyhow::{Result, ensure};
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct DirtyPieces {
    words: Box<[u64]>,
    piece_count: u32,
    count: usize,
    // Drop backing before returning its resident credit.
    _credit: Reservation,
}

impl DirtyPieces {
    pub(super) fn new(
        control: &Arc<ResidentControl>,
        manifest: &Ed2kResumeManifest,
    ) -> Result<Self> {
        let piece_count = super::manifest::piece_count(manifest.file_size, manifest.piece_size);
        let word_count = usize::try_from(piece_count)?.div_ceil(64);
        let bytes = word_count
            .checked_mul(size_of::<u64>())
            .ok_or(LocalMutationError::TooLarge)?;
        let credit = control.reserve_bookkeeping(manifest.token.job_id, bytes)?;
        Ok(Self {
            words: vec![0; word_count].into_boxed_slice(),
            piece_count,
            count: 0,
            _credit: credit,
        })
    }

    pub(super) fn validate(&self, index: u32) -> Result<()> {
        ensure!(
            index < self.piece_count,
            "dirty piece lies outside checkpoint geometry"
        );
        Ok(())
    }

    pub(super) fn insert(&mut self, index: u32) -> Result<()> {
        self.validate(index)?;
        let word = &mut self.words[index as usize / 64];
        let bit = 1u64 << (index % 64);
        if *word & bit == 0 {
            *word |= bit;
            self.count += 1;
        }
        Ok(())
    }

    pub(super) fn contains(&self, index: &u32) -> bool {
        *index < self.piece_count && self.words[*index as usize / 64] & (1u64 << (*index % 64)) != 0
    }

    pub(super) fn remove(&mut self, index: &u32) {
        if self.contains(index) {
            self.words[*index as usize / 64] &= !(1u64 << (*index % 64));
            self.count -= 1;
        }
    }

    pub(super) fn len(&self) -> usize {
        self.count
    }
    pub(super) fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub(super) fn first(&self) -> Option<u32> {
        self.iter().next()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.words.iter().enumerate().flat_map(|(offset, &word)| {
            let mut remaining = word;
            std::iter::from_fn(move || {
                if remaining == 0 {
                    return None;
                }
                let bit = remaining.trailing_zeros();
                remaining &= remaining - 1;
                Some(offset as u32 * 64 + bit)
            })
        })
    }
}

#[cfg(test)]
mod tests;
