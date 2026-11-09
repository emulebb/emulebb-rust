//! AICH root corroboration for network-learned roots.
//!
//! A peer can advertise an AICH root hash (via `OP_AICHFILEHASHANS` or the
//! file-identifier carried in startup metadata). A single peer's word is not
//! authoritative: a hostile or buggy peer could hand us a bogus root which, if
//! trusted blindly, would authorize ICH part salvage against attacker-chosen
//! recovery data. The master client (`CAICHRecoveryHashSet::AddHash` /
//! `SetStatus`, `SHAHashSet.cpp:998-1018`) only promotes a network-learned root
//! to `AICH_TRUSTED` once at least `MINUNIQUEIPS_TOTRUST` distinct IPs have
//! proposed it AND that root accounts for at least `MINPERCENTAGE_TOTRUST`
//! percent of all proposing IPs.
//!
//! This module mirrors that policy for network-learned roots. Authoritative
//! roots have explicit local/operator/import provenance. A persisted accepted
//! decision resumes VERIFIED as stock without changing that recorded origin;
//! a part set that was merely acquired never creates such a decision.

use std::collections::{BTreeMap, HashMap};

use super::{Ed2kAichRootOrigin, Ed2kResumeManifest};

/// Change accepted identity under the manifest lock. The generation and
/// dependent part set change atomically with the persisted decision.
pub(super) fn set_identity(
    manifest: &mut Ed2kResumeManifest,
    root: Option<String>,
    origin: Option<Ed2kAichRootOrigin>,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        root.is_some() == origin.is_some(),
        "incomplete AICH decision"
    );
    if manifest.aich_root == root && manifest.aich_root_origin == origin {
        return Ok(false);
    }
    let generation = manifest
        .aich_trust_generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("AICH trust generation exhausted"))?;
    i64::try_from(generation)?;
    if manifest.aich_root != root {
        manifest.aich_hashset.clear();
        manifest.aich_hashset_acquired = false;
    }
    manifest.aich_root = root;
    manifest.aich_root_origin = origin;
    manifest.aich_trust_generation = generation;
    Ok(true)
}

/// How many distinct IPs must propose the same AICH root before it is trusted.
/// Mirrors `MINUNIQUEIPS_TOTRUST` (`SHAHashSet.cpp:40`).
pub(super) const MINUNIQUEIPS_TOTRUST: usize = 10;

/// Minimum share (percent) of all proposing IPs that the leading root must hold
/// before it is trusted. Mirrors `MINPERCENTAGE_TOTRUST` (`SHAHashSet.cpp:41`).
pub(super) const MINPERCENTAGE_TOTRUST: u64 = 92;

/// Resource limits do not turn a truncated sample into trust. Once either
/// limit is exceeded, only independent authoritative metadata can establish
/// the root for this transfer; ordinary MD4 downloading remains available.
const MAX_SIGNERS: usize = 4_096;
const MAX_CANDIDATES: usize = 64;

/// Mask applied to a proposing IPv4 address (in network/big-endian byte order)
/// before counting it as a unique signer. Mirrors the master's
/// `dwIP &= 0x00F0FFFF` in `CAICHUntrustedHash::AddSigningIP`
/// (`SHAHashSet.cpp:519`): only the 20 most significant bits of the address are
/// retained, so a single subnet cannot inflate the unique-IP count.
///
/// eMule stores the IP as a little-endian `uint32` and masks with `0x00F0FFFF`.
/// We hold the address as the big-endian `[u8; 4]` octets `[a, b, c, d]`, which
/// is the byte-reverse of eMule's `uint32`, so the equivalent mask keeps octets
/// `a`, `b`, and the high nibble of `c`.
fn mask_signer_ip(octets: [u8; 4]) -> [u8; 4] {
    [octets[0], octets[1], octets[2] & 0xF0, 0]
}

/// Per-file accumulator of network-proposed AICH roots keyed by signer. Keeping
/// one root per masked signer prevents one responder from inflating multiple
/// conflicting candidates. In-memory only (live session trust state, never
/// persisted): the durable master, origin and generation describe an accepted
/// decision. Live vote history is bounded and released with the transfer.
#[derive(Debug, Default)]
pub(super) struct AichRootCorroboration {
    /// Masked proposing IP -> first root proposed by that signer.
    proposals: HashMap<[u8; 4], [u8; 20]>,
    /// Ordered roots make equal-weight evidence deterministic.
    counts: BTreeMap<[u8; 20], usize>,
    saturated: bool,
}

impl AichRootCorroboration {
    /// Record the first root proposed by `from_ip`'s masked signer identity.
    /// Returns `true` only when that signer had not voted before.
    pub(super) fn record(&mut self, root: [u8; 20], from_ip: [u8; 4]) -> bool {
        let masked = mask_signer_ip(from_ip);
        if self.saturated || self.proposals.contains_key(&masked) {
            return false;
        }
        if self.proposals.len() == MAX_SIGNERS
            || (!self.counts.contains_key(&root) && self.counts.len() == MAX_CANDIDATES)
        {
            self.saturated = true;
            return false;
        }
        self.proposals.insert(masked, root);
        *self.counts.entry(root).or_default() += 1;
        true
    }

    /// Return the leading root if it now satisfies the master's trust gate:
    /// `>= MINUNIQUEIPS_TOTRUST` distinct IPs AND `>= MINPERCENTAGE_TOTRUST`
    /// percent of all proposing IPs. Mirrors `SHAHashSet.cpp:998`.
    pub(super) fn trusted_root(&self) -> Option<[u8; 20]> {
        if self.saturated {
            return None;
        }
        let total_signers = self.proposals.len();
        let (&root, &count) = self.counts.iter().max_by_key(|(_, count)| **count)?;
        if total_signers == 0 {
            return None;
        }
        if count >= MINUNIQUEIPS_TOTRUST
            && (100u64 * count as u64) / total_signers as u64 >= MINPERCENTAGE_TOTRUST
        {
            Some(root)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
        [a, b, c, d]
    }

    #[test]
    fn single_proposal_is_not_trusted() {
        let mut acc = AichRootCorroboration::default();
        assert!(acc.record([1u8; 20], ip(203, 0, 113, 7)));
        assert_eq!(acc.trusted_root(), None);
    }

    #[test]
    fn ten_unique_ips_unanimous_promotes() {
        let mut acc = AichRootCorroboration::default();
        for i in 0..10u8 {
            // Distinct /20 networks so masking keeps them unique.
            assert!(acc.record([9u8; 20], ip(203, i, 0, 7)));
        }
        assert_eq!(acc.trusted_root(), Some([9u8; 20]));
    }

    #[test]
    fn same_subnet_does_not_inflate_unique_count() {
        let mut acc = AichRootCorroboration::default();
        // Ten addresses, all in the same /20 -> one unique signer.
        for d in 0..10u8 {
            acc.record([5u8; 20], ip(198, 51, 0, d));
        }
        assert_eq!(acc.trusted_root(), None);
    }

    #[test]
    fn minority_root_below_percentage_is_not_trusted() {
        let mut acc = AichRootCorroboration::default();
        // Leading root: 10 unique IPs.
        for i in 0..10u8 {
            acc.record([7u8; 20], ip(203, i, 0, 1));
        }
        // Dissenting root: 2 unique IPs -> leader holds 10/12 = 83% < 92%.
        acc.record([8u8; 20], ip(10, 0, 0, 1));
        acc.record([8u8; 20], ip(10, 16, 0, 1));
        assert_eq!(acc.trusted_root(), None);
    }

    #[test]
    fn signer_cannot_vote_for_two_roots() {
        let mut acc = AichRootCorroboration::default();
        let signer = ip(203, 0, 113, 7);
        assert!(acc.record([1u8; 20], signer));
        assert!(!acc.record([2u8; 20], signer));

        for i in 1..10u8 {
            assert!(acc.record([1u8; 20], ip(203, i, 0, 7)));
        }
        assert_eq!(acc.trusted_root(), Some([1u8; 20]));
    }

    #[test]
    fn signer_mask_matches_stock_little_endian_integer_mask() {
        for octets in [[1, 2, 15, 255], [1, 2, 16, 1], [203, 0, 113, 7]] {
            let stock = u32::from_le_bytes(octets) & 0x00F0_FFFF;
            assert_eq!(mask_signer_ip(octets), stock.to_le_bytes());
        }
        assert_eq!(mask_signer_ip([1, 2, 15, 255]), [1, 2, 0, 0]);
        assert_eq!(mask_signer_ip([1, 2, 16, 1]), [1, 2, 16, 0]);
    }

    #[test]
    fn later_disagreement_reconsiders_consensus_at_stock_percentage_boundary() {
        let mut acc = AichRootCorroboration::default();
        for signer in 0..92 {
            acc.record([1; 20], [203, signer, 0, 1]);
        }
        for signer in 0..8 {
            acc.record([2; 20], [198, signer, 0, 1]);
        }
        assert_eq!(acc.trusted_root(), Some([1; 20]));
        acc.record([2; 20], [198, 8, 0, 1]);
        assert_eq!(acc.trusted_root(), None);
    }

    #[test]
    fn candidate_limit_does_not_freeze_previously_trusted_sample() {
        let mut acc = AichRootCorroboration::default();
        for signer in 0..10 {
            acc.record([1; 20], [203, signer, 0, 1]);
        }
        assert_eq!(acc.trusted_root(), Some([1; 20]));
        for candidate in 2..=u8::try_from(MAX_CANDIDATES).unwrap() {
            acc.record([candidate; 20], [198, candidate, 0, 1]);
        }
        assert!(!acc.record([0xff; 20], [192, 0, 0, 1]));
        assert_eq!(acc.counts.len(), MAX_CANDIDATES);
        assert_eq!(acc.trusted_root(), None);
    }

    #[test]
    fn signer_limit_is_bounded_and_fails_closed() {
        let mut acc = AichRootCorroboration::default();
        for signer in 0..MAX_SIGNERS {
            let bytes = u16::try_from(signer).unwrap().to_be_bytes();
            acc.record([1; 20], [bytes[0], bytes[1], 0, 1]);
        }
        assert_eq!(acc.trusted_root(), Some([1; 20]));
        assert!(!acc.record([1; 20], [200, 0, 0, 1]));
        assert_eq!(acc.proposals.len(), MAX_SIGNERS);
        assert_eq!(acc.trusted_root(), None);
    }
}
