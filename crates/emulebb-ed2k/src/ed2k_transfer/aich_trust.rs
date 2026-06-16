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
//! roots (computed locally from a completed file, or read back from persisted
//! `.met`/manifest metadata) bypass corroboration entirely and are promoted
//! directly via `reconcile_aich_root`.

use std::collections::HashMap;

/// How many distinct IPs must propose the same AICH root before it is trusted.
/// Mirrors `MINUNIQUEIPS_TOTRUST` (`SHAHashSet.cpp:40`).
pub(super) const MINUNIQUEIPS_TOTRUST: usize = 10;

/// Minimum share (percent) of all proposing IPs that the leading root must hold
/// before it is trusted. Mirrors `MINPERCENTAGE_TOTRUST` (`SHAHashSet.cpp:41`).
pub(super) const MINPERCENTAGE_TOTRUST: u64 = 92;

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

/// Per-file accumulator of network-proposed AICH roots and the distinct IPs
/// that proposed each one. In-memory only (live session trust state, never
/// persisted): the durable trust decision lives in `manifest.aich_root`, which
/// is only written once a root is promoted.
#[derive(Debug, Default)]
pub(super) struct AichRootCorroboration {
    /// candidate root hash -> set of masked proposing IPs.
    proposals: HashMap<[u8; 20], Vec<[u8; 4]>>,
}

impl AichRootCorroboration {
    /// Record that `from_ip` proposed `root`. Returns `true` if this proposal
    /// (root, masked-IP pair) was new, i.e. it changed the accumulated state.
    pub(super) fn record(&mut self, root: [u8; 20], from_ip: [u8; 4]) -> bool {
        let masked = mask_signer_ip(from_ip);
        let signers = self.proposals.entry(root).or_default();
        if signers.contains(&masked) {
            return false;
        }
        signers.push(masked);
        true
    }

    /// Return the leading root if it now satisfies the master's trust gate:
    /// `>= MINUNIQUEIPS_TOTRUST` distinct IPs AND `>= MINPERCENTAGE_TOTRUST`
    /// percent of all proposing IPs. Mirrors `SHAHashSet.cpp:998`.
    pub(super) fn trusted_root(&self) -> Option<[u8; 20]> {
        let mut total_signers: usize = 0;
        let mut leader: Option<([u8; 20], usize)> = None;
        for (root, signers) in &self.proposals {
            let count = signers.len();
            total_signers += count;
            if leader.is_none_or(|(_, best)| count > best) {
                leader = Some((*root, count));
            }
        }
        let (root, count) = leader?;
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
}
