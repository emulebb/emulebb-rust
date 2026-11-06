//! Validation at the stock-import and native hashing boundary uses one geometry.
use super::{
    ED2K_EMBLOCK_SIZE,
    hashset::{
        aich_part_specs_for_size, build_aich_block_tree_root,
        reconstruct_aich_root_from_part_hashes,
    },
};
use anyhow::{Result, ensure};

/// Validate packed, ordered leaves against a trusted master without payload I/O.
/// Returns part roots (also the sole root for a one-part file).
pub fn validate_aich_recovery_set(
    size: u64,
    master: [u8; 20],
    parts: &[Vec<u8>],
) -> Result<Vec<[u8; 20]>> {
    let (actual, roots) = recovery_roots(size, parts)?;
    ensure!(
        actual == master,
        "recovery leaves do not reconstruct AICH master"
    );
    Ok(roots)
}

pub(super) fn recovery_roots(size: u64, parts: &[Vec<u8>]) -> Result<([u8; 20], Vec<[u8; 20]>)> {
    ensure!(
        size > 0 && size <= 0x4000000000,
        "invalid recovery file size"
    );
    let specs = aich_part_specs_for_size(size)?;
    ensure!(parts.len() == specs.len(), "incomplete recovery set");
    let mut roots = Vec::with_capacity(specs.len());
    for (spec, packed) in specs.iter().zip(parts) {
        ensure!(
            packed.len() as u64 == spec.size.div_ceil(ED2K_EMBLOCK_SIZE) * 20,
            "invalid recovery block count"
        );
        let leaves: Vec<[u8; 20]> = packed
            .chunks_exact(20)
            .map(|bytes| bytes.try_into().expect("fixed hash width"))
            .collect();
        roots.push(build_aich_block_tree_root(
            spec.size,
            spec.is_left_branch,
            &leaves,
            0,
        )?);
    }
    let actual = if roots.len() == 1 {
        roots[0]
    } else {
        reconstruct_aich_root_from_part_hashes(size, &roots)?
    };
    Ok((actual, roots))
}

#[cfg(test)]
mod tests {
    use super::super::{
        ED2K_PART_SIZE, aich_recovery::AichRecoveryHashSet,
        hashset::build_md4_and_aich_hashsets_from_reader_with_progress,
    };
    use super::*;

    #[test]
    fn large_file_recovery_uses_32bit_framing_without_a_payload() {
        let size = u64::from(u32::MAX) + 2;
        let parts: Vec<Vec<u8>> = (0..size.div_ceil(ED2K_PART_SIZE))
            .map(|index| {
                vec![
                    0x59;
                    ((size - index * ED2K_PART_SIZE)
                        .min(ED2K_PART_SIZE)
                        .div_ceil(ED2K_EMBLOCK_SIZE)
                        * 20) as usize
                ]
            })
            .collect();
        let (master, roots) = recovery_roots(size, &parts).unwrap();
        for index in [0, parts.len() - 1] {
            let mut cached = AichRecoveryHashSet::from_cached_part(
                size,
                master,
                &roots,
                index as u16,
                &parts[index],
            )
            .unwrap();
            let body = cached.create_part_recovery_data(index as u64).unwrap();
            assert_eq!(&body[..2], &[0, 0]);
            let leaves = super::super::aich_recovery::trusted_part_block_hashes_from_recovery(
                size,
                master,
                index as u64,
                &body,
            )
            .unwrap();
            assert_eq!(leaves.len() * 20, parts[index].len());
        }
    }

    #[test]
    fn cached_proofs_match_full_payload_tree_at_boundaries() {
        for size in [184_321, 9_728_000, 9_728_001, 19_456_123] {
            let data = vec![0x5a; size];
            let hashed = build_md4_and_aich_hashsets_from_reader_with_progress(
                &mut data.as_slice(),
                size as u64,
                None,
            )
            .unwrap();
            let master = hashed.aich_hashset.master_hash;
            let roots =
                validate_aich_recovery_set(size as u64, master, &hashed.recovery_parts).unwrap();
            let mut full = AichRecoveryHashSet::new(size as u64);
            full.build_from_data(&data).unwrap();
            for (index, packed) in hashed.recovery_parts.iter().enumerate() {
                if size as u64 - index as u64 * ED2K_PART_SIZE <= ED2K_EMBLOCK_SIZE {
                    continue;
                }
                let mut cached = AichRecoveryHashSet::from_cached_part(
                    size as u64,
                    master,
                    &roots,
                    index as u16,
                    packed,
                )
                .unwrap();
                assert_eq!(
                    cached.create_part_recovery_data(index as u64).unwrap(),
                    full.create_part_recovery_data(index as u64).unwrap()
                );
            }
            let mut corrupt = hashed.recovery_parts;
            corrupt[0][0] ^= 1;
            assert!(validate_aich_recovery_set(size as u64, master, &corrupt).is_err());
            corrupt[0].pop();
            assert!(validate_aich_recovery_set(size as u64, master, &corrupt).is_err());
        }
    }
}
