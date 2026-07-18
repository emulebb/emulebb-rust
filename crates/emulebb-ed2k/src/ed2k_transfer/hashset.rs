use std::{fs, io::Read, path::Path, str::FromStr};

use anyhow::{Context, Result};
use md4::{Digest, Md4};
use sha1::Sha1;

use emulebb_kad_proto::Ed2kHash;

use super::{
    ED2K_EMBLOCK_SIZE, ED2K_PART_SIZE, Ed2kAichHashset, Ed2kResumeManifest, PAYLOAD_FILE_NAME,
};
pub(super) fn expected_md4_hash_count(file_size: u64) -> u16 {
    if file_size == 0 {
        return 0;
    }
    let whole_parts = file_size / ED2K_PART_SIZE;
    let count = whole_parts + u64::from(whole_parts > 0);
    u16::try_from(count).unwrap_or(u16::MAX)
}

pub(super) fn validate_md4_hashset(file_hash: &str, md4_hashset: &[[u8; 16]]) -> Result<()> {
    let expected = Ed2kHash::from_str(file_hash)
        .with_context(|| format!("invalid ED2K file hash {}", file_hash))?;
    if md4_hashset.is_empty() {
        return Ok(());
    }
    let mut hasher = Md4::new();
    for part_hash in md4_hashset {
        hasher.update(part_hash);
    }
    let digest: [u8; 16] = hasher.finalize().into();
    if digest != expected.0 {
        anyhow::bail!(
            "MD4 hashset does not reconstruct ED2K file hash {}",
            file_hash
        );
    }
    Ok(())
}

pub(super) fn build_md4_hashset_from_payload(
    payload_path: &Path,
    file_size: u64,
) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    build_md4_hashset_from_payload_with_progress(payload_path, file_size, None)
}

pub(super) fn build_md4_hashset_from_payload_with_progress(
    payload_path: &Path,
    file_size: u64,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<(Ed2kHash, Vec<[u8; 16]>)> {
    if file_size == 0 {
        anyhow::bail!("cannot build ED2K MD4 hashset for zero-sized file");
    }
    let mut file = fs::File::open(payload_path)
        .with_context(|| format!("failed to open ED2K payload {}", payload_path.display()))?;
    if file_size < ED2K_PART_SIZE {
        let digest = read_md4_digest_from_reader(&mut file, file_size, &mut progress)?;
        return Ok((Ed2kHash::from_bytes(digest), Vec::new()));
    }

    let part_count = chunk_count_for_size(file_size, ED2K_PART_SIZE);
    let mut part_hashes = Vec::with_capacity(usize::try_from(part_count + 1).unwrap_or(0));
    let mut remaining = file_size;
    while remaining > 0 {
        let part_size = remaining.min(ED2K_PART_SIZE);
        part_hashes.push(read_md4_digest_from_reader(
            &mut file,
            part_size,
            &mut progress,
        )?);
        remaining -= part_size;
    }
    if file_size.is_multiple_of(ED2K_PART_SIZE) {
        part_hashes.push(read_md4_digest_from_reader(&mut file, 0, &mut progress)?);
    }

    let mut file_hasher = Md4::new();
    for part_hash in &part_hashes {
        file_hasher.update(part_hash);
    }
    Ok((
        Ed2kHash::from_bytes(file_hasher.finalize().into()),
        part_hashes,
    ))
}

fn read_md4_digest_from_reader(
    file: &mut fs::File,
    size: u64,
    progress: &mut Option<&mut dyn FnMut(u64)>,
) -> Result<[u8; 16]> {
    let mut hasher = Md4::new();
    let mut remaining = size;
    let mut buffer = vec![0u8; 65_536];
    while remaining > 0 {
        let chunk_len =
            usize::try_from(remaining.min(u64::try_from(buffer.len()).unwrap_or(0))).unwrap_or(0);
        file.read_exact(&mut buffer[..chunk_len])
            .context("failed to read ED2K MD4 payload data")?;
        hasher.update(&buffer[..chunk_len]);
        if let Some(progress) = progress.as_deref_mut() {
            progress(u64::try_from(chunk_len).unwrap_or(0));
        }
        remaining -= u64::try_from(chunk_len).unwrap_or(0);
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn decode_aich_hash_hex(hash: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(hash).with_context(|| format!("invalid AICH hash {hash}"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid AICH hash length {len}"))
}

pub(super) fn decode_manifest_aich_hashset(
    manifest: &Ed2kResumeManifest,
) -> Result<Ed2kAichHashset> {
    let root = manifest
        .aich_root
        .as_deref()
        .context("AICH root not available in manifest")?;
    let master_hash = decode_aich_hash_hex(root)?;
    let part_hashes = manifest
        .aich_hashset
        .iter()
        .map(|hash| decode_aich_hash_hex(hash))
        .collect::<Result<Vec<_>>>()?;
    if manifest.aich_hashset_acquired {
        validate_aich_hashset(
            manifest.file_size,
            &Ed2kAichHashset {
                master_hash,
                part_hashes: part_hashes.clone(),
            },
        )?;
    }
    Ok(Ed2kAichHashset {
        master_hash,
        part_hashes,
    })
}

fn expected_aich_hash_count(file_size: u64) -> u16 {
    if file_size <= ED2K_PART_SIZE {
        return 0;
    }
    let count = file_size.div_ceil(ED2K_PART_SIZE);
    u16::try_from(count).unwrap_or(u16::MAX)
}

pub(super) fn validate_aich_hashset(file_size: u64, aich_hashset: &Ed2kAichHashset) -> Result<()> {
    let expected = usize::from(expected_aich_hash_count(file_size));
    if aich_hashset.part_hashes.len() != expected {
        anyhow::bail!(
            "unexpected AICH hashset length {} expected {} for file size {}",
            aich_hashset.part_hashes.len(),
            expected,
            file_size
        );
    }
    if expected == 0 {
        return Ok(());
    }
    let reconstructed =
        reconstruct_aich_root_from_part_hashes(file_size, &aich_hashset.part_hashes)?;
    if reconstructed != aich_hashset.master_hash {
        anyhow::bail!("AICH hashset does not reconstruct the advertised master hash");
    }
    Ok(())
}

fn reconstruct_aich_root_from_part_hashes(
    file_size: u64,
    part_hashes: &[[u8; 20]],
) -> Result<[u8; 20]> {
    fn build_part_root(
        start: u64,
        size: u64,
        is_left_branch: bool,
        part_hashes: &[[u8; 20]],
    ) -> Result<[u8; 20]> {
        if size <= ED2K_PART_SIZE {
            let part_index =
                usize::try_from(start / ED2K_PART_SIZE).context("AICH part index exceeds usize")?;
            return part_hashes
                .get(part_index)
                .copied()
                .with_context(|| format!("missing AICH part hash at index {part_index}"));
        }
        let part_count = size / ED2K_PART_SIZE + u64::from(!size.is_multiple_of(ED2K_PART_SIZE));
        let left_size = ((part_count + u64::from(is_left_branch)) / 2) * ED2K_PART_SIZE;
        let right_size = size - left_size;
        let left = build_part_root(start, left_size, true, part_hashes)?;
        let right = build_part_root(start + left_size, right_size, false, part_hashes)?;
        Ok(sha1_pair(left, right))
    }

    build_part_root(0, file_size, true, part_hashes)
}

pub(super) fn refresh_completed_manifest_aich_hashset(
    transfer_dir: &Path,
    manifest: &mut Ed2kResumeManifest,
) -> Result<()> {
    // Once a modern peer has supplied a canonical AICH identity, keep serving
    // that network-learned root/hashset instead of replacing it on completion.
    // Completion-time synthesis is only for files that finished without any
    // prior AICH metadata.
    if manifest.aich_root.is_some() {
        return Ok(());
    }
    let payload_path = transfer_dir.join(PAYLOAD_FILE_NAME);
    let aich_hashset = build_aich_hashset_from_payload(&payload_path, manifest.file_size)?;
    manifest.aich_root = Some(hex::encode(aich_hashset.master_hash));
    manifest.aich_hashset = aich_hashset.part_hashes.iter().map(hex::encode).collect();
    manifest.aich_hashset_acquired = true;
    Ok(())
}

pub(super) fn build_aich_hashset_from_payload(
    payload_path: &Path,
    file_size: u64,
) -> Result<Ed2kAichHashset> {
    build_aich_hashset_from_payload_with_progress(payload_path, file_size, None)
}

pub(super) fn build_aich_hashset_from_payload_with_progress(
    payload_path: &Path,
    file_size: u64,
    mut progress: Option<&mut dyn FnMut(u64)>,
) -> Result<Ed2kAichHashset> {
    if file_size == 0 {
        anyhow::bail!("cannot build AICH hashset for zero-sized file");
    }
    let mut file = fs::File::open(payload_path)
        .with_context(|| format!("failed to open AICH payload {}", payload_path.display()))?;
    if file_size <= ED2K_PART_SIZE {
        let master_hash =
            build_aich_part_root_from_reader(&mut file, file_size, true, &mut progress)?;
        return Ok(Ed2kAichHashset {
            master_hash,
            part_hashes: Vec::new(),
        });
    }

    let mut part_hashes = Vec::with_capacity(usize::from(expected_aich_hash_count(file_size)));
    collect_aich_part_hashes_from_reader(
        &mut file,
        file_size,
        true,
        &mut part_hashes,
        &mut progress,
    )?;
    let master_hash = reconstruct_aich_root_from_part_hashes(file_size, &part_hashes)?;
    Ok(Ed2kAichHashset {
        master_hash,
        part_hashes,
    })
}

fn collect_aich_part_hashes_from_reader(
    file: &mut fs::File,
    size: u64,
    is_left_branch: bool,
    part_hashes: &mut Vec<[u8; 20]>,
    progress: &mut Option<&mut dyn FnMut(u64)>,
) -> Result<()> {
    if size <= ED2K_PART_SIZE {
        part_hashes.push(build_aich_part_root_from_reader(
            file,
            size,
            is_left_branch,
            progress,
        )?);
        return Ok(());
    }

    let part_count = chunk_count_for_size(size, ED2K_PART_SIZE);
    let left_size = ((part_count + u64::from(is_left_branch)) / 2) * ED2K_PART_SIZE;
    let right_size = size - left_size;
    collect_aich_part_hashes_from_reader(file, left_size, true, part_hashes, progress)?;
    collect_aich_part_hashes_from_reader(file, right_size, false, part_hashes, progress)
}

fn build_aich_part_root_from_reader(
    file: &mut fs::File,
    part_size: u64,
    is_left_branch: bool,
    progress: &mut Option<&mut dyn FnMut(u64)>,
) -> Result<[u8; 20]> {
    let block_hashes = read_aich_block_hashes_from_reader(file, part_size, progress)?;
    build_aich_block_tree_root(part_size, is_left_branch, &block_hashes, 0)
}

fn read_aich_block_hashes_from_reader(
    file: &mut fs::File,
    size: u64,
    progress: &mut Option<&mut dyn FnMut(u64)>,
) -> Result<Vec<[u8; 20]>> {
    let mut block_hashes = Vec::with_capacity(
        usize::try_from(chunk_count_for_size(size, ED2K_EMBLOCK_SIZE)).unwrap_or(0),
    );
    let mut remaining = size;
    let mut buffer = vec![0u8; usize::try_from(ED2K_EMBLOCK_SIZE).unwrap_or(0)];
    while remaining > 0 {
        let block_len = usize::try_from(remaining.min(ED2K_EMBLOCK_SIZE)).unwrap_or(0);
        file.read_exact(&mut buffer[..block_len])
            .context("failed to read AICH block data from payload")?;
        let digest = Sha1::digest(&buffer[..block_len]);
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&digest);
        block_hashes.push(hash);
        if let Some(progress) = progress.as_deref_mut() {
            progress(u64::try_from(block_len).unwrap_or(0));
        }
        remaining -= u64::try_from(block_len).unwrap_or(0);
    }
    Ok(block_hashes)
}

fn build_aich_block_tree_root(
    size: u64,
    is_left_branch: bool,
    block_hashes: &[[u8; 20]],
    block_offset: usize,
) -> Result<[u8; 20]> {
    if size <= ED2K_EMBLOCK_SIZE {
        return block_hashes
            .get(block_offset)
            .copied()
            .with_context(|| format!("missing AICH block hash at index {block_offset}"));
    }

    let block_count = chunk_count_for_size(size, ED2K_EMBLOCK_SIZE);
    let left_size = ((block_count + u64::from(is_left_branch)) / 2) * ED2K_EMBLOCK_SIZE;
    let right_size = size - left_size;
    let left_hash = build_aich_block_tree_root(left_size, true, block_hashes, block_offset)?;
    let right_offset = block_offset
        + usize::try_from(chunk_count_for_size(left_size, ED2K_EMBLOCK_SIZE))
            .context("AICH block offset exceeds usize")?;
    let right_hash = build_aich_block_tree_root(right_size, false, block_hashes, right_offset)?;
    Ok(sha1_pair(left_hash, right_hash))
}

fn chunk_count_for_size(size: u64, chunk_size: u64) -> u64 {
    size / chunk_size + u64::from(!size.is_multiple_of(chunk_size))
}

fn sha1_pair(left: [u8; 20], right: [u8; 20]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    let digest = hasher.finalize();
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&digest);
    hash
}
