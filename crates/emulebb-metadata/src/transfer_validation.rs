//! Persistence admission for transfer state and payload geometry.
use crate::{
    MetadataTransferDeliveryOwnership, MetadataTransferDeliveryState, MetadataTransferManifest,
};
use anyhow::{Context, Result, ensure};

pub(crate) fn validate_manifest(manifest: &MetadataTransferManifest) -> Result<()> {
    ensure!(
        manifest.aich_root.is_some() == manifest.aich_root_origin.is_some(),
        "AICH root and accepted origin must be present together"
    );
    if let Some(origin) = manifest.aich_root_origin.as_deref() {
        ensure!(
            matches!(
                origin,
                "local_computed" | "operator_link" | "stock_import" | "network_consensus"
            ),
            "invalid AICH root origin"
        );
    }
    ensure!(
        !manifest.aich_hashset_acquired || manifest.aich_root.is_some(),
        "acquired AICH part hashes require an accepted master"
    );
    i64::try_from(manifest.aich_trust_generation)?;
    ensure!(
        manifest.piece_size > 0,
        "transfer piece size must be positive"
    );
    for piece in &manifest.pieces {
        let start = u64::from(piece.piece_index)
            .checked_mul(manifest.piece_size)
            .context("transfer piece offset overflow")?;
        ensure!(
            start < manifest.file_size,
            "transfer piece starts outside the payload"
        );
        let extent = manifest.piece_size.min(manifest.file_size - start);
        ensure!(
            piece.bytes_written <= extent,
            "transfer piece progress exceeds its payload extent"
        );
    }
    for range in &manifest.verified_ranges {
        ensure!(
            range.start <= range.end && range.end <= manifest.file_size,
            "verified range is outside the payload"
        );
    }
    validate_delivery_state(manifest)
}

fn validate_delivery_state(manifest: &MetadataTransferManifest) -> Result<()> {
    let valid = match (manifest.delivery_state, manifest.delivery_ownership) {
        (MetadataTransferDeliveryState::Pending, MetadataTransferDeliveryOwnership::None) => {
            manifest.delivered_path.is_none()
        }
        (MetadataTransferDeliveryState::Delivered, MetadataTransferDeliveryOwnership::Owned) => {
            manifest.delivered_path.is_some()
                && manifest
                    .source_fingerprint
                    .as_ref()
                    .is_some_and(|fingerprint| fingerprint.size_bytes == manifest.file_size)
        }
        (MetadataTransferDeliveryState::Delivered, MetadataTransferDeliveryOwnership::Unowned) => {
            manifest.delivered_path.is_some()
        }
        _ => false,
    };
    if !valid {
        anyhow::bail!(
            "invalid delivery state {:?}/{:?} for transfer {}: delivered_path={}",
            manifest.delivery_state,
            manifest.delivery_ownership,
            manifest.file_hash,
            manifest.delivered_path.is_some()
        );
    }
    if let Some(fingerprint) = manifest.payload_fingerprint.as_ref() {
        ensure!(
            manifest.completed
                && !manifest.final_rehash_pending
                && fingerprint.size_bytes == manifest.file_size,
            "invalid canonical payload fingerprint for transfer {}",
            manifest.file_hash
        );
    }
    Ok(())
}
