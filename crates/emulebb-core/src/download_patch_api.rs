//! Canonical job scalar edits use the existing category publication owner.
use super::*;

impl EmulebbCore {
    pub async fn patch_download(
        &self,
        id: emulebb_metadata::JobId,
        update: DownloadUpdate,
    ) -> Result<DownloadChange> {
        emulebb_metadata::MetadataDownloadPatch::validate_fields(
            update.name.as_deref(),
            None,
            update.size_bytes,
        )?;
        if let Some(Some(name)) = &update.category {
            ensure!(
                emulebb_metadata::valid_category_name(name),
                DownloadPatchError::InvalidCategory
            );
        }
        self.persistence_owner.check_coherent_state()?;
        let owner = self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?;
        Ok(owner
            .patch_download(
                id,
                &update,
                &self.ed2k_transfers,
                &self.download_attempts,
                &self.download_events,
            )
            .await??)
    }
}
