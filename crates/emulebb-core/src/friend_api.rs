use super::*;

impl EmulebbCore {
    /// Stop accepting regular persistence work while allowing final Kad capture.
    pub fn stop_persistence_admission(&self) -> Result<()> {
        Ok(self.persistence_owner.stop_regular_admission()?)
    }
    /// Stop and join accepted local-share mutations.
    pub async fn drain_local_share_mutations(&self) -> Result<()> {
        self.ed2k_transfers.drain_local_mutations().await
    }
    pub async fn friends(&self) -> Result<Vec<Friend>> {
        let state = self.state.lock().await;
        self.persistence_owner.check_coherent_state()?;
        Ok(state.friends.values().cloned().collect())
    }

    pub async fn add_friend(&self, request: FriendCreate) -> Result<Friend> {
        let user_hash = normalize_user_hash(&request.user_hash)?;
        let name = normalize_friend_name(request.name.as_deref())?;
        let browse_key_sha256 = request
            .browse_key_sha256
            .as_deref()
            .map(|fingerprint| {
                let mut key = [0; 32];
                hex::decode_to_slice(fingerprint, &mut key).map_err(|_| {
                    anyhow::anyhow!("browse key fingerprint must be 64 hexadecimal digits")
                })?;
                Ok::<_, anyhow::Error>(key)
            })
            .transpose()?;
        Ok(self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?
            .add_with_browse_key(user_hash, name, browse_key_sha256)
            .await?)
    }

    pub async fn delete_friend(&self, user_hash: &str) -> Result<Option<Friend>> {
        let user_hash = normalize_user_hash(user_hash)?;
        Ok(self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?
            .delete(user_hash)
            .await?)
    }

    /// Close persistence admission and finish all accepted mutations.
    pub async fn drain_persistence(&self) -> Result<()> {
        self.begin_shutdown();
        let admission = self.stop_persistence_admission();
        let monitor = self.stop_shared_directory_monitor().await;
        let owner = self.persistence_owner.close_and_drain().await;
        let reload = crate::shared_directories::drain_reload(self).await;
        let local = self.ed2k_transfers.drain_local_mutations().await;
        let root = crate::shared_dir_monitor::drain_root_sql(self).await;
        let reads = self.ed2k_transfers.drain_shared_eligibility().await;
        // WHY: refused requests have no upload-session release to flush their
        // tail. The daemon drains here after stopping network producers, before
        // releasing the profile; required accounting errors must surface.
        let accounting = self.ed2k_transfers.checkpoint_upload_accounting().await;
        admission?;
        monitor?;
        owner?;
        reload?;
        local?;
        root?;
        reads?;
        accounting?;
        Ok(())
    }
}
