use super::*;

impl EmulebbCore {
    pub async fn friends(&self) -> Result<Vec<Friend>> {
        let state = self.state.lock().await;
        self.persistence_owner.check_friend_state()?;
        Ok(state.friends.values().cloned().collect())
    }

    pub async fn add_friend(&self, request: FriendCreate) -> Result<Friend> {
        let user_hash = normalize_user_hash(&request.user_hash)?;
        let name = normalize_friend_name(request.name.as_deref())?;
        Ok(self
            .persistence_owner
            .owner(&self.metadata_store, &self.state)?
            .add(user_hash, name)
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
        Ok(self.persistence_owner.close_and_drain().await?)
    }
}
