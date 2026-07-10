use super::*;

impl EmulebbCore {
    pub async fn friends(&self) -> Vec<Friend> {
        self.state.lock().await.friends.values().cloned().collect()
    }

    pub async fn add_friend(&self, request: FriendCreate) -> Result<Friend> {
        let user_hash = normalize_user_hash(&request.user_hash)?;
        let name = normalize_friend_name(request.name.as_deref())?;
        let mut state = self.state.lock().await;
        if let Some(friend) = state.friends.get(&user_hash) {
            return Ok(friend.clone());
        }
        let friend = Friend {
            user_hash: user_hash.clone(),
            name,
            last_seen: None,
            address: None,
            port: 0,
        };
        profile_state::persist_friend(&self.metadata_store, &friend)?;
        state.friends.insert(user_hash, friend.clone());
        Ok(friend)
    }

    pub async fn delete_friend(&self, user_hash: &str) -> Result<Option<Friend>> {
        let user_hash = normalize_user_hash(user_hash)?;
        let mut state = self.state.lock().await;
        let Some(friend) = state.friends.get(&user_hash).cloned() else {
            return Ok(None);
        };
        self.metadata_store.delete_friend(&user_hash)?;
        state.friends.remove(&user_hash);
        Ok(Some(friend))
    }
}
