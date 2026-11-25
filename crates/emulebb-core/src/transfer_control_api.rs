use super::*;

use emulebb_ed2k::ed2k_tcp::{PeerBrowsePage, PeerBrowseStart};

impl EmulebbCore {
    pub async fn browse_download_source(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<PeerBrowseStart>> {
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        ensure!(
            source.view_shared_files,
            "transfer source is not connected for shared-file browsing"
        );
        self.ed2k_transfers
            .peer_browse_registry()
            .start(
                parse_ban_hash(source.user_hash.as_deref()),
                source.endpoint.parse()?,
            )
            .map(Some)
    }

    pub async fn download_source_browse_page(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
        search_id: u64,
        offset: usize,
        limit: usize,
    ) -> Result<Option<PeerBrowsePage>> {
        ensure!((1..=200).contains(&limit), "invalid peer browse page limit");
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        Ok(self.ed2k_transfers.peer_browse_registry().page_for_peer(
            parse_ban_hash(source.user_hash.as_deref()),
            source.endpoint.parse()?,
            search_id,
            offset,
            limit,
        ))
    }

    pub async fn add_download_source_friend(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            anyhow::bail!("transfer source does not expose a userHash");
        };
        self.add_friend(FriendCreate {
            user_hash: user_hash.to_string(),
            name: Some(source_friend_name(&source)),
            browse_key_sha256: None,
        })
        .await
        .map(Some)
    }

    pub async fn remove_download_source_friend(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<Friend>> {
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        let Some(user_hash) = source.user_hash.as_deref() else {
            return Ok(None);
        };
        self.delete_friend(user_hash).await
    }

    pub async fn ban_download_source(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<bool>> {
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        // Back the manual source ban with the enforced ban store (IP + user
        // hash, 4h TTL) so the source is rejected on the next connect / source
        // add (eMule CUpDownClient::Ban).
        self.ed2k_transfers.ban_client(
            parse_ban_ip(&source.ip),
            parse_ban_hash(source.user_hash.as_deref()),
        );
        Ok(Some(true))
    }

    pub async fn unban_download_source(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<bool>> {
        let Some(source) = self.download_source(id, client_id).await? else {
            return Ok(None);
        };
        let user_hash = parse_ban_hash(source.user_hash.as_deref());
        self.ed2k_transfers
            .ban_store()
            .unban(parse_ban_ip(&source.ip), user_hash.as_ref());
        Ok(Some(false))
    }

    pub async fn remove_download_source(
        &self,
        id: emulebb_metadata::JobId,
        client_id: &str,
    ) -> Result<Option<()>> {
        validate_source_client_id(client_id)?;
        let Some(job) = self.ed2k_transfers.download_job(id).await? else {
            return Ok(None);
        };
        if job.removed_at_s.is_some() {
            return Ok(None);
        }
        let token = job.token;
        drop(job);
        if !self.ed2k_transfers.remove_source(token, client_id).await? {
            return Ok(None);
        }
        Ok(Some(()))
    }
}
