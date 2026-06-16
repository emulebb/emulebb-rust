use super::DhtNode;
use crate::error::DhtError;
use emulebb_kad_net::RpcWorkClass;
use emulebb_kad_proto::{Ed2kHash, NodeId, Tag};

impl DhtNode {
    /// Publish a keyword -> file mapping.
    pub async fn publish_keyword(
        &self,
        keyword_hash: NodeId,
        file_hash: Ed2kHash,
        tags: Vec<Tag>,
        aich_hash: Option<[u8; 20]>,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        self.publish_keyword_with_class_and_fanout(
            keyword_hash,
            file_hash,
            tags,
            aich_hash,
            RpcWorkClass::Publish,
            self.inner.config.publish_contact_fanout,
        )
        .await
    }

    /// Publish a keyword -> file mapping under an explicit work class and fanout.
    pub async fn publish_keyword_with_class_and_fanout(
        &self,
        keyword_hash: NodeId,
        file_hash: Ed2kHash,
        tags: Vec<Tag>,
        aich_hash: Option<[u8; 20]>,
        work_class: RpcWorkClass,
        publish_contact_fanout: usize,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        crate::publish::publish_keyword(
            &self.inner.rpc,
            &self.inner.routing_table,
            crate::publish::KeywordPublishRequest {
                keyword_hash,
                file_hash,
                tags,
                aich_hash,
                publish_contact_fanout,
                work_class,
            },
            self.ip_filter(),
        )
        .await
    }

    /// Publish source availability for a file.
    pub async fn publish_source(
        &self,
        file_hash: Ed2kHash,
        publisher_id: NodeId,
        tags: Vec<Tag>,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        self.publish_source_with_class_and_fanout(
            file_hash,
            publisher_id,
            tags,
            RpcWorkClass::Publish,
            self.inner.config.publish_contact_fanout,
        )
        .await
    }

    /// Publish source availability for a file under an explicit work class and fanout.
    pub async fn publish_source_with_class_and_fanout(
        &self,
        file_hash: Ed2kHash,
        publisher_id: NodeId,
        tags: Vec<Tag>,
        work_class: RpcWorkClass,
        publish_contact_fanout: usize,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        crate::publish::publish_source(
            &self.inner.rpc,
            &self.inner.routing_table,
            publisher_id,
            file_hash,
            tags,
            publish_contact_fanout,
            work_class,
            self.ip_filter(),
        )
        .await
    }

    /// Publish a note/rating for a file.
    ///
    /// The publisher identity is the Kad node ID written into the second
    /// 128-bit field of `KADEMLIA2_PUBLISH_NOTES_REQ`.
    pub async fn publish_notes(
        &self,
        file_hash: Ed2kHash,
        publisher_id: NodeId,
        tags: Vec<Tag>,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        self.publish_notes_with_class_and_fanout(
            file_hash,
            publisher_id,
            tags,
            RpcWorkClass::Publish,
            self.inner.config.publish_contact_fanout,
        )
        .await
    }

    /// Publish a note/rating under an explicit work class and fanout.
    pub async fn publish_notes_with_class_and_fanout(
        &self,
        file_hash: Ed2kHash,
        publisher_id: NodeId,
        tags: Vec<Tag>,
        work_class: RpcWorkClass,
        publish_contact_fanout: usize,
    ) -> Result<crate::publish::PublishAttemptStats, DhtError> {
        crate::publish::publish_notes(
            &self.inner.rpc,
            &self.inner.routing_table,
            file_hash,
            publisher_id,
            tags,
            publish_contact_fanout,
            work_class,
            self.ip_filter(),
        )
        .await
    }
}
