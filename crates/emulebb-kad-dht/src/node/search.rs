use super::{DhtNode, contact_helpers::addr_from_contact};
use crate::error::DhtError;
use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use crate::types::{NoteResult, SearchResult, SourceResult};
use emulebb_kad_net::RpcWorkClass;
use emulebb_kad_proto::{Ed2kHash, NodeId, SearchKeyReq, SearchSourceReq, constants::K};
use emulebb_kad_routing::Contact;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

impl DhtNode {
    /// Iterative node lookup. Returns up to K contacts closest to target.
    pub async fn lookup_nodes(&self, target: &NodeId) -> Result<Vec<TraversalContact>, DhtError> {
        self.lookup_nodes_with_class(target, RpcWorkClass::Interactive)
            .await
    }

    /// Iterative node lookup. Returns up to K contacts closest to target.
    pub async fn lookup_nodes_with_class(
        &self,
        target: &NodeId,
        work_class: RpcWorkClass,
    ) -> Result<Vec<TraversalContact>, DhtError> {
        let initial = {
            let rt = self.inner.routing_table.lock().await;
            rt.get_closest(target, K)
                .into_iter()
                .map(|c| TraversalContact {
                    id: c.id,
                    addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
                    version: c.kad_version,
                })
                .collect::<Vec<_>>()
        };

        let config = TraversalConfig {
            target: *target,
            search_kind: TraversalKind::FindNode,
            timeout: Duration::from_secs(45),
            query_timeout: Duration::from_secs(10),
            phase2_fanout: self.inner.config.search_phase2_fanout,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
            ip_filter: self.ip_filter(),
        };

        let result = run_traversal(&self.inner.rpc, initial, config).await;

        // Add discovered contacts to routing table
        {
            let mut rt = self.inner.routing_table.lock().await;
            for contact in &result.closest {
                let ip = match contact.addr.ip() {
                    IpAddr::V4(ip) => ip,
                    _ => continue,
                };
                let c = Contact::new(
                    contact.id,
                    ip,
                    contact.addr.port(),
                    contact.addr.port(), // use same port for tcp as fallback
                    contact.version,
                );
                self.inner
                    .rpc
                    .register_peer_identity(addr_from_contact(&c), c.id);
                let _ = rt.add_contact(c);
            }
        }

        Ok(result.closest)
    }

    /// Search by keyword hash. Returns a Stream of results.
    pub fn search_keywords(
        &self,
        target: NodeId,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keywords_with_cancel(target, CancellationToken::new())
    }

    pub fn search_keywords_with_cancel(
        &self,
        target: NodeId,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keywords_with_cancel_and_class(target, cancel, RpcWorkClass::Interactive)
    }

    pub fn search_keywords_with_cancel_and_class(
        &self,
        target: NodeId,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_cancel_and_class(
            SearchKeyReq {
                target,
                start_position: 0,
                restrictive_payload: Vec::new(),
            },
            cancel,
            work_class,
        )
    }

    /// Replay a full Kad keyword request shape harvested from the network.
    pub fn search_keyword_request(
        &self,
        request: SearchKeyReq,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_cancel_and_class(
            request,
            CancellationToken::new(),
            RpcWorkClass::Interactive,
        )
    }

    pub fn search_keyword_request_with_cancel(
        &self,
        request: SearchKeyReq,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_cancel_and_class(
            request,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    pub fn search_keyword_request_with_cancel_and_class(
        &self,
        request: SearchKeyReq,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_phase2_fanout_and_cancel_and_class(
            request,
            self.inner.config.search_phase2_fanout,
            cancel,
            work_class,
        )
    }

    /// Replay a harvested Kad keyword request shape with an explicit phase-2
    /// responder ceiling.
    pub fn search_keyword_request_with_phase2_fanout_and_cancel(
        &self,
        request: SearchKeyReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        self.search_keyword_request_with_phase2_fanout_and_cancel_and_class(
            request,
            phase2_fanout,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    /// Replay a harvested Kad keyword request shape with an explicit phase-2
    /// responder ceiling and outbound work class.
    pub fn search_keyword_request_with_phase2_fanout_and_cancel_and_class(
        &self,
        request: SearchKeyReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
        let target = request.target;
        let initial = self.closest_search_contacts(target);
        crate::search::search_keywords_by_request(
            self.inner.rpc.clone(),
            initial,
            request,
            self.inner.config.keyword_result_cap,
            phase2_fanout,
            cancel,
            work_class,
            self.ip_filter(),
        )
    }

    /// Search for file sources. Returns a Stream of results.
    pub fn search_sources(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_sources_with_cancel(file_hash, file_size, CancellationToken::new())
    }

    pub fn search_sources_with_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_sources_with_cancel_and_class(
            file_hash,
            file_size,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    pub fn search_sources_with_cancel_and_class(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel_and_class(
            SearchSourceReq {
                target: NodeId::from_be_bytes(file_hash.0),
                start_position: 0,
                size: file_size,
            },
            self.inner.config.search_phase2_fanout,
            cancel,
            work_class,
        )
    }

    /// Replay a full Kad source request shape harvested from the network.
    pub fn search_source_request(
        &self,
        request: SearchSourceReq,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_cancel_and_class(
            request,
            CancellationToken::new(),
            RpcWorkClass::Interactive,
        )
    }

    pub fn search_source_request_with_cancel(
        &self,
        request: SearchSourceReq,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_cancel_and_class(request, cancel, RpcWorkClass::Interactive)
    }

    pub fn search_source_request_with_cancel_and_class(
        &self,
        request: SearchSourceReq,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel_and_class(
            request,
            self.inner.config.search_phase2_fanout,
            cancel,
            work_class,
        )
    }

    /// Search for file sources with an explicit phase-2 responder ceiling while
    /// preserving the full request shape.
    pub fn search_source_request_with_phase2_fanout_and_cancel(
        &self,
        request: SearchSourceReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel_and_class(
            request,
            phase2_fanout,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    /// Search for file sources with an explicit phase-2 responder ceiling while
    /// preserving the full request shape and work class.
    pub fn search_source_request_with_phase2_fanout_and_cancel_and_class(
        &self,
        request: SearchSourceReq,
        phase2_fanout: usize,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        let target = request.target;
        let initial = self.closest_search_contacts(target);
        crate::search::search_sources_by_request(
            self.inner.rpc.clone(),
            initial,
            request,
            self.inner.config.source_result_cap,
            phase2_fanout,
            cancel,
            work_class,
            self.ip_filter(),
        )
    }

    /// Search for file sources with an explicit phase-2 responder ceiling.
    pub fn search_sources_with_phase2_fanout_and_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
        self.search_source_request_with_phase2_fanout_and_cancel(
            SearchSourceReq {
                target: NodeId::from_be_bytes(file_hash.0),
                start_position: 0,
                size: file_size,
            },
            phase2_fanout,
            cancel,
        )
    }

    /// Search for notes/ratings. Returns a Stream of results.
    pub fn search_notes(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_cancel(file_hash, file_size, CancellationToken::new())
    }

    pub fn search_notes_with_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_cancel_and_class(
            file_hash,
            file_size,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    pub fn search_notes_with_cancel_and_class(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_phase2_fanout_and_cancel_and_class(
            file_hash,
            file_size,
            self.inner.config.search_phase2_fanout,
            cancel,
            work_class,
        )
    }

    /// Search for notes/ratings with an explicit phase-2 responder ceiling.
    pub fn search_notes_with_phase2_fanout_and_cancel(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        phase2_fanout: usize,
        cancel: CancellationToken,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        self.search_notes_with_phase2_fanout_and_cancel_and_class(
            file_hash,
            file_size,
            phase2_fanout,
            cancel,
            RpcWorkClass::Interactive,
        )
    }

    /// Search for notes/ratings with an explicit phase-2 responder ceiling and work class.
    pub fn search_notes_with_phase2_fanout_and_cancel_and_class(
        &self,
        file_hash: Ed2kHash,
        file_size: u64,
        phase2_fanout: usize,
        cancel: CancellationToken,
        work_class: RpcWorkClass,
    ) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
        let target = NodeId::from_be_bytes(file_hash.0);
        let initial = self.closest_search_contacts(target);
        crate::search::search_notes(
            self.inner.rpc.clone(),
            initial,
            crate::search::NotesSearchRequest {
                file_hash,
                file_size,
            },
            self.inner.config.notes_result_cap,
            phase2_fanout,
            cancel,
            work_class,
            self.ip_filter(),
        )
    }

    /// Returns the routing-table contacts used to seed one Kad search walk.
    fn closest_search_contacts(&self, target: NodeId) -> Vec<TraversalContact> {
        match self.inner.routing_table.try_lock() {
            Ok(rt) => rt
                .get_closest(&target, K)
                .into_iter()
                .map(|c| TraversalContact {
                    id: c.id,
                    addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
                    version: c.kad_version,
                })
                .collect(),
            Err(_) => vec![],
        }
    }
}
