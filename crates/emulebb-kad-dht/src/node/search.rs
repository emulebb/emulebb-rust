use super::{DhtNode, contact_helpers::addr_from_contact};
use crate::error::DhtError;
use crate::traversal::refresh::{NodeRefreshConfig, NodeRefreshOutcome, run_node_refresh_lookup};
use crate::traversal::{TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use crate::types::{NoteResult, SearchResult, SourceResult};
use emulebb_kad_net::RpcWorkClass;
use emulebb_kad_proto::packet::{CallbackReq, FindBuddyReq};
use emulebb_kad_proto::{
    Ed2kHash, NodeId, SearchKeyReq, SearchSourceReq,
    constants::{
        K, SEARCHFINDBUDDY_LIFETIME_SECS, SEARCHFINDBUDDY_TOTAL, SEARCHFINDSOURCE_LIFETIME_SECS,
        SEARCHFINDSOURCE_TOTAL, STORE_STOP_GRACE_SECS,
    },
};
use emulebb_kad_routing::Contact;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// FINDBUDDY walk budget: the oracle lifetime (`SEARCHFINDBUDDY_LIFETIME` =
/// 100 s) minus the shared 20 s stop grace the search manager applies before
/// deletion (`SearchManager.cpp:322-325`). The trailing grace only drains late
/// replies in MFC; our `FINDBUDDY_RES` handling lives in the unsolicited
/// dispatch, so the walk itself ends at the stop mark.
const FIND_BUDDY_LOOKUP_TIMEOUT: Duration =
    Duration::from_secs(SEARCHFINDBUDDY_LIFETIME_SECS - STORE_STOP_GRACE_SECS);
const FIND_SOURCE_LOOKUP_TIMEOUT: Duration =
    Duration::from_secs(SEARCHFINDSOURCE_LIFETIME_SECS - STORE_STOP_GRACE_SECS);

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
        // Oracle CSearchManager: drop a duplicate same-target lookup and cap the
        // number of concurrent traversals. The permit is held until the lookup
        // returns (or unwinds), releasing the slot + target on drop.
        let Ok(_permit) = self.try_acquire_search_permit(*target) else {
            return Ok(Vec::new());
        };
        let initial = self.closest_traversal_seed(target).await;

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
            res_contact_sink: Some(self.res_contact_sink()),
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
                // Prefer the real eD2k TCP port carried by the RES contact entry;
                // fall back to the UDP port only when the source advertised none
                // (tcp_port == 0), so a lookup-learned contact keeps the correct
                // eD2k endpoint instead of the UDP port.
                let tcp_port = if contact.tcp_port != 0 {
                    contact.tcp_port
                } else {
                    contact.addr.port()
                };
                let c = Contact::new(
                    contact.id,
                    ip,
                    contact.addr.port(),
                    tcp_port,
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

    /// Bucket-refresh NODE lookup (oracle `CSearchManager::FindNode(target,
    /// false)` -> `CSearch` type NODE): one initial `KADEMLIA2_REQ` to the
    /// closest known contact, jump-start retries while silent, stop on the
    /// first `RES` (Search.cpp:194,373-387). Answered contacts reach the
    /// routing table through the RES-contact sink (oracle `AddUnfiltered`);
    /// there is no convergence walk. Only for the hourly zone refresh —
    /// value/store/bootstrap lookups keep [`Self::lookup_nodes_with_class`].
    pub async fn refresh_node_lookup(
        &self,
        target: &NodeId,
        work_class: RpcWorkClass,
    ) -> NodeRefreshOutcome {
        // Oracle CSearchManager::StartSearch drops a duplicate same-target
        // search (AlreadySearchingFor); the permit also caps concurrency.
        let Ok(_permit) = self.try_acquire_search_permit(*target) else {
            return NodeRefreshOutcome::default();
        };
        let initial = self.closest_traversal_seed(target).await;
        let mut config = NodeRefreshConfig::new(*target, work_class);
        config.ip_filter = self.ip_filter();
        config.res_contact_sink = Some(self.res_contact_sink());
        run_node_refresh_lookup(&self.inner.rpc, initial, config).await
    }

    /// NODECOMPLETE self-lookup (oracle `CSearchManager::FindNode(GetKadID(),
    /// true)` -> `CSearch` type NODECOMPLETE, fired every 4 hours by
    /// `CKademlia::Process`, Kademlia.cpp:261-264). Unlike the feather-weight
    /// NODE refresh above, NODECOMPLETE is a full convergence walk:
    /// `CSearch::Go` fans out `ALPHA_QUERY` initial `KADEMLIA2_REQ`s
    /// (`iCount = (m_uType == NODE) ? 1 : min(ALPHA_QUERY, ...)`,
    /// Search.cpp:194), every `REQ` carries the NODE-family contact-count byte
    /// `KADEMLIA_FIND_NODE` (0x0B, Search.cpp:1643-1647), and a `RES` feeds
    /// closer candidates back into the walk instead of ending it (the
    /// stop-on-first-response path at Search.cpp:369-387 covers NODE and
    /// NODEFWCHECKUDP only; NODECOMPLETE runs the full response processing and
    /// counts answers, Search.cpp:515-518). That is exactly the
    /// [`Self::lookup_nodes_with_class`] traversal, whose 45 s budget matches
    /// the NODECOMPLETE hard lifetime (`SEARCHNODE_LIFETIME`, Defines.h:53).
    /// The oracle may delete the search earlier — 10 s old with >= 10 answers
    /// (`SEARCHNODECOMP_LIFETIME`/`SEARCHNODECOMP_TOTAL`,
    /// SearchManager.cpp:339-345, which also flips `SetPublish(true)`; our
    /// publish gating keys off bootstrap state instead) — while our walk ends
    /// on convergence, so the tail bookkeeping differs without changing which
    /// contacts get queried.
    pub async fn self_node_complete_lookup(
        &self,
        work_class: RpcWorkClass,
    ) -> Result<Vec<TraversalContact>, DhtError> {
        let own_id = self.inner.own_id;
        self.lookup_nodes_with_class(&own_id, work_class).await
    }

    /// FINDBUDDY buddy-acquisition walk (oracle `CSearchManager::FindBuddy` ->
    /// `CSearch` type FINDBUDDY): a full convergence lookup whose every
    /// `KADEMLIA2_REQ` requests the STORE contact count (`KADEMLIA_STORE` =
    /// 0x04, `Search.cpp:1653-1657`), followed by the jump-start action walk
    /// that sends the provided `KADEMLIA_FINDBUDDY_REQ` to each
    /// SEARCHTOLERANCE-passing responded contact (`Search.cpp:536,864-896`)
    /// up to `SEARCHFINDBUDDY_TOTAL` answers, all inside the oracle search
    /// lifetime minus its stop grace. `FINDBUDDY_RES` replies are consumed by
    /// the caller's unsolicited-packet dispatch, not collected here.
    pub async fn find_buddy_search(&self, request: FindBuddyReq, work_class: RpcWorkClass) {
        let target = request.buddy_id;
        // Oracle CSearchManager::StartSearch drops a duplicate same-target
        // search (AlreadySearchingFor); the permit also caps concurrency.
        let Ok(_permit) = self.try_acquire_search_permit(target) else {
            return;
        };
        let initial = self.closest_traversal_seed(&target).await;
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::FindBuddy { request },
            timeout: FIND_BUDDY_LOOKUP_TIMEOUT,
            query_timeout: Duration::from_secs(10),
            phase2_fanout: SEARCHFINDBUDDY_TOTAL,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
            ip_filter: self.ip_filter(),
            res_contact_sink: Some(self.res_contact_sink()),
        };
        let _ = run_traversal(&self.inner.rpc, initial, config).await;
    }

    /// Locate an unknown buddy endpoint and send the source callback request to
    /// close contacts, matching MFC's `CSearch::FINDSOURCE` fallback.
    pub async fn find_source_search(&self, request: CallbackReq, work_class: RpcWorkClass) {
        let target = request.buddy_id;
        let Ok(_permit) = self.try_acquire_search_permit(target) else {
            return;
        };
        let initial = self.closest_traversal_seed(&target).await;
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::FindSource { request },
            timeout: FIND_SOURCE_LOOKUP_TIMEOUT,
            query_timeout: Duration::from_secs(10),
            phase2_fanout: SEARCHFINDSOURCE_TOTAL,
            cancel: CancellationToken::new(),
            result_tx: None,
            work_class,
            ip_filter: self.ip_filter(),
            res_contact_sink: Some(self.res_contact_sink()),
        };
        let _ = run_traversal(&self.inner.rpc, initial, config).await;
    }

    /// Routing-table contacts closest to `target`, mapped into the traversal
    /// seed shape shared by every search walk.
    async fn closest_traversal_seed(&self, target: &NodeId) -> Vec<TraversalContact> {
        let rt = self.inner.routing_table.lock().await;
        rt.get_closest(target, K)
            .into_iter()
            .map(|c| TraversalContact {
                id: c.id,
                addr: SocketAddr::new(IpAddr::V4(c.ip), c.udp_port),
                tcp_port: c.tcp_port,
                version: c.kad_version,
            })
            .collect::<Vec<_>>()
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
            Some(self.res_contact_sink()),
            Some(self.search_concurrency()),
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
            Some(self.res_contact_sink()),
            Some(self.search_concurrency()),
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
            Some(self.res_contact_sink()),
            Some(self.search_concurrency()),
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
                    tcp_port: c.tcp_port,
                    version: c.kad_version,
                })
                .collect(),
            Err(_) => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FIND_BUDDY_LOOKUP_TIMEOUT, FIND_SOURCE_LOOKUP_TIMEOUT};
    use crate::{DhtConfig, DhtNode};
    use emulebb_kad_net::RpcWorkClass;
    use emulebb_kad_proto::{
        KadPacket, NodeId, constants::KADEMLIA_FIND_NODE, packet::Res as KadRes,
    };
    use emulebb_kad_routing::Contact;
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    /// FINDBUDDY honors the oracle 100 s search lifetime with the shared 20 s
    /// stop grace (`SEARCHFINDBUDDY_LIFETIME - SEC(20)`,
    /// `SearchManager.cpp:322-325`): the walk budget is exactly 80 s.
    #[test]
    fn find_buddy_walk_budget_is_lifetime_minus_stop_grace() {
        assert_eq!(FIND_BUDDY_LOOKUP_TIMEOUT.as_secs(), 80);
    }

    #[test]
    fn find_source_walk_budget_is_lifetime_minus_stop_grace() {
        assert_eq!(FIND_SOURCE_LOOKUP_TIMEOUT.as_secs(), 25);
    }

    /// The 4-hour NODECOMPLETE self-lookup targets our OWN KadID and goes on
    /// the wire as a `KADEMLIA2_REQ` with the NODE-family contact-count byte
    /// `KADEMLIA_FIND_NODE` (0x0B) — oracle
    /// `CSearchManager::FindNode(GetKadID(), true)` (Kademlia.cpp:261-264)
    /// through `CSearch::GetRequestContactCount` (Search.cpp:1643-1647).
    #[tokio::test]
    async fn self_node_complete_lookup_sends_find_node_req_for_own_id() {
        let bind_ip = crate::test_bind_ip();
        let peer = tokio::net::UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
            .await
            .unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let dht = DhtNode::new(DhtConfig {
            bind_addr: Some(SocketAddr::new(IpAddr::V4(bind_ip), 0)),
            obfuscation_enabled: false,
            ..DhtConfig::default()
        })
        .await
        .unwrap();
        let _handle = dht.start();
        dht.add_contact(Contact::new(
            NodeId::from_bytes([0x42; 16]),
            bind_ip,
            peer_addr.port(),
            4662,
            9,
        ))
        .await
        .unwrap();

        let own_id = dht.own_id();
        let lookup = tokio::spawn({
            let dht = dht.clone();
            async move {
                dht.self_node_complete_lookup(RpcWorkClass::Maintenance)
                    .await
            }
        });

        let mut buf = [0u8; 512];
        let (len, from) = tokio::time::timeout(Duration::from_secs(10), peer.recv_from(&mut buf))
            .await
            .expect("self-lookup REQ should arrive")
            .unwrap();
        let KadPacket::Req(req) = KadPacket::decode(&buf[..len]).unwrap() else {
            panic!("self-lookup must send a KADEMLIA2_REQ");
        };
        assert_eq!(req.count, KADEMLIA_FIND_NODE, "NODECOMPLETE count byte");
        assert_eq!(req.target, own_id, "self-lookup targets our own KadID");

        // Answer with an empty RES so the walk converges and returns.
        let res = KadPacket::Res(KadRes {
            target: own_id,
            contacts: Vec::new(),
        })
        .encode()
        .unwrap();
        peer.send_to(&res, from).await.unwrap();
        let closest = tokio::time::timeout(Duration::from_secs(30), lookup)
            .await
            .expect("self-lookup should finish once the pool is exhausted")
            .unwrap()
            .unwrap();
        assert_eq!(closest.len(), 1, "the sole responder is the closest set");
    }
}
