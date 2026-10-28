use crate::node::concurrency::SearchPermit;
use crate::traversal::{
    KadIpFilter, KadResContactSink, MoreResultsMode, SearchResultObservation, TraversalConfig,
    TraversalContact, TraversalKind, run_traversal,
};
use crate::types::{KadSearchTerminalReason, NoteResult, SearchResult, SourceResult};
use emulebb_kad_net::{RpcManager, RpcWorkClass};
use emulebb_kad_proto::constants::SEARCH_RESULT_GRACE_SECS;
use emulebb_kad_proto::{
    Ed2kHash, NodeId, SearchKeyReq, SearchSourceReq, matches_restrictive_keyword_payload,
};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const SEARCH_RESULT_GRACE: Duration = Duration::from_secs(SEARCH_RESULT_GRACE_SECS);
/// Buffer used between traversal SEARCH_RES ingestion and higher-level search consumers.
///
/// Large passive harvest bursts can deliver many consecutive SEARCH_RES pages
/// from one peer. Keeping this buffer comfortably above one page train avoids
/// turning inbound harvest volume into backpressure on the traversal loop.
const SEARCH_RESULT_STREAM_BUFFER: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KadSearchCompletion {
    pub terminal_reason: KadSearchTerminalReason,
    pub routing_seed_count: usize,
    pub responding_contact_count: usize,
    pub phase2_attempted_count: usize,
    pub phase2_sent_count: usize,
    pub raw_result_count: usize,
    pub accepted_result_count: usize,
    pub elapsed: Duration,
}

impl KadSearchCompletion {
    pub const fn search_packet_dispatched(self) -> bool {
        self.phase2_sent_count != 0
    }
}

pub struct KadSearchStream<T> {
    results: ReceiverStream<T>,
    completion: oneshot::Receiver<KadSearchCompletion>,
}

impl<T> KadSearchStream<T> {
    fn new(results: mpsc::Receiver<T>, completion: oneshot::Receiver<KadSearchCompletion>) -> Self {
        Self {
            results: ReceiverStream::new(results),
            completion,
        }
    }

    pub async fn completion(self) -> Option<KadSearchCompletion> {
        self.completion.await.ok()
    }
}

impl<T> Stream for KadSearchStream<T> {
    type Item = T;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().results).poll_next(cx)
    }
}

fn completion_from_traversal(
    traversal: crate::traversal::TraversalResult,
    raw_result_count: usize,
    accepted_result_count: usize,
) -> KadSearchCompletion {
    KadSearchCompletion {
        terminal_reason: traversal.terminal_reason,
        routing_seed_count: traversal.routing_seed_count,
        responding_contact_count: traversal.responding_contact_count,
        phase2_attempted_count: traversal.phase2_dispatch.attempted,
        phase2_sent_count: traversal.phase2_dispatch.sent,
        raw_result_count,
        accepted_result_count,
        elapsed: traversal.elapsed,
    }
}

/// Full notes-search identity so the stream builder stays request-shaped while
/// the public helper surface avoids long argument lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotesSearchRequest {
    pub file_hash: Ed2kHash,
    pub file_size: u64,
    pub requester_id: NodeId,
}

fn map_source_search_result(
    requested_file_hash: Ed2kHash,
    source_id: Ed2kHash,
    tags: Vec<emulebb_kad_proto::Tag>,
) -> Option<SourceResult> {
    // Kad SEARCH_RES entries for source searches use the entry-id slot for the
    // publishing/source identity, not the requested file hash. Preserve the
    // source endpoint from the result tags, but always pin the logical file
    // hash to the original request target.
    SourceResult::from_tags(requested_file_hash, source_id, tags)
}

/// Run a keyword search using a prebuilt Kad keyword request shape.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
pub(crate) fn search_keywords_by_request(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: SearchKeyReq,
    search_timeout: Duration,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
    res_contact_sink: Option<KadResContactSink>,
    permit: SearchPermit,
) -> KadSearchStream<SearchResult> {
    let (tx, rx) = mpsc::channel::<SearchResult>(SEARCH_RESULT_STREAM_BUFFER);
    let (completion_tx, completion_rx) = oneshot::channel();
    let request_target = request.target;
    let restrictive_payload =
        ((request.start_position & 0x8000) != 0).then(|| request.restrictive_payload.clone());
    tokio::spawn(async move {
        // The public start boundary acquired this before returning the stream.
        // Hold it for the lifetime of the traversal task.
        let _permit = permit;
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<SearchResultObservation>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target: request.target,
            search_kind: TraversalKind::Keyword { request },
            timeout: search_timeout,
            response_grace: SEARCH_RESULT_GRACE,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            more_results: MoreResultsMode::Maximize,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
            res_contact_sink,
        };

        let traversal = tokio::spawn(async move { run_traversal(&rpc, initial, config).await });

        let mut seen_hashes = HashSet::new();
        let mut raw_entry_count = 0usize;
        let mut accepted_count = 0usize;
        let mut duplicate_count = 0usize;
        let mut missing_name_count = 0usize;
        let mut missing_size_count = 0usize;
        let mut restrictive_mismatch_count = 0usize;
        let mut sample_rejection = None::<String>;
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some(observation) = next else {
                break;
            };
            raw_entry_count += 1;
            let std::net::IpAddr::V4(responder_ip) = observation.responder_addr.ip() else {
                continue;
            };
            let mut result = SearchResult::from_observation(
                observation.entry_id,
                observation.tags,
                responder_ip,
                observation.responder_version,
            );
            if result.names.is_empty() {
                missing_name_count += 1;
                if sample_rejection.is_none() {
                    sample_rejection = Some(format!(
                        "missing_name hash={} size={:?} tag_count={}",
                        result.hash,
                        result.size,
                        result.tags.len()
                    ));
                }
                continue;
            }
            if result.size.is_none() {
                missing_size_count += 1;
                if sample_rejection.is_none() {
                    sample_rejection = Some(format!(
                        "missing_size hash={} first_name={:?} tag_count={}",
                        result.hash,
                        result.names.first(),
                        result.tags.len()
                    ));
                }
                continue;
            }
            if !retain_matching_keyword_names(&mut result, restrictive_payload.as_deref()) {
                restrictive_mismatch_count += 1;
                continue;
            }
            if !seen_hashes.contains(&result.hash) && seen_hashes.len() >= result_cap {
                continue;
            }
            if !seen_hashes.insert(result.hash) {
                duplicate_count += 1;
            } else {
                accepted_count += 1;
            }
            if tx.send(result).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        if let Ok(traversal) = traversal.await {
            let _ = completion_tx.send(completion_from_traversal(
                traversal,
                raw_entry_count,
                accepted_count,
            ));
        }
        debug!(
            "kad keyword search stream summary target={} raw_entries={} accepted={} duplicates={} missing_name={} missing_size={} restrictive_mismatch={} result_cap={} sample_rejection={}",
            request_target,
            raw_entry_count,
            accepted_count,
            duplicate_count,
            missing_name_count,
            missing_size_count,
            restrictive_mismatch_count,
            result_cap,
            sample_rejection.unwrap_or_else(|| "-".to_string())
        );
    });
    KadSearchStream::new(rx, completion_rx)
}

/// Run a source search using a prebuilt Kad source request shape.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
pub(crate) fn search_sources_by_request(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: SearchSourceReq,
    search_timeout: Duration,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
    res_contact_sink: Option<KadResContactSink>,
    permit: SearchPermit,
) -> KadSearchStream<SourceResult> {
    let (tx, rx) = mpsc::channel::<SourceResult>(SEARCH_RESULT_STREAM_BUFFER);
    let (completion_tx, completion_rx) = oneshot::channel();
    let target = request.target;
    let requested_file_hash = Ed2kHash::from_bytes(target.to_be_bytes());

    tokio::spawn(async move {
        let _permit = permit;
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<SearchResultObservation>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Source { request },
            timeout: search_timeout,
            response_grace: SEARCH_RESULT_GRACE,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            more_results: MoreResultsMode::Maximize,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
            res_contact_sink,
        };

        let traversal = tokio::spawn(async move { run_traversal(&rpc, initial, config).await });

        let mut seen_sources = HashSet::<(Ipv4Addr, u16, u16)>::new();
        let mut raw_result_count = 0usize;
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some(observation) = next else {
                break;
            };
            raw_result_count += 1;
            if seen_sources.len() >= result_cap {
                break;
            }

            let Some(source) = map_source_search_result(
                requested_file_hash,
                observation.entry_id,
                observation.tags,
            ) else {
                continue;
            };
            let source_key = (source.ip, source.tcp_port, source.udp_port);
            if !seen_sources.insert(source_key) {
                continue;
            }
            if tx.send(source).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        if let Ok(traversal) = traversal.await {
            let _ = completion_tx.send(completion_from_traversal(
                traversal,
                raw_result_count,
                seen_sources.len(),
            ));
        }
    });
    KadSearchStream::new(rx, completion_rx)
}

/// Run a notes search.
#[expect(
    clippy::too_many_arguments,
    reason = "flat protocol or runtime boundary"
)]
pub(crate) fn search_notes(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: NotesSearchRequest,
    search_timeout: Duration,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
    res_contact_sink: Option<KadResContactSink>,
    permit: SearchPermit,
) -> KadSearchStream<NoteResult> {
    let (tx, rx) = mpsc::channel::<NoteResult>(SEARCH_RESULT_STREAM_BUFFER);
    let (completion_tx, completion_rx) = oneshot::channel();
    let target = NodeId::from_be_bytes(request.file_hash.0);

    tokio::spawn(async move {
        let _permit = permit;
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<SearchResultObservation>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Notes {
                size: request.file_size,
                requester_id: request.requester_id,
            },
            timeout: search_timeout,
            response_grace: SEARCH_RESULT_GRACE,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            more_results: MoreResultsMode::Maximize,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
            res_contact_sink,
        };

        let traversal = tokio::spawn(async move { run_traversal(&rpc, initial, config).await });

        let mut seen_sources = HashSet::new();
        let mut raw_result_count = 0usize;
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some(observation) = next else {
                break;
            };
            raw_result_count += 1;
            if seen_sources.len() >= result_cap {
                break;
            }

            let Some(note) =
                NoteResult::from_tags(request.file_hash, observation.entry_id, observation.tags)
            else {
                continue;
            };
            if !seen_sources.insert(note.source_id) {
                continue;
            }
            if tx.send(note).await.is_err() {
                break;
            }
        }

        drop(raw_rx);
        if let Ok(traversal) = traversal.await {
            let _ = completion_tx.send(completion_from_traversal(
                traversal,
                raw_result_count,
                seen_sources.len(),
            ));
        }
    });
    KadSearchStream::new(rx, completion_rx)
}

fn retain_matching_keyword_names(
    result: &mut SearchResult,
    restrictive_payload: Option<&[u8]>,
) -> bool {
    // Unrestricted harvest/replay requests deliberately retain every usable
    // result. Interactive restrictive requests must filter before the unique
    // hash cap, otherwise unrelated or poisoned entries can consume the whole
    // result budget before a matching publication arrives.
    if let Some(payload) = restrictive_payload {
        result
            .names
            .retain(|name| matches_restrictive_keyword_payload(name, &result.tags, payload));
    }
    !result.names.is_empty() && result.size.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::{Tag, TagValue, tag_name};
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn search_stream_preserves_completion_after_results_close() {
        let (result_tx, result_rx) = mpsc::channel::<SearchResult>(1);
        let (completion_tx, completion_rx) = oneshot::channel();
        let completion = KadSearchCompletion {
            terminal_reason: KadSearchTerminalReason::Completed,
            routing_seed_count: 4,
            responding_contact_count: 2,
            phase2_attempted_count: 2,
            phase2_sent_count: 1,
            raw_result_count: 3,
            accepted_result_count: 1,
            elapsed: Duration::from_millis(25),
        };
        let mut stream = KadSearchStream::new(result_rx, completion_rx);

        drop(result_tx);
        completion_tx.send(completion).expect("completion receipt");

        assert!(stream.next().await.is_none());
        assert_eq!(stream.completion().await, Some(completion));
    }

    #[test]
    fn keyword_result_requires_filename_and_size() {
        let mut missing_name =
            SearchResult::from_tags(Ed2kHash::from_bytes([1; 16]), vec![Tag::filesize(42)]);
        assert!(!retain_matching_keyword_names(&mut missing_name, None));

        let mut missing_size = SearchResult::from_tags(
            Ed2kHash::from_bytes([2; 16]),
            vec![Tag::filename("torino-trip.avi")],
        );
        assert!(!retain_matching_keyword_names(&mut missing_size, None));
    }

    #[test]
    fn unrestricted_keyword_result_accepts_any_filename_with_core_fields() {
        let mut result = SearchResult::from_tags(
            Ed2kHash::from_bytes([3; 16]),
            vec![Tag::filename("Torino Holiday.avi"), Tag::filesize(123)],
        );
        assert!(retain_matching_keyword_names(&mut result, None));
    }

    #[test]
    fn restrictive_keyword_result_keeps_only_matching_names() {
        let mut result = SearchResult::from_tags(
            Ed2kHash::from_bytes([4; 16]),
            vec![
                Tag::filename("Live In Torino Train Station.mkv"),
                Tag::filename("Unrelated Alias.mkv"),
                Tag::filesize(123),
            ],
        );
        let payload = restrictive_string_payload("torino train");

        assert!(retain_matching_keyword_names(&mut result, Some(&payload)));
        assert_eq!(result.names, vec!["Live In Torino Train Station.mkv"]);
    }

    #[test]
    fn restrictive_keyword_result_rejects_nonmatching_hash_before_budgeting() {
        let mut result = SearchResult::from_tags(
            Ed2kHash::from_bytes([7; 16]),
            vec![Tag::filename("Unrelated Alias.mkv"), Tag::filesize(123)],
        );
        let payload = restrictive_string_payload("torino train");

        assert!(!retain_matching_keyword_names(&mut result, Some(&payload)));
        assert!(result.names.is_empty());
    }

    #[test]
    fn notes_parsing_keeps_description_and_rating_only() {
        let note = NoteResult::from_tags(
            Ed2kHash::from_bytes([5; 16]),
            Ed2kHash::from_bytes([6; 16]),
            vec![
                Tag::new_short(tag_name::DESCRIPTION, TagValue::String("good".into())),
                Tag::new_short(tag_name::FILERATING, TagValue::U8(4)),
            ],
        )
        .expect("note");
        assert_eq!(note.comment.as_deref(), Some("good"));
        assert_eq!(note.rating, Some(4));
    }

    #[test]
    fn source_search_results_keep_requested_file_hash_instead_of_entry_id() {
        let requested_file_hash = Ed2kHash::from_bytes([0x44; 16]);
        let source_identity = Ed2kHash::from_bytes([0x80; 16]);
        let tags = vec![
            Tag::new_short(tag_name::SOURCEIP, TagValue::U32(0x7F000001)),
            Tag::new_short(tag_name::SOURCEPORT, TagValue::U16(42062)),
            Tag::new_short(tag_name::SOURCEUPORT, TagValue::U16(42072)),
        ];

        let source = map_source_search_result(requested_file_hash, source_identity, tags)
            .expect("source search result");
        assert_eq!(source.file_hash, requested_file_hash);
        assert_eq!(source.source_id, source_identity);
        assert_ne!(source.file_hash, source_identity);
        assert_eq!(source.ip, std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(source.tcp_port, 42062);
        assert_eq!(source.udp_port, 42072);
    }

    fn restrictive_string_payload(value: &str) -> Vec<u8> {
        let mut payload = vec![0x01];
        payload.extend_from_slice(&(value.len() as u16).to_le_bytes());
        payload.extend_from_slice(value.as_bytes());
        payload
    }
}
