use crate::traversal::{KadIpFilter, TraversalConfig, TraversalContact, TraversalKind, run_traversal};
use crate::types::{NoteResult, SearchResult, SourceResult};
use emulebb_kad_net::{RpcManager, RpcWorkClass};
use emulebb_kad_proto::constants::SEARCH_TIMEOUT_SECS;
use emulebb_kad_proto::{Ed2kHash, NodeId, SearchKeyReq, SearchSourceReq};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::info;

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const SEARCH_TIMEOUT: Duration = Duration::from_secs(SEARCH_TIMEOUT_SECS);
/// Buffer used between traversal SEARCH_RES ingestion and higher-level search consumers.
///
/// Large passive harvest bursts can deliver many consecutive SEARCH_RES pages
/// from one peer. Keeping this buffer comfortably above one page train avoids
/// turning inbound harvest volume into backpressure on the traversal loop.
const SEARCH_RESULT_STREAM_BUFFER: usize = 2048;

/// Full notes-search identity so the stream builder stays request-shaped while
/// the public helper surface avoids long argument lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotesSearchRequest {
    pub file_hash: Ed2kHash,
    pub file_size: u64,
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

/// Run a keyword search. Returns a Stream of results.
#[allow(clippy::too_many_arguments)]
pub fn search_keywords(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    target: NodeId,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
    search_keywords_by_request(
        rpc,
        initial,
        SearchKeyReq {
            target,
            start_position: 0,
            restrictive_payload: Vec::new(),
        },
        result_cap,
        phase2_fanout,
        cancel,
        work_class,
        ip_filter,
    )
}

/// Run a keyword search using a prebuilt Kad keyword request shape.
#[allow(clippy::too_many_arguments)]
pub fn search_keywords_by_request(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: SearchKeyReq,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
) -> impl tokio_stream::Stream<Item = SearchResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<SearchResult>(SEARCH_RESULT_STREAM_BUFFER);
    let request_target = request.target;
    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<emulebb_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target: request.target,
            search_kind: TraversalKind::Keyword { request },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_hashes = HashSet::new();
        let mut raw_entry_count = 0usize;
        let mut accepted_count = 0usize;
        let mut duplicate_count = 0usize;
        let mut missing_name_count = 0usize;
        let mut missing_size_count = 0usize;
        let mut sample_rejection = None::<String>;
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((hash, tags)) = next else {
                break;
            };
            raw_entry_count += 1;
            if seen_hashes.len() >= result_cap {
                break;
            }

            let result = SearchResult::from_tags(hash, tags);
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
            if !is_acceptable_keyword_result(&result) {
                continue;
            }
            if !seen_hashes.insert(result.hash) {
                duplicate_count += 1;
                continue;
            }
            if tx.send(result).await.is_err() {
                break;
            }
            accepted_count += 1;
        }

        drop(raw_rx);
        let _ = traversal.await;
        info!(
            "kad keyword search stream summary target={} raw_entries={} accepted={} duplicates={} missing_name={} missing_size={} result_cap={} sample_rejection={}",
            request_target,
            raw_entry_count,
            accepted_count,
            duplicate_count,
            missing_name_count,
            missing_size_count,
            result_cap,
            sample_rejection.unwrap_or_else(|| "-".to_string())
        );
    });
    ReceiverStream::new(rx)
}

/// Run a source search using a prebuilt Kad source request shape.
#[allow(clippy::too_many_arguments)]
pub fn search_sources_by_request(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: SearchSourceReq,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
) -> impl tokio_stream::Stream<Item = SourceResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<SourceResult>(SEARCH_RESULT_STREAM_BUFFER);
    let target = request.target;
    let requested_file_hash = Ed2kHash::from_bytes(target.to_be_bytes());

    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<emulebb_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Source { request },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_sources = HashSet::<(Ipv4Addr, u16, u16)>::new();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((source_id, tags)) = next else {
                break;
            };
            if seen_sources.len() >= result_cap {
                break;
            }

            let Some(source) = map_source_search_result(requested_file_hash, source_id, tags)
            else {
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
        let _ = traversal.await;
    });
    ReceiverStream::new(rx)
}

/// Run a notes search.
#[allow(clippy::too_many_arguments)]
pub fn search_notes(
    rpc: RpcManager,
    initial: Vec<TraversalContact>,
    request: NotesSearchRequest,
    result_cap: usize,
    phase2_fanout: usize,
    cancel: CancellationToken,
    work_class: RpcWorkClass,
    ip_filter: Option<KadIpFilter>,
) -> impl tokio_stream::Stream<Item = NoteResult> + Send + 'static {
    let (tx, rx) = mpsc::channel::<NoteResult>(SEARCH_RESULT_STREAM_BUFFER);
    let target = NodeId::from_be_bytes(request.file_hash.0);

    tokio::spawn(async move {
        let (raw_tx, mut raw_rx) =
            mpsc::channel::<(Ed2kHash, Vec<emulebb_kad_proto::Tag>)>(SEARCH_RESULT_STREAM_BUFFER);
        let config = TraversalConfig {
            target,
            search_kind: TraversalKind::Notes {
                size: request.file_size,
            },
            timeout: SEARCH_TIMEOUT,
            query_timeout: QUERY_TIMEOUT,
            phase2_fanout,
            cancel: cancel.clone(),
            result_tx: Some(raw_tx),
            work_class,
            ip_filter,
        };

        let traversal = tokio::spawn(async move {
            let _ = run_traversal(&rpc, initial, config).await;
        });

        let mut seen_sources = HashSet::new();
        loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => break,
                next = raw_rx.recv() => next,
            };
            let Some((source_id, tags)) = next else {
                break;
            };
            if seen_sources.len() >= result_cap {
                break;
            }

            let Some(note) = NoteResult::from_tags(request.file_hash, source_id, tags) else {
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
        let _ = traversal.await;
    });
    ReceiverStream::new(rx)
}

fn is_acceptable_keyword_result(result: &SearchResult) -> bool {
    // Harvest-first repo policy: keep wire-compatible requests, but accept any
    // keyword result which has the core fields needed for indexing. We
    // intentionally do not apply eMule's local query-word filtering here,
    // because this daemon is an indexer rather than a UI search client.
    !result.names.is_empty() && result.size.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::{Tag, TagValue, tag_name};

    #[test]
    fn keyword_result_requires_filename_and_size() {
        let missing_name =
            SearchResult::from_tags(Ed2kHash::from_bytes([1; 16]), vec![Tag::filesize(42)]);
        assert!(!is_acceptable_keyword_result(&missing_name));

        let missing_size = SearchResult::from_tags(
            Ed2kHash::from_bytes([2; 16]),
            vec![Tag::filename("torino-trip.avi")],
        );
        assert!(!is_acceptable_keyword_result(&missing_size));
    }

    #[test]
    fn keyword_result_accepts_nonmatching_filename_when_core_fields_exist() {
        let result = SearchResult::from_tags(
            Ed2kHash::from_bytes([3; 16]),
            vec![Tag::filename("Torino Holiday.avi"), Tag::filesize(123)],
        );
        assert!(is_acceptable_keyword_result(&result));
    }

    #[test]
    fn keyword_result_accepts_matching_multiword_filename() {
        let result = SearchResult::from_tags(
            Ed2kHash::from_bytes([4; 16]),
            vec![
                Tag::filename("Live In Torino Train Station.mkv"),
                Tag::filesize(123),
            ],
        );
        assert!(is_acceptable_keyword_result(&result));
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
}
