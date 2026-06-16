//! Kad passive-replay (snoop-queue) runtime drivers.
//!
//! The background workers that replay snooped keyword/source/notes requests
//! against the live DHT to harvest the local index and remember learned
//! sources/notes: the two-flavour `run_kad_passive_replay_loop` (general +
//! source workers), the family-prioritized request selection, the per-family
//! replay runners, and the result-remembering/indexing helpers. Moved verbatim
//! out of `lib.rs` during the maintainability restructuring; they carry no
//! behavior beyond what they had inline. Re-exported `pub(crate)` from the
//! crate root so the network-startup spawn site and the test module reach them
//! by their bare names.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use emulebb_ed2k::ed2k_transfer::{Ed2kSourceHint, Ed2kTransferRuntime};
use emulebb_index::{
    FileIndex, IndexedFile, ScheduledSnoopRequest, SnoopQueue, SnoopQueueFamilyCounts,
};
use emulebb_kad_dht::{
    DhtNode, NoteResult as KadNoteResult, RpcWorkClass, SearchResult as KadSearchResult,
    SourceResult,
};
use emulebb_kad_proto::{Ed2kHash, SearchKeyReq, SearchNotesReq, SearchSourceReq};
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::kad_source_result_to_ed2k_found_source;

const PASSIVE_GENERAL_CRAWL_SECS: u64 = 45;
const PASSIVE_SOURCE_CRAWL_SECS: u64 = 15;
const PASSIVE_KEYWORD_RESULT_TARGET: usize = 10;
const PASSIVE_NOTES_RESULT_TARGET: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveReplayWorker {
    General,
    Source,
}

#[derive(Debug)]
enum PassiveReplaySelection {
    Keyword(ScheduledSnoopRequest<SearchKeyReq>),
    Source(ScheduledSnoopRequest<SearchSourceReq>),
    Notes(ScheduledSnoopRequest<SearchNotesReq>),
}

pub(crate) async fn run_kad_passive_replay_loop(
    dht: DhtNode,
    snoop_queue: Arc<Mutex<SnoopQueue>>,
    index: Arc<Mutex<FileIndex>>,
    transfer_runtime: Arc<Ed2kTransferRuntime>,
    shutdown: Arc<AtomicBool>,
    worker: PassiveReplayWorker,
) {
    let interval = match worker {
        PassiveReplayWorker::General => Duration::from_secs(PASSIVE_GENERAL_CRAWL_SECS),
        PassiveReplayWorker::Source => Duration::from_secs(PASSIVE_SOURCE_CRAWL_SECS),
    };
    while !shutdown.load(Ordering::SeqCst) {
        tokio::time::sleep(interval).await;
        if shutdown.load(Ordering::SeqCst) || !dht.is_bootstrapped() {
            continue;
        }
        let selected = match worker {
            PassiveReplayWorker::General => next_passive_replay_request(&snoop_queue).await,
            PassiveReplayWorker::Source => next_passive_replay_source_request(&snoop_queue)
                .await
                .map(PassiveReplaySelection::Source),
        };
        let Some(selected) = selected else {
            continue;
        };
        run_selected_passive_replay(&dht, &snoop_queue, &index, &transfer_runtime, selected).await;
    }
}

async fn next_passive_replay_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<PassiveReplaySelection> {
    let mut queue = snoop_queue.lock().await;
    let now = Utc::now();
    for family in preferred_passive_replay_families(queue.family_counts()) {
        let selected = match family {
            PassiveReplayFamily::Keyword => queue
                .select_next_keyword_request(now)
                .map(PassiveReplaySelection::Keyword),
            PassiveReplayFamily::Source => queue
                .select_next_source_request(now)
                .map(PassiveReplaySelection::Source),
            PassiveReplayFamily::Notes => queue
                .select_next_notes_request(now)
                .map(PassiveReplaySelection::Notes),
        };
        if selected.is_some() {
            return selected;
        }
    }
    None
}

async fn next_passive_replay_source_request(
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
) -> Option<ScheduledSnoopRequest<SearchSourceReq>> {
    snoop_queue
        .lock()
        .await
        .select_next_source_request(Utc::now())
}

async fn run_selected_passive_replay(
    dht: &DhtNode,
    snoop_queue: &Arc<Mutex<SnoopQueue>>,
    index: &Arc<Mutex<FileIndex>>,
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    selected: PassiveReplaySelection,
) {
    let (logical_key, result_count) = match selected {
        PassiveReplaySelection::Keyword(selected) => {
            let logical_key = selected.logical_key;
            let result_count = run_passive_keyword_replay(dht, index, selected.request).await;
            (logical_key, result_count)
        }
        PassiveReplaySelection::Source(selected) => {
            let source_stop_after_results = {
                snoop_queue
                    .lock()
                    .await
                    .config()
                    .source_stop_after_results
                    .max(1)
            };
            let logical_key = selected.logical_key;
            let source_results =
                run_passive_source_replay(dht, selected.request, source_stop_after_results).await;
            remember_passive_source_results(transfer_runtime, &source_results).await;
            (logical_key, source_results.len())
        }
        PassiveReplaySelection::Notes(selected) => {
            let logical_key = selected.logical_key;
            let note_results = run_passive_notes_replay(dht, selected.request).await;
            remember_passive_note_results(transfer_runtime, &note_results).await;
            (logical_key, note_results.len())
        }
    };
    snoop_queue
        .lock()
        .await
        .record_replay_outcome(&logical_key, Utc::now(), result_count);
}

async fn run_passive_keyword_replay(
    dht: &DhtNode,
    index: &Arc<Mutex<FileIndex>>,
    request: SearchKeyReq,
) -> usize {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_keyword_request_with_cancel_and_class(
        request.clone(),
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_hashes = HashSet::new();
    let mut result_count = 0usize;
    while let Some(result) = stream.next().await {
        if !seen_hashes.insert(result.hash) {
            continue;
        }
        result_count += 1;
        index_passive_keyword_result(index, &result).await;
        if result_count >= PASSIVE_KEYWORD_RESULT_TARGET {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        start_position = request.start_position,
        result_count,
        "completed Kad passive keyword replay"
    );
    result_count
}

async fn run_passive_source_replay(
    dht: &DhtNode,
    request: SearchSourceReq,
    source_stop_after_results: usize,
) -> Vec<SourceResult> {
    let cancel = CancellationToken::new();
    let mut stream = dht.search_source_request_with_cancel_and_class(
        request.clone(),
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_sources = HashSet::new();
    let mut results = Vec::new();
    while let Some(result) = stream.next().await {
        let source_key = (result.ip, result.tcp_port, result.udp_port);
        if !seen_sources.insert(source_key) {
            continue;
        }
        results.push(result);
        if results.len() >= source_stop_after_results {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        start_position = request.start_position,
        size = request.size,
        result_count = results.len(),
        "completed Kad passive source replay"
    );
    results
}

pub(crate) async fn remember_passive_source_results(
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    results: &[SourceResult],
) {
    for result in results {
        let source = kad_source_result_to_ed2k_found_source(result.clone());
        if !source.is_direct_dialable() {
            continue;
        }
        let hint = Ed2kSourceHint {
            ip: source.ip.to_string(),
            tcp_port: source.tcp_port,
            user_hash: source.user_hash.map(hex::encode),
        };
        if let Err(error) = transfer_runtime
            .remember_source(&result.file_hash.to_string(), hint)
            .await
        {
            tracing::debug!(
                file_hash = %result.file_hash,
                source = %SocketAddr::new(IpAddr::V4(result.ip), result.tcp_port),
                "skipping passive Kad source memory: {error:#}"
            );
        }
    }
}

async fn run_passive_notes_replay(dht: &DhtNode, request: SearchNotesReq) -> Vec<KadNoteResult> {
    let cancel = CancellationToken::new();
    let file_hash = Ed2kHash::from_bytes(request.target.to_be_bytes());
    let mut stream = dht.search_notes_with_cancel_and_class(
        file_hash,
        request.size,
        cancel.clone(),
        RpcWorkClass::Harvest,
    );
    let mut seen_notes = HashSet::new();
    let mut results = Vec::new();
    while let Some(result) = stream.next().await {
        if !seen_notes.insert(note_result_key(&result)) {
            continue;
        }
        results.push(result);
        if results.len() >= PASSIVE_NOTES_RESULT_TARGET {
            cancel.cancel();
            break;
        }
    }
    tracing::debug!(
        target = %request.target,
        size = request.size,
        result_count = results.len(),
        "completed Kad passive notes replay"
    );
    results
}

pub(crate) async fn remember_passive_note_results(
    transfer_runtime: &Arc<Ed2kTransferRuntime>,
    results: &[KadNoteResult],
) {
    for result in results {
        let file_hash = result.file_hash.to_string();
        let Ok(manifest) = transfer_runtime.manifest(&file_hash).await else {
            tracing::debug!(
                file_hash,
                "skipping passive Kad note memory for unknown transfer"
            );
            continue;
        };
        if !manifest.comment.is_empty() || manifest.rating != 0 {
            continue;
        }
        let comment = result.comment.clone().unwrap_or_default();
        let rating = result.rating.unwrap_or(0).min(5);
        if comment.is_empty() && rating == 0 {
            continue;
        }
        if let Err(error) = transfer_runtime
            .update_shared_file_metadata(&file_hash, None, Some((&comment, rating)))
            .await
        {
            tracing::debug!(
                file_hash,
                source_id = %result.source_id,
                "skipping passive Kad note memory: {error:#}"
            );
        }
    }
}

pub(crate) async fn index_passive_keyword_result(
    index: &Arc<Mutex<FileIndex>>,
    result: &KadSearchResult,
) {
    let Some(size_bytes) = result.size.filter(|size| *size > 0) else {
        return;
    };
    if result.names.is_empty() {
        return;
    }
    let availability_score = result.source_count.unwrap_or(1).max(1) as i64;
    let mut index = index.lock().await;
    for name in &result.names {
        if name.trim().is_empty() {
            continue;
        }
        if let Err(error) = index.upsert_file(&IndexedFile {
            ed2k_hash: result.hash.to_string(),
            name: name.clone(),
            size_bytes,
            content_type: "unknown".to_string(),
            availability_score,
        }) {
            tracing::debug!(
                file_hash = %result.hash,
                name,
                "failed to index passive Kad keyword result: {error:#}"
            );
        }
    }
}

fn note_result_key(result: &KadNoteResult) -> (Ed2kHash, Ed2kHash, Option<u8>, Option<String>) {
    (
        result.file_hash,
        result.source_id,
        result.rating,
        result.comment.clone(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassiveReplayFamily {
    Keyword,
    Source,
    Notes,
}

pub(crate) fn preferred_passive_replay_families(
    counts: SnoopQueueFamilyCounts,
) -> [PassiveReplayFamily; 3] {
    let mut families = [
        (PassiveReplayFamily::Keyword, counts.keyword, 0u8),
        (PassiveReplayFamily::Source, counts.source, 1u8),
        (PassiveReplayFamily::Notes, counts.notes, 2u8),
    ];
    families.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.2.cmp(&right.2)));
    [families[0].0, families[1].0, families[2].0]
}
