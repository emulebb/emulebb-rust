//! Capture raw claims before presentation defaults, filters, or aggregation.

use std::net::SocketAddr;

use chrono::Utc;
use emulebb_ed2k::ed2k_server::Ed2kSearchFile;
use emulebb_kad_dht::SearchResult as KadSearchResult;
use emulebb_metadata::{
    MetadataContentClaim, MetadataContentMetadata, MetadataContentObservationEvent,
    MetadataObservationOrigin,
};

use crate::{SearchCreate, SearchResult, search_queue_runtime::SearchLiveUpdate};

/// Drain already decoded observations even when the network operation settles.
/// A bounded channel carries backpressure to the page decoder.
pub(crate) async fn forward_ed2k<T>(
    search_id: &str,
    request: &SearchCreate,
    origin: MetadataObservationOrigin,
    sink: Option<&tokio::sync::mpsc::Sender<SearchLiveUpdate>>,
    mut receive: tokio::sync::mpsc::Receiver<
        emulebb_ed2k::ed2k_server::Ed2kServerSearchObservation,
    >,
    operation: impl std::future::Future<Output = T>,
) -> T {
    tokio::pin!(operation);
    loop {
        tokio::select! {
            output = &mut operation => {
                while let Ok(observation) = receive.try_recv() {
                    forward_one(search_id, request, origin, sink, observation).await;
                }
                return output;
            }
            Some(observation) = receive.recv() => {
                forward_one(search_id, request, origin, sink, observation).await;
            }
        }
    }
}

async fn forward_one(
    search_id: &str,
    request: &SearchCreate,
    origin: MetadataObservationOrigin,
    sink: Option<&tokio::sync::mpsc::Sender<SearchLiveUpdate>>,
    observation: emulebb_ed2k::ed2k_server::Ed2kServerSearchObservation,
) {
    if let Some(sink) = sink {
        let result = crate::search_query::search_result_from_ed2k(
            search_id,
            request,
            origin.as_str(),
            Some(observation.server_endpoint),
            observation.file.clone(),
        );
        let _ = sink
            .send(ed2k(
                result,
                origin,
                Some(observation.server_endpoint),
                &observation.file,
            ))
            .await;
    }
}

pub(crate) fn ed2k(
    result: SearchResult,
    origin: MetadataObservationOrigin,
    reporter: Option<SocketAddr>,
    raw: &Ed2kSearchFile,
) -> SearchLiveUpdate {
    let event = MetadataContentObservationEvent {
        claim: MetadataContentClaim {
            hash: raw.file_hash.0,
            size_bytes: raw.file_size,
        },
        origin,
        reporter_endpoint: reporter.and_then(|endpoint| match endpoint {
            SocketAddr::V4(endpoint) => Some(endpoint),
            SocketAddr::V6(_) => None,
        }),
        metadata: MetadataContentMetadata {
            name: raw.file_name.clone(),
            source_count: raw.source_count,
            complete_source_count: raw.complete_source_count,
            source_client_id: (raw.client_id != 0).then_some(raw.client_id),
            source_client_port: (raw.client_port != 0).then_some(raw.client_port),
            file_type: raw.file_type.clone(),
            media_artist: raw.media_artist.clone(),
            media_album: raw.media_album.clone(),
            media_title: raw.media_title.clone(),
            media_length_seconds: raw.media_length_seconds,
            media_bitrate_kbps: raw.media_bitrate_kbps,
            media_codec: raw.media_codec.clone(),
            rating: raw.rating,
            aich_root: raw.aich_hash.as_deref().and_then(|root| {
                data_encoding::BASE32
                    .decode(root.as_bytes())
                    .ok()?
                    .try_into()
                    .ok()
            }),
            complete: None,
            directory: raw.directory.clone(),
        },
        observed_at_s: Utc::now().timestamp(),
    };
    SearchLiveUpdate::Result {
        result: Box::new(result),
        observations: vec![event],
    }
}

pub(crate) fn kad(result: SearchResult, raw: &KadSearchResult) -> SearchLiveUpdate {
    let base = MetadataContentObservationEvent {
        claim: MetadataContentClaim {
            hash: raw.hash.0,
            size_bytes: raw.size,
        },
        origin: MetadataObservationOrigin::Kad,
        reporter_endpoint: raw.reporter_endpoint,
        metadata: MetadataContentMetadata {
            source_count: raw.source_count,
            file_type: raw.file_type.clone(),
            media_artist: raw.media_artist.clone(),
            media_album: raw.media_album.clone(),
            media_title: raw.media_title.clone(),
            media_length_seconds: raw.media_length_seconds,
            media_bitrate_kbps: raw.media_bitrate_kbps,
            media_codec: raw.media_codec.clone(),
            aich_root: raw.aich_candidate.map(|candidate| candidate.root),
            ..Default::default()
        },
        observed_at_s: Utc::now().timestamp(),
    };
    let mut observations = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for name in &raw.names {
        if seen.insert(name) {
            let mut event = base.clone();
            event.metadata.name = Some(name.clone());
            observations.push(event);
        }
    }
    if observations.is_empty() {
        observations.push(base);
    }
    SearchLiveUpdate::Result {
        result: Box::new(result),
        observations,
    }
}

#[cfg(test)]
pub(crate) mod tests;
