use crate::{Search, SearchResult};
#[cfg(test)]
use anyhow::Context;
use anyhow::Result;
#[cfg(test)]
use emulebb_metadata::MetadataStore;
use emulebb_metadata::{
    MetadataSearchData, MetadataSearchResultFields, MetadataSearchSpec, normalized_search_query,
};

#[cfg(test)]
pub(crate) fn persist_search(metadata: &MetadataStore, search: &Search) -> Result<()> {
    metadata
        .transition_search(
            search.id.parse().context("invalid search identity")?,
            &search_to_metadata(search),
            &[],
        )
        .map(|_| ())
}

#[cfg(test)]
pub(crate) fn create_search(metadata: &MetadataStore, search: &Search) -> Result<String> {
    Ok(metadata
        .create_search(&search_to_metadata(search))?
        .to_string())
}

pub(crate) fn search_to_metadata(search: &Search) -> MetadataSearchData {
    MetadataSearchData {
        parent_search_id: search.spec.parent_search_id,
        normalized_query: normalized_search_query(&search.spec.query),
        spec: MetadataSearchSpec {
            query: search.spec.query.clone(),
            method: search.spec.method.clone(),
            file_type: search.spec.r#type.clone(),
            extension: search.spec.extension.clone(),
            min_size_bytes: search.spec.min_size_bytes,
            max_size_bytes: search.spec.max_size_bytes,
            min_availability: search.spec.min_availability,
            min_complete_sources: search.spec.min_complete_sources,
            min_bitrate_kbps: search.spec.min_bitrate_kbps,
            min_length_seconds: search.spec.min_length_seconds,
            codec: search.spec.codec.clone(),
            title: search.spec.title.clone(),
            album: search.spec.album.clone(),
            artist: search.spec.artist.clone(),
        },
        resolved_method: search.resolved_method.clone(),
        status: search.status.clone(),
        status_reason: search.status_reason.clone(),
        created_at_s: search.created_at.timestamp(),
        updated_at_s: search.updated_at.timestamp(),
        completed_at_s: (search.status == "completed").then(|| search.updated_at.timestamp()),
    }
}

pub(crate) fn result_fields(result: &SearchResult) -> Vec<MetadataSearchResultFields> {
    result
        .observations
        .iter()
        .map(|observation| {
            let (useful, sources, complete_sources, _, rating) =
                crate::rest_model::observation_quality(observation, &result.hash);
            let source = observation
                .source_client_id
                .zip(observation.source_client_port);
            MetadataSearchResultFields {
                quality: emulebb_metadata::MetadataSearchNameQuality {
                    useful,
                    sources,
                    complete_sources,
                    rating,
                },
                source_client_id: source.map(|v| v.0),
                source_client_port: source.map(|v| v.1),
                file_type: observation.file_type.clone(),
                media_artist: observation.media.artist.clone(),
                media_album: observation.media.album.clone(),
                media_title: observation.media.title.clone(),
                media_length_seconds: observation.media.length_seconds,
                media_bitrate_kbps: observation.media.bitrate_kbps,
                media_codec: observation.media.codec.clone(),
                rating: observation.rating,
                aich_hash: observation.aich_hash.clone(),
                complete: observation.complete,
                directory: observation.directory.clone(),
            }
        })
        .collect()
}

pub(crate) fn projection_name_votes(
    result: &SearchResult,
) -> Result<Vec<emulebb_metadata::MetadataSearchNameVote>> {
    use emulebb_metadata::{
        MetadataObservationOrigin, MetadataSearchNameQuality, MetadataSearchNameVote,
    };
    result
        .observations
        .iter()
        .map(|observation| {
            let origin = match observation.origin.as_str() {
                "server" => MetadataObservationOrigin::Server,
                "global" => MetadataObservationOrigin::Global,
                "kad" => MetadataObservationOrigin::Kad,
                _ => anyhow::bail!("invalid search presentation origin"),
            };
            let (useful, sources, complete_sources, _, rating) =
                crate::rest_model::observation_quality(observation, &result.hash);
            Ok(MetadataSearchNameVote {
                normalized_name: emulebb_ed2k::normalize_ed2k_file_name(&observation.name),
                reporter_endpoint: observation
                    .reporter_endpoint
                    .as_ref()
                    .map(|v| v.parse())
                    .transpose()?,
                origin,
                quality: MetadataSearchNameQuality {
                    useful,
                    sources,
                    complete_sources,
                    rating,
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SearchProgress, SearchResultMedia, SearchResultObservation, SearchSpec};
    use chrono::Utc;

    #[test]
    fn complete_spec_and_terminal_reason_survive_persistence() {
        let metadata = MetadataStore::in_memory().unwrap();
        let spec = SearchSpec {
            parent_search_id: None,
            query: "exact session".to_string(),
            method: "global".to_string(),
            r#type: "audio".to_string(),
            extension: "flac".to_string(),
            min_size_bytes: Some(u64::MAX - 1),
            max_size_bytes: Some(u64::MAX),
            min_availability: Some(23),
            min_complete_sources: Some(7),
            min_bitrate_kbps: Some(1_411),
            min_length_seconds: Some(240),
            codec: "flac".to_string(),
            title: "Example Title".to_string(),
            album: "Example Album".to_string(),
            artist: "Example Artist".to_string(),
        };
        let now = Utc::now();
        let mut result = SearchResult::from_observation(
            String::new(),
            "audio".to_string(),
            "00112233445566778899aabbccddeeff".to_string(),
            SearchResultObservation {
                origin: "global".to_string(),
                reporter_endpoint: None,
                name: "Example Track.flac".to_string(),
                size_bytes: Some(8_192),
                sources: 12,
                complete_sources: 4,
                source_client_id: None,
                source_client_port: None,
                file_type: "Audio".to_string(),
                media: SearchResultMedia {
                    artist: "Example Artist".to_string(),
                    album: "Example Album".to_string(),
                    title: "Example Title".to_string(),
                    length_seconds: 240,
                    bitrate_kbps: 1_411,
                    codec: "flac".to_string(),
                },
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observed_at: now,
            },
        );
        let mut search = Search {
            id: String::new(),
            spec: spec.clone(),
            resolved_method: Some("global".to_string()),
            status: "running".to_string(),
            status_reason: Some("network-search-failed".to_string()),
            progress: SearchProgress::new("failed", 0, None, ""),
            created_at: now,
            updated_at: now,
        };

        search.id = create_search(&metadata, &search).unwrap();
        result.search_id.clone_from(&search.id);
        let claim_id = metadata
            .ingest_search_observations(
                &[emulebb_metadata::MetadataContentObservationEvent {
                    claim: emulebb_metadata::MetadataContentClaim {
                        hash: hex::decode(&result.hash).unwrap().try_into().unwrap(),
                        size_bytes: Some(8192),
                    },
                    origin: emulebb_metadata::MetadataObservationOrigin::Global,
                    reporter_endpoint: Some("192.0.2.4:4661".parse().unwrap()),
                    metadata: emulebb_metadata::MetadataContentMetadata {
                        name: Some("Example Track.flac".into()),
                        source_count: Some(12),
                        complete_source_count: Some(4),
                        file_type: Some("Audio".into()),
                        media_artist: Some("Example Artist".into()),
                        media_album: Some("Example Album".into()),
                        media_title: Some("Example Title".into()),
                        media_length_seconds: Some(240),
                        media_bitrate_kbps: Some(1411),
                        media_codec: Some("flac".into()),
                        ..Default::default()
                    },
                    observed_at_s: now.timestamp(),
                }],
                &emulebb_metadata::MetadataSearchProjection {
                    session_id: search.id.parse().unwrap(),
                    fields: result_fields(&result),
                    name_votes: projection_name_votes(&result).unwrap(),
                },
            )
            .unwrap()
            .unwrap();
        result.id = claim_id.claim_id.to_string();
        search.status = "error".into();
        persist_search(&metadata, &search).unwrap();
        let reloaded = metadata
            .search_header(search.id.parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.data, search_to_metadata(&search));
        assert_eq!(reloaded.result_count, 1);
        let summary = metadata
            .search_result_header(reloaded.id, claim_id.claim_id)
            .unwrap()
            .unwrap()
            .summary;
        assert_eq!(summary.media_artist, "Example Artist");
        assert_eq!(summary.media_album, "Example Album");
        assert_eq!(summary.media_title, "Example Title");
        assert_eq!(summary.media_length_seconds, 240);
        assert_eq!(summary.media_bitrate_kbps, 1411);
        assert_eq!(summary.media_codec, "flac");
        let observations = metadata
            .search_result_observations_page(reloaded.id, claim_id.claim_id, 0, 10)
            .unwrap()
            .unwrap();
        assert_eq!(
            observations.items[0].observation.event.origin.as_str(),
            "global"
        );
    }
}

/// Publish activity only after the evidence and materialized summary commit.
pub(crate) async fn publish_search_activity(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::CoreState>>,
    search_id: &str,
) {
    let mut state = state.lock().await;
    if let Some(search) = state.searches.get_mut(search_id) {
        search.updated_at = chrono::Utc::now();
    }
}
