use crate::{
    Search, SearchProgress, SearchResult, SearchResultMedia, SearchResultObservation, SearchSpec,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_metadata::{
    MetadataSearch, MetadataSearchData, MetadataSearchResult, MetadataSearchResultFields,
    MetadataSearchSpec, MetadataStore, normalized_search_query,
};
use std::collections::HashMap;

pub(crate) fn load_searches(metadata: &MetadataStore) -> Result<HashMap<String, Search>> {
    metadata
        .load_searches()?
        .into_iter()
        .map(|search| {
            let search = search_from_metadata(search)?;
            Ok((search.id.clone(), search))
        })
        .collect()
}

#[cfg(test)]
pub(crate) fn persist_search(metadata: &MetadataStore, search: &Search) -> Result<()> {
    metadata.update_search(
        search.id.parse().context("invalid search identity")?,
        &search_to_metadata(search),
    )
}

#[cfg(test)]
pub(crate) fn create_search(metadata: &MetadataStore, search: &Search) -> Result<String> {
    Ok(metadata
        .create_search(&search_to_metadata(search))?
        .to_string())
}

pub(crate) fn search_to_metadata(search: &Search) -> MetadataSearchData {
    MetadataSearchData {
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

fn search_from_metadata(search: MetadataSearch) -> Result<Search> {
    let id = search.id.to_string();
    let header = search.data;
    let created_at = timestamp_s(header.created_at_s, "search created_at_s")?;
    let updated_at = timestamp_s(header.updated_at_s, "search updated_at_s")?;
    let (status, status_reason) = match header.status.as_str() {
        "queued" | "running" => (
            "error".to_owned(),
            Some("interrupted-by-restart".to_owned()),
        ),
        _ => (header.status, header.status_reason),
    };
    let s = header.spec;
    let spec = SearchSpec {
        query: s.query,
        method: s.method,
        r#type: s.file_type,
        extension: s.extension,
        min_size_bytes: s.min_size_bytes,
        max_size_bytes: s.max_size_bytes,
        min_availability: s.min_availability,
        min_complete_sources: s.min_complete_sources,
        min_bitrate_kbps: s.min_bitrate_kbps,
        min_length_seconds: s.min_length_seconds,
        codec: s.codec,
        title: s.title,
        album: s.album,
        artist: s.artist,
    };
    let results = search
        .results
        .into_iter()
        .map(|result| search_result_from_metadata(&id, &spec.r#type, result))
        .collect::<Result<Vec<_>>>()?;
    let phase = match status.as_str() {
        "completed" => "completed",
        "error" => "failed",
        "queued" => "queued",
        _ => "interrupted",
    };
    Ok(Search {
        id,
        spec,
        resolved_method: header.resolved_method,
        status_reason,
        progress: SearchProgress::new(phase, 0, None, ""),
        status,
        created_at,
        updated_at,
        results,
    })
}

fn search_result_from_metadata(
    search_id: &str,
    file_type_filter: &str,
    result: MetadataSearchResult,
) -> Result<SearchResult> {
    let observations = result
        .observations
        .into_iter()
        .map(|member| {
            let event = member.observation.event;
            let m = event.metadata;
            Ok(SearchResultObservation {
                origin: event.origin.as_str().to_owned(),
                reporter_endpoint: event.reporter_endpoint.map(|v| v.to_string()),
                name: m.name.unwrap_or_default(),
                size_bytes: event.claim.size_bytes,
                sources: m.source_count.unwrap_or_default(),
                complete_sources: m.complete_source_count.unwrap_or_default(),
                source_client_id: m.source_client_id,
                source_client_port: m.source_client_port,
                file_type: m.file_type.unwrap_or_default(),
                media: SearchResultMedia {
                    artist: m.media_artist.unwrap_or_default(),
                    album: m.media_album.unwrap_or_default(),
                    title: m.media_title.unwrap_or_default(),
                    length_seconds: m.media_length_seconds.unwrap_or_default(),
                    bitrate_kbps: m.media_bitrate_kbps.unwrap_or_default(),
                    codec: m.media_codec.unwrap_or_default(),
                },
                rating: m.rating.unwrap_or_default(),
                aich_hash: m
                    .aich_root
                    .map(|root| data_encoding::BASE32_NOPAD.encode(&root))
                    .unwrap_or_default(),
                complete: m.complete.unwrap_or_default(),
                directory: m.directory.unwrap_or_default(),
                observed_at: timestamp_s(
                    member.last_seen_at_s,
                    "search observation last_seen_at_s",
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let s = result.summary;
    Ok(SearchResult {
        id: result.claim_id.to_string(),
        search_id: search_id.to_owned(),
        r#type: file_type_filter.to_owned(),
        hash: result.file_hash,
        size_bytes: result.size_bytes,
        name: s.name,
        sources: s.source_count,
        complete_sources: s.complete_source_count,
        source_client_id: s.source_client_id,
        source_client_port: s.source_client_port,
        file_type: s.file_type,
        media: SearchResultMedia {
            artist: s.media_artist,
            album: s.media_album,
            title: s.media_title,
            length_seconds: s.media_length_seconds,
            bitrate_kbps: s.media_bitrate_kbps,
            codec: s.media_codec,
        },
        rating: s.rating,
        aich_hash: s.aich_hash,
        complete: s.complete,
        directory: s.directory,
        observations,
    })
}

fn timestamp_s(value: i64, label: &str) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(value, 0).with_context(|| format!("invalid {label}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_spec_and_terminal_reason_survive_persistence() {
        let metadata = MetadataStore::in_memory().unwrap();
        let spec = SearchSpec {
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
        let result = SearchResult::from_observation(
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
            results: vec![result],
        };

        search.id = create_search(&metadata, &search).unwrap();
        search.results[0].search_id.clone_from(&search.id);
        let claim_id = metadata
            .ingest_search_observations(
                &[emulebb_metadata::MetadataContentObservationEvent {
                    claim: emulebb_metadata::MetadataContentClaim {
                        hash: hex::decode(&search.results[0].hash)
                            .unwrap()
                            .try_into()
                            .unwrap(),
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
                    fields: result_fields(&search.results[0]),
                    name_votes: projection_name_votes(&search.results[0]).unwrap(),
                },
            )
            .unwrap()
            .unwrap();
        search.results[0].id = claim_id.claim_id.to_string();
        search.status = "error".into();
        persist_search(&metadata, &search).unwrap();
        let searches = load_searches(&metadata).unwrap();

        assert_eq!(searches.len(), 1);
        let reloaded = searches.get(&search.id).unwrap();
        assert_eq!(reloaded.spec, spec);
        assert_eq!(reloaded.results[0].search_id, search.id);
        assert_eq!(reloaded.resolved_method.as_deref(), Some("global"));
        assert_eq!(reloaded.results.len(), 1);
        assert_eq!(reloaded.results[0].media.artist, "Example Artist");
        assert_eq!(reloaded.results[0].media.album, "Example Album");
        assert_eq!(reloaded.results[0].media.title, "Example Title");
        assert_eq!(reloaded.results[0].media.length_seconds, 240);
        assert_eq!(reloaded.results[0].media.bitrate_kbps, 1_411);
        assert_eq!(reloaded.results[0].media.codec, "flac");
        assert_eq!(reloaded.results[0].observations[0].origin, "global");
        assert_eq!(
            reloaded.status_reason.as_deref(),
            Some("network-search-failed")
        );
        assert_eq!(reloaded.progress.phase, "failed");
        assert_eq!(reloaded.progress.total_units, None);
    }
}

/// Publish the already committed display projection without re-aggregating it.
pub(crate) async fn publish_observation(
    state: &std::sync::Arc<tokio::sync::Mutex<crate::CoreState>>,
    search_id: &str,
    result: SearchResult,
) {
    let mut state = state.lock().await;
    let Some(search) = state.searches.get_mut(search_id) else {
        return;
    };
    if !matches!(search.status.as_str(), "queued" | "running") {
        return;
    }
    if let Some(existing) = search.results.iter_mut().find(|r| r.id == result.id) {
        *existing = result;
    } else {
        search.results.push(result);
    }
    search.updated_at = Utc::now();
}
