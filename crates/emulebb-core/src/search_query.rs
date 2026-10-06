//! Search-result construction and request-side filtering for the `/api/v1/searches` surface.

use chrono::Utc;
use emulebb_ed2k::ed2k_server::{Ed2kSearchFile, SearchCriteria};
use emulebb_index::IndexedFile;
use emulebb_kad_dht::SearchResult as KadSearchResult;

use crate::{SearchCreate, SearchResult, SearchResultMedia, SearchResultObservation};

/// Build the server-side eD2k metatag search criteria from a `/api/v1/searches`
/// request, so the constraints (type/size/extension/availability) are folded
/// into the OP_SEARCHREQUEST tree (eMule `GetSearchPacket`) instead of only
/// post-filtered. Empty/unset fields are omitted. `apply_search_filters` still
/// runs as a defensive client-side pass.
pub(crate) fn search_criteria_from_request(request: &SearchCreate) -> SearchCriteria {
    let non_empty = |value: &str| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    SearchCriteria {
        file_type: ed2k_wire_file_type(&request.r#type),
        extension: non_empty(&request.extension),
        min_size: request.min_size_bytes.filter(|&v| v > 0),
        max_size: request.max_size_bytes.filter(|&v| v > 0),
        min_availability: request.min_availability.filter(|&v| v > 0),
        min_complete_sources: request.min_complete_sources.filter(|&v| v > 0),
        min_bitrate_kbps: request.min_bitrate_kbps.filter(|&v| v > 0),
        min_length_seconds: request.min_length_seconds.filter(|&v| v > 0),
        codec: non_empty(&request.codec),
        title: non_empty(&request.title),
        album: non_empty(&request.album),
        artist: non_empty(&request.artist),
    }
}

/// Map the lowercase `/api/v1/searches` `type` token (validated set: arc, audio,
/// iso, image, pro, video, doc, emulecollection) to the canonical eD2k
/// FT_FILETYPE wire string (ED2KFTSTR_*). "arc"/"iso" fold to "Pro" exactly as
/// eMule's GetSearchPacket does. Empty/unknown -> None (no type constraint).
fn ed2k_wire_file_type(token: &str) -> Option<String> {
    let wire = match token.trim().to_ascii_lowercase().as_str() {
        "" => return None,
        "audio" => "Audio",
        "video" => "Video",
        "image" => "Image",
        "doc" => "Doc",
        "pro" | "arc" | "iso" => "Pro",
        "emulecollection" => "EmuleCollection",
        _ => return None,
    };
    Some(wire.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchNetworkMethod {
    Ed2kServer,
    Ed2kGlobal,
    Kad,
}

/// Resolve the public search method against live network state.
///
/// This mirrors the MFC client policy: automatic searches prefer ED2K global
/// search when ED2K is connected, fall back to Kad only when Kad is the sole
/// connected search network, and fail closed when no search network is ready.
pub(crate) fn resolve_search_network_method(
    method: &str,
    ed2k_connected: bool,
    kad_connected: bool,
) -> Option<SearchNetworkMethod> {
    match method.trim().to_ascii_lowercase().as_str() {
        "server" => Some(SearchNetworkMethod::Ed2kServer),
        "global" => Some(SearchNetworkMethod::Ed2kGlobal),
        "kad" => Some(SearchNetworkMethod::Kad),
        "" | "automatic" => {
            if ed2k_connected {
                Some(SearchNetworkMethod::Ed2kGlobal)
            } else if kad_connected {
                Some(SearchNetworkMethod::Kad)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Apply the optional `SearchCreateRequest` filters for which every result has
/// local evidence (file family, extension, size bounds, and source counts).
/// This defensive pass rejects replies that do not honor the constraints
/// encoded on the wire.
pub(crate) fn apply_search_filters(results: &mut Vec<SearchResult>, request: &SearchCreate) {
    let file_type = ed2k_wire_file_type(&request.r#type);
    let extension = request
        .extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    results.retain(|result| {
        if let Some(file_type) = file_type.as_deref()
            && result_file_type(result) != Some(file_type)
        {
            return false;
        }
        if !extension.is_empty() {
            let suffix = format!(".{extension}");
            if !result.name.to_ascii_lowercase().ends_with(&suffix) {
                return false;
            }
        }
        if let Some(min) = request.min_size_bytes
            && result.size_bytes < min
        {
            return false;
        }
        if let Some(max) = request.max_size_bytes
            && result.size_bytes > max
        {
            return false;
        }
        if let Some(min_availability) = request.min_availability
            && result.sources < min_availability
        {
            return false;
        }
        if let Some(min_complete_sources) = request.min_complete_sources
            && result.complete_sources < min_complete_sources
        {
            return false;
        }
        true
    });
}

fn result_file_type(result: &SearchResult) -> Option<&'static str> {
    let tagged = match result.file_type.trim().to_ascii_lowercase().as_str() {
        "audio" => Some("Audio"),
        "video" => Some("Video"),
        "image" => Some("Image"),
        "doc" | "document" => Some("Doc"),
        "pro" | "program" | "arc" | "archive" | "iso" => Some("Pro"),
        "emulecollection" => Some("EmuleCollection"),
        _ => None,
    };
    tagged.or_else(|| crate::ed2k_file_type_search_term(&result.name))
}

pub(crate) fn search_result_from_indexed(
    search_id: &str,
    request: &SearchCreate,
    file: IndexedFile,
) -> SearchResult {
    let observation = SearchResultObservation {
        origin: "local_index".to_string(),
        name: file.name,
        size_bytes: file.size_bytes,
        sources: file.availability_score.max(0) as u32,
        complete_sources: 0,
        source_client_id: None,
        source_client_port: None,
        file_type: file.content_type.clone(),
        media: SearchResultMedia::default(),
        rating: 0,
        aich_hash: String::new(),
        complete: false,
        directory: String::new(),
        observed_at: Utc::now(),
    };
    SearchResult::from_observation(
        search_id.to_string(),
        request.r#type.clone(),
        file.ed2k_hash,
        observation,
    )
}

pub(crate) fn search_result_from_ed2k(
    search_id: &str,
    request: &SearchCreate,
    origin: &str,
    file: Ed2kSearchFile,
) -> SearchResult {
    let file_type = file.file_type.unwrap_or_else(|| "unknown".to_string());
    let source_client_id = (file.client_id != 0).then_some(file.client_id);
    let source_client_port = (file.client_port != 0).then_some(file.client_port);
    let observation = SearchResultObservation {
        origin: origin.to_string(),
        name: file.file_name.unwrap_or_else(|| file.file_hash.to_string()),
        size_bytes: file.file_size.unwrap_or_default(),
        sources: file.source_count.unwrap_or_default(),
        complete_sources: file.complete_source_count.unwrap_or_default(),
        source_client_id,
        source_client_port,
        file_type: file_type.clone(),
        media: SearchResultMedia {
            length_seconds: file.media_length_seconds.unwrap_or_default(),
            bitrate_kbps: file.media_bitrate_kbps.unwrap_or_default(),
            codec: file.media_codec.unwrap_or_default(),
            ..SearchResultMedia::default()
        },
        rating: file.rating.unwrap_or_default(),
        aich_hash: file.aich_hash.unwrap_or_default(),
        complete: false,
        directory: file.directory.unwrap_or_default(),
        observed_at: Utc::now(),
    };
    SearchResult::from_observation(
        search_id.to_string(),
        request.r#type.clone(),
        file.file_hash.to_string(),
        observation,
    )
}

pub(crate) fn search_result_from_kad(
    search_id: &str,
    request: &SearchCreate,
    result: KadSearchResult,
) -> SearchResult {
    let hash = result.hash.to_string();
    let name = result
        .names
        .into_iter()
        .find(|name| !name.trim().is_empty())
        .unwrap_or_else(|| hash.clone());
    let aich_hash = result
        .aich_candidate
        .map(|candidate| hex::encode(candidate.root))
        .unwrap_or_default();
    let observation = SearchResultObservation {
        origin: "kad".to_string(),
        name,
        size_bytes: result.size.unwrap_or_default(),
        sources: result.source_count.unwrap_or_default(),
        complete_sources: result.source_count.unwrap_or_default(),
        source_client_id: None,
        source_client_port: None,
        file_type: result.file_type.unwrap_or_else(|| "unknown".to_string()),
        media: SearchResultMedia {
            artist: result.media_artist.unwrap_or_default(),
            album: result.media_album.unwrap_or_default(),
            title: result.media_title.unwrap_or_default(),
            length_seconds: result.media_length_seconds.unwrap_or_default(),
            bitrate_kbps: result.media_bitrate_kbps.unwrap_or_default(),
            codec: result.media_codec.unwrap_or_default(),
        },
        rating: 0,
        aich_hash,
        complete: false,
        directory: String::new(),
        observed_at: Utc::now(),
    };
    SearchResult::from_observation(
        search_id.to_string(),
        request.r#type.clone(),
        hash,
        observation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_dht::KadAichCandidate;
    use emulebb_kad_proto::Ed2kHash;
    use std::net::Ipv4Addr;

    fn result(name: &str, size_bytes: u64, sources: u32) -> SearchResult {
        SearchResult::from_observation(
            "s".to_string(),
            String::new(),
            "00112233445566778899aabbccddeeff".to_string(),
            SearchResultObservation {
                origin: "unknown".to_string(),
                name: name.to_string(),
                size_bytes,
                sources,
                complete_sources: 0,
                source_client_id: None,
                source_client_port: None,
                file_type: String::new(),
                media: SearchResultMedia::default(),
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observed_at: Utc::now(),
            },
        )
    }

    fn request() -> SearchCreate {
        SearchCreate {
            query: "q".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            extension: String::new(),
            min_size_bytes: None,
            max_size_bytes: None,
            min_availability: None,
            min_complete_sources: None,
            min_bitrate_kbps: None,
            min_length_seconds: None,
            codec: String::new(),
            title: String::new(),
            album: String::new(),
            artist: String::new(),
        }
    }

    #[test]
    fn resolves_explicit_search_methods_without_cross_network_fallback() {
        assert_eq!(
            resolve_search_network_method("server", false, true),
            Some(SearchNetworkMethod::Ed2kServer)
        );
        assert_eq!(
            resolve_search_network_method("global", false, true),
            Some(SearchNetworkMethod::Ed2kGlobal)
        );
        assert_eq!(
            resolve_search_network_method("kad", true, false),
            Some(SearchNetworkMethod::Kad)
        );
    }

    #[test]
    fn automatic_search_prefers_ed2k_global_then_kad() {
        assert_eq!(
            resolve_search_network_method("automatic", true, true),
            Some(SearchNetworkMethod::Ed2kGlobal)
        );
        assert_eq!(
            resolve_search_network_method("automatic", false, true),
            Some(SearchNetworkMethod::Kad)
        );
        assert_eq!(
            resolve_search_network_method("automatic", false, false),
            None
        );
        assert_eq!(
            resolve_search_network_method("", true, true),
            Some(SearchNetworkMethod::Ed2kGlobal)
        );
    }

    #[test]
    fn empty_filters_keep_all_results() {
        let mut results = vec![result("A.bin", 10, 1), result("B.mkv", 20, 2)];
        apply_search_filters(&mut results, &request());
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn extension_size_and_source_filters_apply() {
        let mut results = vec![
            result("Movie.One.mkv", 5_000, 8),
            result("Movie.Two.mkv", 50, 8),
            result("Movie.Three.avi", 5_000, 8),
            result("Movie.Four.mkv", 5_000, 1),
            result("Movie.Five.mkv", 5_000, 8),
        ];
        results[0].complete_sources = 3;
        results[0].observations[0].complete_sources = 3;
        results[4].complete_sources = 1;
        results[4].observations[0].complete_sources = 1;
        let mut req = request();
        req.extension = "MKV".to_string();
        req.min_size_bytes = Some(1_000);
        req.max_size_bytes = Some(10_000);
        req.min_availability = Some(5);
        req.min_complete_sources = Some(2);
        apply_search_filters(&mut results, &req);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Movie.One.mkv");
    }

    #[test]
    fn file_type_filter_uses_stock_type_families_and_filename_fallback() {
        let mut video = result("Movie.mkv", 5_000, 8);
        video.file_type = "Video".to_string();
        let mut audio = result("Track.flac", 5_000, 8);
        audio.file_type = "audio".to_string();
        let mut archive = result("Bundle.7z", 5_000, 8);
        archive.file_type = "archive".to_string();
        let unknown_iso = result("Disc.iso", 5_000, 8);

        let mut req = request();
        req.r#type = "video".to_string();
        let mut results = vec![
            video.clone(),
            audio.clone(),
            archive.clone(),
            unknown_iso.clone(),
        ];
        apply_search_filters(&mut results, &req);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Movie.mkv");

        // Stock eMule folds archive, CD-image, and program searches into the
        // same `Pro` wire family. An untagged result can be classified from
        // its filename, as Kad/local observations commonly require.
        req.r#type = "iso".to_string();
        let mut results = vec![video, audio, archive, unknown_iso];
        apply_search_filters(&mut results, &req);
        assert_eq!(
            results
                .iter()
                .map(|result| result.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Bundle.7z", "Disc.iso"]
        );
    }

    #[test]
    fn hash_merge_retains_observations_and_recomputes_the_aggregate() {
        let mut local = result("local-name.bin", 0, 1);
        let mut network = result("network-name.bin", 4_096, 12);
        local.observations[0].origin = "local_index".to_string();
        network.observations[0].origin = "global".to_string();
        network.observations[0].complete_sources = 4;
        network.observations[0].file_type = "Pro".to_string();
        network.observations[0].media = SearchResultMedia {
            artist: "Example Artist".to_string(),
            album: "Example Album".to_string(),
            title: "Example Title".to_string(),
            length_seconds: 321,
            bitrate_kbps: 192,
            codec: "AV1".to_string(),
        };
        network.observations[0].rating = 3;
        network.observations[0].aich_hash = "A".repeat(32);
        let expected_media = network.observations[0].media.clone();

        local.merge_observations(network.clone());
        local.merge_observations(network);

        assert_eq!(local.observations.len(), 2);
        assert_eq!(local.name, "network-name.bin");
        assert_eq!(local.size_bytes, 4_096);
        assert_eq!(local.sources, 12);
        assert_eq!(local.complete_sources, 4);
        assert_eq!(local.file_type, "Pro");
        assert_eq!(local.media, expected_media);
        assert_eq!(local.rating, 3);
        assert_eq!(local.aich_hash, "A".repeat(32));
    }

    #[test]
    fn media_search_fields_map_to_server_criteria() {
        let mut req = request();
        req.r#type = "audio".to_string();
        req.extension = " mp3 ".to_string();
        req.min_size_bytes = Some(1_024);
        req.max_size_bytes = Some(8_192);
        req.min_availability = Some(4);
        req.min_complete_sources = Some(2);
        req.min_bitrate_kbps = Some(192);
        req.min_length_seconds = Some(180);
        req.codec = " MPEG Layer-3 ".to_string();
        req.title = " Synthetic Title ".to_string();
        req.album = " Sample Album ".to_string();
        req.artist = " Example Artist ".to_string();

        let criteria = search_criteria_from_request(&req);

        assert_eq!(criteria.file_type.as_deref(), Some("Audio"));
        assert_eq!(criteria.extension.as_deref(), Some("mp3"));
        assert_eq!(criteria.min_size, Some(1_024));
        assert_eq!(criteria.max_size, Some(8_192));
        assert_eq!(criteria.min_availability, Some(4));
        assert_eq!(criteria.min_complete_sources, Some(2));
        assert_eq!(criteria.min_bitrate_kbps, Some(192));
        assert_eq!(criteria.min_length_seconds, Some(180));
        assert_eq!(criteria.codec.as_deref(), Some("MPEG Layer-3"));
        assert_eq!(criteria.title.as_deref(), Some("Synthetic Title"));
        assert_eq!(criteria.album.as_deref(), Some("Sample Album"));
        assert_eq!(criteria.artist.as_deref(), Some("Example Artist"));
    }

    #[test]
    fn kad_result_maps_to_rest_search_result() {
        let req = request();
        let file_hash = Ed2kHash::from_bytes([0x11; 16]);
        let result = search_result_from_kad(
            "42",
            &req,
            KadSearchResult {
                hash: file_hash,
                names: vec!["Sample File.bin".to_string()],
                size: Some(1234),
                file_type: Some("Audio".to_string()),
                source_count: Some(9),
                media_artist: Some("Example Artist".to_string()),
                media_album: Some("Example Album".to_string()),
                media_title: Some("Example Title".to_string()),
                media_length_seconds: Some(321),
                media_bitrate_kbps: Some(192),
                media_codec: Some("MP3".to_string()),
                aich_candidate: Some(KadAichCandidate {
                    root: [0xAB; 20],
                    responder_ip: Ipv4Addr::new(203, 0, 113, 9),
                }),
                tags: Vec::new(),
            },
        );

        assert_eq!(result.search_id, "42");
        assert_eq!(result.hash, file_hash.to_string());
        assert_eq!(result.name, "Sample File.bin");
        assert_eq!(result.size_bytes, 1234);
        assert_eq!(result.sources, 9);
        assert_eq!(result.complete_sources, 9);
        assert_eq!(result.file_type, "Audio");
        assert_eq!(result.media.artist, "Example Artist");
        assert_eq!(result.media.album, "Example Album");
        assert_eq!(result.media.title, "Example Title");
        assert_eq!(result.media.length_seconds, 321);
        assert_eq!(result.media.bitrate_kbps, 192);
        assert_eq!(result.media.codec, "MP3");
        assert_eq!(result.aich_hash, hex::encode([0xAB; 20]));
    }

    #[test]
    fn ed2k_result_maps_source_identity_and_complete_sources() {
        let req = request();
        let file_hash = Ed2kHash::from_bytes([0x22; 16]);
        let result = search_result_from_ed2k(
            "43",
            &req,
            "global",
            Ed2kSearchFile {
                file_hash,
                client_id: u32::from_le_bytes([10, 20, 30, 40]),
                client_port: 4662,
                file_name: Some("Server Result.pdf".to_string()),
                file_size: Some(4096),
                file_type: Some("doc".to_string()),
                media_length_seconds: Some(245),
                media_bitrate_kbps: Some(320),
                media_codec: Some("AAC".to_string()),
                source_count: Some(5),
                complete_source_count: Some(3),
                rating: Some(4),
                aich_hash: Some("A".repeat(32)),
                directory: Some("Synthetic Folder".to_string()),
            },
        );

        assert_eq!(result.search_id, "43");
        assert_eq!(result.hash, file_hash.to_string());
        assert_eq!(result.sources, 5);
        assert_eq!(result.complete_sources, 3);
        assert_eq!(
            result.source_client_id,
            Some(u32::from_le_bytes([10, 20, 30, 40]))
        );
        assert_eq!(result.source_client_port, Some(4662));
        assert_eq!(result.file_type, "doc");
        assert_eq!(result.media.length_seconds, 245);
        assert_eq!(result.media.bitrate_kbps, 320);
        assert_eq!(result.media.codec, "AAC");
        assert_eq!(result.rating, 4);
        assert_eq!(result.aich_hash, "A".repeat(32));
        assert_eq!(result.directory, "Synthetic Folder");
        assert_eq!(result.observations[0].origin, "global");
    }
}
