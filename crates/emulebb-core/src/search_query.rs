//! Search-result construction and request-side filtering for the `/api/v1/searches` surface.

use emulebb_ed2k::ed2k_server::{Ed2kSearchFile, SearchCriteria};
use emulebb_index::IndexedFile;
use emulebb_kad_dht::SearchResult as KadSearchResult;

use crate::{SearchCreate, SearchResult};

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

/// Apply the optional `SearchCreateRequest` filters (extension, size bounds, and
/// minimum availability) from the eMuleBB `/api/v1` contract to a result set.
pub(crate) fn apply_search_filters(results: &mut Vec<SearchResult>, request: &SearchCreate) {
    let extension = request
        .extension
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    results.retain(|result| {
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
        true
    });
}

pub(crate) fn search_result_from_indexed(
    search_id: &str,
    request: &SearchCreate,
    file: IndexedFile,
) -> SearchResult {
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash: file.ed2k_hash,
        name: file.name,
        size_bytes: file.size_bytes,
        sources: file.availability_score.max(0) as u32,
        complete_sources: 0,
        source_client_id: None,
        source_client_port: None,
        file_type: file.content_type.clone(),
        rating: 0,
        aich_hash: String::new(),
        complete: false,
        directory: String::new(),
    }
}

pub(crate) fn search_result_from_ed2k(
    search_id: &str,
    request: &SearchCreate,
    file: Ed2kSearchFile,
) -> SearchResult {
    let file_type = file.file_type.unwrap_or_else(|| "unknown".to_string());
    let source_client_id = (file.client_id != 0).then_some(file.client_id);
    let source_client_port = (file.client_port != 0).then_some(file.client_port);
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash: file.file_hash.to_string(),
        name: file.file_name.unwrap_or_else(|| file.file_hash.to_string()),
        size_bytes: file.file_size.unwrap_or_default(),
        sources: file.source_count.unwrap_or_default(),
        complete_sources: file.complete_source_count.unwrap_or_default(),
        source_client_id,
        source_client_port,
        file_type: file_type.clone(),
        rating: file.rating.unwrap_or_default(),
        aich_hash: file.aich_hash.unwrap_or_default(),
        complete: false,
        directory: file.directory.unwrap_or_default(),
    }
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
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash,
        name,
        size_bytes: result.size.unwrap_or_default(),
        sources: result.source_count.unwrap_or_default(),
        complete_sources: result.source_count.unwrap_or_default(),
        source_client_id: None,
        source_client_port: None,
        file_type: "unknown".to_string(),
        rating: 0,
        aich_hash: String::new(),
        complete: false,
        directory: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulebb_kad_proto::Ed2kHash;

    fn result(name: &str, size_bytes: u64, sources: u32) -> SearchResult {
        SearchResult {
            search_id: "s".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            hash: "00112233445566778899aabbccddeeff".to_string(),
            name: name.to_string(),
            size_bytes,
            sources,
            complete_sources: 0,
            source_client_id: None,
            source_client_port: None,
            file_type: String::new(),
            rating: 0,
            aich_hash: String::new(),
            complete: false,
            directory: String::new(),
        }
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
    fn extension_size_and_availability_filters_apply() {
        let mut results = vec![
            result("Movie.One.mkv", 5_000, 8),
            result("Movie.Two.mkv", 50, 8),
            result("Movie.Three.avi", 5_000, 8),
            result("Movie.Four.mkv", 5_000, 1),
        ];
        let mut req = request();
        req.extension = "MKV".to_string();
        req.min_size_bytes = Some(1_000);
        req.max_size_bytes = Some(10_000);
        req.min_availability = Some(5);
        apply_search_filters(&mut results, &req);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Movie.One.mkv");
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
                source_count: Some(9),
                tags: Vec::new(),
            },
        );

        assert_eq!(result.search_id, "42");
        assert_eq!(result.hash, file_hash.to_string());
        assert_eq!(result.name, "Sample File.bin");
        assert_eq!(result.size_bytes, 1234);
        assert_eq!(result.sources, 9);
        assert_eq!(result.complete_sources, 9);
        assert_eq!(result.file_type, "unknown");
    }

    #[test]
    fn ed2k_result_maps_source_identity_and_complete_sources() {
        let req = request();
        let file_hash = Ed2kHash::from_bytes([0x22; 16]);
        let result = search_result_from_ed2k(
            "43",
            &req,
            Ed2kSearchFile {
                file_hash,
                client_id: u32::from_le_bytes([10, 20, 30, 40]),
                client_port: 4662,
                file_name: Some("Server Result.pdf".to_string()),
                file_size: Some(4096),
                file_type: Some("doc".to_string()),
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
        assert_eq!(result.rating, 4);
        assert_eq!(result.aich_hash, "A".repeat(32));
        assert_eq!(result.directory, "Synthetic Folder");
    }
}
