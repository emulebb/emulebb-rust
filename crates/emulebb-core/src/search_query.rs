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
        min_complete_sources: None,
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
        file_type: file.content_type.clone(),
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
    SearchResult {
        search_id: search_id.to_string(),
        method: request.method.clone(),
        r#type: request.r#type.clone(),
        hash: file.file_hash.to_string(),
        name: file.file_name.unwrap_or_else(|| file.file_hash.to_string()),
        size_bytes: file.file_size.unwrap_or_default(),
        sources: file.source_count.unwrap_or_default(),
        complete_sources: 0,
        file_type: file_type.clone(),
        complete: false,
        directory: String::new(),
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
        complete_sources: 0,
        file_type: "unknown".to_string(),
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
            file_type: String::new(),
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
        assert_eq!(result.file_type, "unknown");
    }
}
