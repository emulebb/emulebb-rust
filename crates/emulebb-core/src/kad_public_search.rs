//! Public `/api/v1/searches` Kad keyword search helpers.

use std::collections::HashMap;

use anyhow::{Result, ensure};
use emulebb_ed2k::ed2k_server::encode_kad_search_expression;
use emulebb_index::matches_restrictive_keyword_payload;
use emulebb_kad_dht::{DhtNode, RpcWorkClass};
use emulebb_kad_proto::{NodeId, SearchKeyReq};
use md4::{Digest, Md4};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{
    KadAichSearchVotes, SearchCreate, SearchResult,
    search_query::{search_criteria_from_request, search_result_from_kad},
};

const INVALID_KAD_KEYWORD_CHARS: &str = " ()[]{}<>,._-!?:;\\/\"";
pub(crate) struct KadKeywordSearchOutcome {
    pub(crate) results: Vec<SearchResult>,
    pub(crate) aich_votes: HashMap<String, KadAichSearchVotes>,
}

impl KadKeywordSearchOutcome {
    pub(crate) fn without_aich(results: Vec<SearchResult>) -> Self {
        Self {
            results,
            aich_votes: HashMap::new(),
        }
    }
}

pub(crate) async fn search_kad_keywords(
    dht: DhtNode,
    search_id: &str,
    request: &SearchCreate,
    cancel: &CancellationToken,
) -> Result<Option<KadKeywordSearchOutcome>> {
    if !dht.is_bootstrapped() {
        return Ok(None);
    }

    let search_request = kad_public_search_request(request)?;
    let restrictive_payload = search_request.restrictive_payload.clone();
    let mut stream = dht.search_keyword_request_with_cancel_and_class(
        search_request,
        cancel.clone(),
        RpcWorkClass::Interactive,
    );
    let mut results = Vec::<SearchResult>::new();
    let mut result_indexes = HashMap::<String, usize>::new();
    let mut aich_votes = HashMap::<String, KadAichSearchVotes>::new();

    while let Some(result) = stream.next().await {
        let mut result = result;
        result.names.retain(|name| {
            matches_restrictive_keyword_payload(name, &result.tags, &restrictive_payload)
        });
        if result.names.is_empty() {
            continue;
        }
        let hash = result.hash.to_string();
        if let Some(candidate) = result.aich_candidate {
            aich_votes
                .entry(hash.clone())
                .or_default()
                .record(candidate.responder_ip, candidate.root);
        }
        let mapped = search_result_from_kad(search_id, request, result);
        merge_kad_search_result(&mut results, &mut result_indexes, hash, mapped);
    }
    Ok(Some(KadKeywordSearchOutcome {
        results,
        aich_votes,
    }))
}

fn merge_kad_search_result(
    results: &mut Vec<SearchResult>,
    result_indexes: &mut HashMap<String, usize>,
    hash: String,
    mapped: SearchResult,
) {
    if let Some(index) = result_indexes.get(&hash).copied() {
        results[index].merge_observations(mapped);
    } else {
        // The DHT stream owns the configured result budget. Do not impose a
        // second, smaller presentation cap here: doing so silently discarded
        // valid hashes after the first 200 even though the Rust-native stream
        // was configured to harvest substantially more.
        result_indexes.insert(hash, results.len());
        results.push(mapped);
    }
}

fn kad_public_search_request(request: &SearchCreate) -> Result<SearchKeyReq> {
    let restrictive_payload =
        encode_kad_search_expression(&request.query, &search_criteria_from_request(request))?;
    Ok(SearchKeyReq {
        target: kad_public_search_keyword_target(&request.query)?,
        start_position: if restrictive_payload.is_empty() {
            0
        } else {
            0x8000
        },
        restrictive_payload,
    })
}

pub(crate) fn kad_public_search_keyword(query: &str) -> Result<String> {
    let expression = query.trim();
    let mut keyword = expression
        .split(' ')
        .find(|part| !part.is_empty())
        .unwrap_or_default()
        .to_string();
    if keyword.starts_with('"') {
        let len = keyword.len();
        if len > 1 && keyword.ends_with('"') {
            keyword = keyword[1..len - 1].to_string();
        } else if expression
            .char_indices()
            .skip(1)
            .any(|(index, char)| char == '"' && index > len)
        {
            keyword = keyword[1..].to_string();
        }
    }
    // Lower-case with the oracle's frozen keyword table (`KadTagStrMakeLower`),
    // not Rust's `str::to_lowercase()`, so the interactive search hashes the
    // primary keyword to the same md4 target eMule publishes it under — see
    // `ed2k_sources::kad_keyword_lowercase`.
    let keyword = crate::ed2k_sources::kad_keyword_lowercase(keyword.trim());
    ensure!(
        !keyword.is_empty()
            && !keyword
                .chars()
                .any(|char| INVALID_KAD_KEYWORD_CHARS.contains(char)),
        "invalid Kad search keyword"
    );
    Ok(keyword)
}

fn kad_public_search_keyword_target(query: &str) -> Result<NodeId> {
    Ok(keyword_hash_target(&kad_public_search_keyword(query)?))
}

fn keyword_hash_target(first_word: &str) -> NodeId {
    let mut hasher = Md4::new();
    hasher.update(first_word.as_bytes());
    let digest: [u8; 16] = hasher.finalize().into();
    NodeId::from_be_bytes(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SearchResultMedia, SearchResultObservation};
    use chrono::Utc;

    fn request(query: &str) -> SearchCreate {
        SearchCreate {
            query: query.to_string(),
            method: "kad".to_string(),
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
    fn kad_public_search_keyword_matches_mfc_first_token_rules() {
        assert_eq!(
            kad_public_search_keyword("Alpha Beta").unwrap(),
            "alpha".to_string()
        );
        assert_eq!(
            kad_public_search_keyword("\"Alpha Beta\" gamma").unwrap(),
            "alpha".to_string()
        );
        assert_eq!(
            kad_public_search_keyword("\"Alpha\" beta").unwrap(),
            "alpha".to_string()
        );
    }

    #[test]
    fn kad_public_search_keyword_rejects_mfc_invalid_keyword_chars() {
        assert!(kad_public_search_keyword("").is_err());
        assert!(kad_public_search_keyword("Alpha-Beta").is_err());
        assert!(kad_public_search_keyword("\"unterminated").is_err());
    }

    #[test]
    fn kad_public_search_request_carries_query_and_filters() {
        let mut request = request("Alpha Beta");
        request.extension = "mp3".to_string();
        request.min_size_bytes = Some(u64::from(u32::MAX) + 1);

        let encoded = kad_public_search_request(&request).unwrap();

        assert_eq!(encoded.start_position, 0x8000);
        assert!(!encoded.restrictive_payload.is_empty());
        assert!(matches_restrictive_keyword_payload(
            "alpha beta.mp3",
            &[emulebb_kad_proto::Tag::filesize(u64::from(u32::MAX) + 1),],
            &encoded.restrictive_payload,
        ));
        assert!(!matches_restrictive_keyword_payload(
            "alpha.mp3",
            &[emulebb_kad_proto::Tag::filesize(u64::from(u32::MAX) + 1),],
            &encoded.restrictive_payload,
        ));
        assert!(!matches_restrictive_keyword_payload(
            "alpha beta.flac",
            &[emulebb_kad_proto::Tag::filesize(u64::from(u32::MAX) + 1),],
            &encoded.restrictive_payload,
        ));
    }

    #[test]
    fn restrictive_payload_selects_only_matching_alternate_names() {
        let mut request = request("Alpha Beta");
        request.extension = "mp3".to_string();
        let payload = kad_public_search_request(&request)
            .unwrap()
            .restrictive_payload;
        let tags = vec![emulebb_kad_proto::Tag::filesize(1_024)];
        let mut names = vec![
            "alpha beta.mp3".to_string(),
            "alpha beta.exe".to_string(),
            "unrelated.mp3".to_string(),
            "ALPHA BETA.MP3".to_string(),
        ];

        names.retain(|name| matches_restrictive_keyword_payload(name, &tags, &payload));

        assert_eq!(
            names,
            vec!["alpha beta.mp3".to_string(), "ALPHA BETA.MP3".to_string()]
        );
    }

    #[test]
    fn public_collector_does_not_recap_the_dht_result_stream() {
        let mut results = Vec::new();
        let mut indexes = HashMap::new();

        // eMuleBB-MFC accepts 750 keyword answers by default. The public
        // collector must preserve at least that many distinct hashes when the
        // authoritative DHT stream budget permits them.
        for index in 0_u32..750 {
            let hash = format!("{index:032x}");
            let observation = SearchResultObservation {
                origin: "kad".to_string(),
                server_endpoint: None,
                name: format!("result-{index}.bin"),
                size_bytes: u64::from(index) + 1,
                sources: 1,
                complete_sources: 0,
                source_client_id: None,
                source_client_port: None,
                file_type: "unknown".to_string(),
                media: SearchResultMedia::default(),
                rating: 0,
                aich_hash: String::new(),
                complete: false,
                directory: String::new(),
                observed_at: Utc::now(),
            };
            let mapped = SearchResult::from_observation(
                "1".to_string(),
                String::new(),
                hash.clone(),
                observation,
            );
            merge_kad_search_result(&mut results, &mut indexes, hash, mapped);
        }

        assert_eq!(results.len(), 750);
        assert_eq!(indexes.len(), 750);
    }
}
