//! Public `/api/v1/searches` Kad keyword search helpers.

use std::{collections::HashSet, time::Duration};

use anyhow::{Result, ensure};
use emulebb_kad_dht::{DhtNode, RpcWorkClass};
use emulebb_kad_proto::{NodeId, constants::SEARCH_TIMEOUT_SECS};
use md4::{Digest, Md4};
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

use crate::{SearchCreate, SearchResult, search_query::search_result_from_kad};

const INVALID_KAD_KEYWORD_CHARS: &str = " ()[]{}<>,._-!?:;\\/\"";
const KAD_KEYWORD_SEARCH_RESULT_LIMIT: usize = 200;
// Give the keyword search the full Kad traversal lifetime. The underlying
// traversal (emulebb-kad-dht SEARCH_TIMEOUT) runs phase-1 find-node toward the
// keyword target and only THEN walks phase-2 SEARCH_KEY_REQ across the closest
// responders. A shorter outer cap (was 15s) cancelled the stream while phase-1
// was still converging, so phase-2 never emitted a single SEARCH_KEY_REQ and
// every keyword search returned 0 (live "0 results, no 0x33 on the wire"). The
// Kad *source* search already uses the 45s floor and works for the same reason;
// match it here so keyword file-discovery reaches phase-2. The search runs in a
// background task (create_search spawns run_background_search), so the longer
// budget does not block the POST — the client polls running->completed.
const KAD_KEYWORD_SEARCH_TIMEOUT_SECS: u64 = SEARCH_TIMEOUT_SECS;

pub(crate) async fn search_kad_keywords(
    dht: DhtNode,
    search_id: &str,
    request: &SearchCreate,
) -> Result<Option<Vec<SearchResult>>> {
    if !dht.is_bootstrapped() {
        return Ok(None);
    }

    let cancel = CancellationToken::new();
    let mut stream = dht.search_keywords_with_cancel_and_class(
        kad_public_search_keyword_target(&request.query)?,
        cancel.clone(),
        RpcWorkClass::Interactive,
    );
    let timeout = tokio::time::sleep(Duration::from_secs(KAD_KEYWORD_SEARCH_TIMEOUT_SECS));
    tokio::pin!(timeout);
    let mut results = Vec::new();
    let mut seen_hashes = HashSet::new();

    loop {
        tokio::select! {
            _ = &mut timeout => break,
            result = stream.next() => {
                let Some(result) = result else {
                    break;
                };
                if seen_hashes.insert(result.hash) {
                    results.push(search_result_from_kad(search_id, request, result));
                    if results.len() >= KAD_KEYWORD_SEARCH_RESULT_LIMIT {
                        break;
                    }
                }
            }
        }
    }
    cancel.cancel();
    Ok(Some(results))
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

    // Regression: the keyword-search outer timeout must cover the full Kad
    // traversal lifetime, or the stream is cancelled while phase-1 find-node is
    // still converging and no phase-2 SEARCH_KEY_REQ ever reaches the wire
    // (returns 0). Was 15s vs a 45s traversal; keep it >= the traversal lifetime.
    #[test]
    fn keyword_search_timeout_covers_traversal_lifetime() {
        // Compile-time assertion: both operands are consts, so a const block fails
        // the build (not just the test) if the invariant is ever broken. The const
        // context cannot format the values, so the message is static; the exact
        // numbers live in the regression comment above.
        const {
            assert!(
                KAD_KEYWORD_SEARCH_TIMEOUT_SECS >= SEARCH_TIMEOUT_SECS,
                "keyword search outer timeout must be >= the Kad traversal lifetime so phase-2 SEARCH_KEY_REQ can fire"
            )
        };
    }
}
