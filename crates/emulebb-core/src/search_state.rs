use std::collections::HashMap;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use emulebb_metadata::{
    MetadataSearch, MetadataSearchResult, MetadataStore, normalized_search_query,
};

use crate::{Search, SearchResult};

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

pub(crate) fn persist_search(metadata: &MetadataStore, search: &Search) -> Result<()> {
    metadata.upsert_search(&search_to_metadata(search))
}

fn search_to_metadata(search: &Search) -> MetadataSearch {
    let updated_at_ms = search.updated_at.timestamp_millis();
    MetadataSearch {
        public_id: search.id.clone(),
        query: search.query.clone(),
        normalized_query: normalized_search_query(&search.query),
        method: search.method.clone(),
        search_type: search.r#type.clone(),
        status: search.status.clone(),
        created_at_ms: search.created_at.timestamp_millis(),
        updated_at_ms,
        completed_at_ms: (search.status == "completed").then_some(updated_at_ms),
        results: search
            .results
            .iter()
            .map(|result| search_result_to_metadata(result, updated_at_ms))
            .collect(),
    }
}

fn search_result_to_metadata(result: &SearchResult, observed_at_ms: i64) -> MetadataSearchResult {
    MetadataSearchResult {
        source_method: result.method.clone(),
        file_hash: result.hash.clone(),
        name: result.name.clone(),
        size_bytes: result.size_bytes,
        source_count: result.sources,
        complete_source_count: result.complete_sources,
        file_type: result.file_type.clone(),
        complete: result.complete,
        known_type: result.known_type.clone(),
        directory: result.directory.clone(),
        observed_at_ms,
    }
}

fn search_from_metadata(search: MetadataSearch) -> Result<Search> {
    let created_at = timestamp_ms(search.created_at_ms, "search created_at_ms")?;
    let updated_at = timestamp_ms(search.updated_at_ms, "search updated_at_ms")?;
    Ok(Search {
        id: search.public_id.clone(),
        query: search.query,
        method: search.method,
        r#type: search.search_type.clone(),
        status: search.status,
        created_at,
        updated_at,
        results: search
            .results
            .into_iter()
            .map(|result| {
                search_result_from_metadata(&search.public_id, &search.search_type, result)
            })
            .collect(),
    })
}

fn search_result_from_metadata(
    search_id: &str,
    search_type: &str,
    result: MetadataSearchResult,
) -> SearchResult {
    SearchResult {
        search_id: search_id.to_string(),
        method: result.source_method,
        r#type: search_type.to_string(),
        hash: result.file_hash,
        name: result.name,
        size_bytes: result.size_bytes,
        sources: result.source_count,
        complete_sources: result.complete_source_count,
        file_type: result.file_type,
        complete: result.complete,
        known_type: result.known_type,
        directory: result.directory,
    }
}

fn timestamp_ms(value: i64, label: &str) -> Result<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp_millis(value).with_context(|| format!("invalid {label}"))
}
