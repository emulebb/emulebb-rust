use std::{
    collections::{BTreeSet, HashSet},
    fmt::Write as _,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    time::SystemTime,
};

use anyhow::{Result, bail};
use chrono::Utc;
use emulebb_core::Search;
use serde_json::{Value, json};

use crate::{
    RestState,
    handlers::logs::recent_log_values,
    responses::{
        app_info_response, runtime_diagnostics_response, search_results_response,
        search_session_response, server_response, shared_file_response, status_response,
    },
};

pub(crate) const DIAGNOSTIC_BUNDLE_SCHEMA: &str = "emulebb.diagnostic-bundle.v6";
pub(crate) const MIN_DIAGNOSTIC_BUNDLE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_DIAGNOSTIC_BUNDLE_BYTES: usize = 64 * 1024 * 1024;

const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_LOG_RECORDS: usize = 200;
const MAX_TAIL_BYTES: u64 = 256 * 1024;
const MAX_TAIL_RECORDS: usize = 64;
const MAX_SERVER_SNAPSHOTS: usize = 512;
const MAX_SHARED_FILE_SNAPSHOTS: usize = 512;
const MAX_SEARCH_SNAPSHOTS: usize = 64;
const MAX_SEARCH_RESULTS_PER_SNAPSHOT: usize = 128;
const MAX_TRANSFER_SNAPSHOTS: usize = 512;
const MAX_UPLOAD_SNAPSHOTS: usize = 512;
const MAX_UPLOAD_QUEUE_SNAPSHOTS: usize = 512;

const ARTIFACT_FAMILIES: &[ArtifactFamilySpec] = &[ArtifactFamilySpec {
    family: "unifiedEvents",
    file_prefix: "emulebb-rust-diag-",
    expected_schema: "diag_event_v2",
    sequence_field: "seq",
    sequence_assessment: "processWideMonotonicTail",
}];

#[derive(Clone, Copy)]
struct ArtifactFamilySpec {
    family: &'static str,
    file_prefix: &'static str,
    expected_schema: &'static str,
    sequence_field: &'static str,
    sequence_assessment: &'static str,
}

struct ArtifactCollection {
    log_directory: Value,
    families: Vec<Value>,
    file_count: u64,
    missing_families: Vec<String>,
    issue_count: u64,
    directory_scan_truncated: bool,
}

struct ArtifactCandidate {
    file_name: String,
    path: PathBuf,
    modified: SystemTime,
}

#[derive(Debug)]
struct UnifiedRunSelection {
    run_id: String,
    process_id: u64,
    active_file_name: String,
}

struct TailRead {
    file_name: String,
    file_size: u64,
    tail_start_offset: u64,
    bytes_read: usize,
    incomplete_final_line_ignored: bool,
    lines: Vec<Vec<u8>>,
}

pub(crate) async fn capture(state: &RestState, max_bytes: usize) -> Result<Vec<u8>> {
    if !(MIN_DIAGNOSTIC_BUNDLE_BYTES..=MAX_DIAGNOSTIC_BUNDLE_BYTES).contains(&max_bytes) {
        bail!(
            "maxBytes must be in the range {MIN_DIAGNOSTIC_BUNDLE_BYTES}..={MAX_DIAGNOSTIC_BUNDLE_BYTES}"
        );
    }
    let status = status_response(state).await;
    let runtime_diagnostics = match status.get("runtimeDiagnostics") {
        Some(runtime_diagnostics) => runtime_diagnostics.clone(),
        None => runtime_diagnostics_response(state).await,
    };
    let unified_run = unified_run_selection(&runtime_diagnostics);
    let writer_issues = diagnostic_writer_issues(&runtime_diagnostics);
    let writer_issue_count = writer_issues.len() as u64;
    let settings = match state.core.app_settings().await {
        Ok(settings) => serde_json::to_value(settings)?,
        Err(error) => json!({
            "available": false,
            "error": error.to_string(),
        }),
    };
    let artifacts = collect_artifacts(
        std::env::var_os("EMULEBB_RUST_LOG_DIR").map(PathBuf::from),
        unified_run.as_ref(),
    );
    let logs = recent_log_values(MAX_LOG_RECORDS);
    let operational_snapshots = operational_snapshots(state).await;

    let payload = json!({
        "schema": DIAGNOSTIC_BUNDLE_SCHEMA,
        "capturedAt": Utc::now(),
        "app": app_info_response(state.core.app_info()),
        "status": status,
        "settings": settings,
        "settingsProvenance": {
            "source": "profileState",
            "apiKeyIncluded": true,
            "sensitiveValues": "exact",
            "apiKey": state.api_key.as_str(),
        },
        "recentLogs": bounded_tail_collection(&logs, MAX_LOG_RECORDS, Value::clone),
        "operationalSnapshots": operational_snapshots,
        "diagnosticHealth": {
            "writerIssues": writer_issues,
        },
        "diagnosticArtifacts": {
            "logDirectory": artifacts.log_directory,
            "families": artifacts.families,
            "directoryScanTruncated": artifacts.directory_scan_truncated,
        },
        "limits": {
            "recentLogRecords": MAX_LOG_RECORDS,
            "artifactFamilies": ARTIFACT_FAMILIES.len(),
            "directoryEntriesScanned": MAX_DIRECTORY_ENTRIES,
            "tailBytesPerArtifact": MAX_TAIL_BYTES,
            "tailRecordsPerArtifact": MAX_TAIL_RECORDS,
            "serverSnapshots": MAX_SERVER_SNAPSHOTS,
            "sharedFileSnapshots": MAX_SHARED_FILE_SNAPSHOTS,
            "searchSnapshots": MAX_SEARCH_SNAPSHOTS,
            "searchResultsPerSnapshot": MAX_SEARCH_RESULTS_PER_SNAPSHOT,
            "transferSnapshots": MAX_TRANSFER_SNAPSHOTS,
            "uploadSnapshots": MAX_UPLOAD_SNAPSHOTS,
            "uploadQueueSnapshots": MAX_UPLOAD_QUEUE_SNAPSHOTS,
        },
        "summary": {
            "artifactFileCount": artifacts.file_count,
            "missingArtifactFamilies": artifacts.missing_families,
            "issueCount": artifacts.issue_count.saturating_add(writer_issue_count),
        },
        "budget": {
            "maxBytes": max_bytes,
            "encodedBytes": 0,
            "truncated": false,
            "truncatedSections": [],
        },
    });

    encode_bounded_bundle(payload, max_bytes)
}

async fn operational_snapshots(state: &RestState) -> Value {
    let mut servers = state.core.servers().await;
    servers.sort_by(|left, right| left.endpoint.cmp(&right.endpoint));
    let (shared_files, shared_file_total) =
        state.core.shares_page(0, MAX_SHARED_FILE_SNAPSHOTS).await;
    let mut searches = state.core.searches().await;
    searches.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut transfers = state.core.transfers().await;
    transfers.sort_by(|left, right| {
        left.added_at
            .cmp(&right.added_at)
            .then_with(|| left.hash.cmp(&right.hash))
    });
    let uploads = state.core.uploads().await;
    let upload_queue = state.core.upload_queue().await;
    json!({
        "servers": bounded_prefix_collection(
            &servers,
            servers.len(),
            MAX_SERVER_SNAPSHOTS,
            server_response,
        ),
        "sharedFiles": bounded_prefix_collection(
            &shared_files,
            shared_file_total,
            MAX_SHARED_FILE_SNAPSHOTS,
            |share| json!(shared_file_response(share)),
        ),
        "searches": bounded_tail_collection(&searches, MAX_SEARCH_SNAPSHOTS, search_snapshot),
        "transfers": bounded_tail_collection(&transfers, MAX_TRANSFER_SNAPSHOTS, |transfer| json!(transfer)),
        "uploads": bounded_prefix_collection(
            &uploads,
            uploads.len(),
            MAX_UPLOAD_SNAPSHOTS,
            |upload| json!(upload),
        ),
        "uploadQueue": bounded_prefix_collection(
            &upload_queue,
            upload_queue.len(),
            MAX_UPLOAD_QUEUE_SNAPSHOTS,
            |upload| json!(upload),
        ),
    })
}

fn bounded_tail_collection<T>(items: &[T], limit: usize, render: impl Fn(&T) -> Value) -> Value {
    let omitted_before_limit = items.len().saturating_sub(limit);
    let retained = &items[omitted_before_limit..];
    json!({
        "total": items.len(),
        "included": retained.len(),
        "omittedBeforeLimit": omitted_before_limit,
        "omittedForBudget": 0,
        "limit": limit,
        "items": retained.iter().map(render).collect::<Vec<_>>(),
    })
}

fn bounded_prefix_collection<T>(
    items: &[T],
    total: usize,
    limit: usize,
    render: impl Fn(&T) -> Value,
) -> Value {
    let included = items.len().min(limit);
    let retained = &items[..included];
    json!({
        "total": total,
        "included": retained.len(),
        "omittedAfterLimit": total.saturating_sub(retained.len()),
        "omittedForBudget": 0,
        "limit": limit,
        "items": retained.iter().map(render).collect::<Vec<_>>(),
    })
}

fn search_snapshot(search: &Search) -> Value {
    let included = search.results.len().min(MAX_SEARCH_RESULTS_PER_SNAPSHOT);
    let retained = &search.results[..included];
    let mut snapshot = search_session_response(search);
    snapshot["createdAt"] = json!(search.created_at);
    snapshot["updatedAt"] = json!(search.updated_at);
    snapshot["results"] = json!({
        "total": search.results.len(),
        "included": retained.len(),
        "omittedAfterLimit": search.results.len().saturating_sub(retained.len()),
        "omittedForBudget": 0,
        "limit": MAX_SEARCH_RESULTS_PER_SNAPSHOT,
        "items": search_results_response(retained, true),
    });
    snapshot
}

fn diagnostic_writer_issues(runtime_diagnostics: &Value) -> Vec<Value> {
    let Some(writer) = runtime_diagnostics.get("diagnosticWriter") else {
        return vec![json!({"code": "diagnosticWriterMissing"})];
    };
    match writer.get("enabled").and_then(Value::as_bool) {
        Some(false) => return Vec::new(),
        Some(true) => {}
        None => return vec![json!({"code": "diagnosticWriterStateInvalid"})],
    }
    if writer.get("configured").and_then(Value::as_bool) != Some(true) {
        return vec![json!({"code": "diagnosticWriterNotConfigured"})];
    }
    if writer.get("initialized").and_then(Value::as_bool) != Some(true) {
        return vec![json!({
            "code": "diagnosticWriterNotInitialized",
            "initializationFailure": writer.get("initializationFailure").cloned().unwrap_or(Value::Null),
        })];
    }

    let mut issues = Vec::new();
    if writer
        .get("storageAuthorityFaulted")
        .and_then(Value::as_bool)
        == Some(true)
    {
        issues.push(json!({
            "code": "diagnosticWriterStorageAuthorityFaulted",
            "reason": writer.get("storageBlockReason").cloned().unwrap_or(Value::Null),
        }));
    }
    if writer.get("writerIoFaulted").and_then(Value::as_bool) == Some(true) {
        issues.push(json!({"code": "diagnosticWriterIoFaulted"}));
    }
    if writer
        .get("storagePolicySatisfied")
        .and_then(Value::as_bool)
        == Some(false)
    {
        issues.push(json!({
            "code": "diagnosticWriterStoragePolicyUnsatisfied",
            "reason": writer.get("storageBlockReason").cloned().unwrap_or(Value::Null),
        }));
    }
    let dropped_events = writer
        .get("droppedEvents")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if dropped_events > 0 {
        issues.push(json!({
            "code": "diagnosticWriterDroppedEvents",
            "count": dropped_events,
        }));
    }
    issues
}

fn unified_run_selection(runtime_diagnostics: &Value) -> Option<UnifiedRunSelection> {
    let writer = runtime_diagnostics.get("diagnosticWriter")?;
    if writer.get("initialized").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    Some(UnifiedRunSelection {
        run_id: writer.get("runId")?.as_str()?.to_string(),
        process_id: writer.get("processId")?.as_u64()?,
        active_file_name: writer.get("activeFileName")?.as_str()?.to_string(),
    })
}

fn collect_artifacts(
    log_dir: Option<PathBuf>,
    unified_run: Option<&UnifiedRunSelection>,
) -> ArtifactCollection {
    let Some(log_dir) = log_dir else {
        return ArtifactCollection {
            log_directory: json!({"configured": false}),
            families: ARTIFACT_FAMILIES
                .iter()
                .map(|spec| missing_artifact(spec, "logDirectoryNotConfigured"))
                .collect(),
            file_count: 0,
            missing_families: ARTIFACT_FAMILIES
                .iter()
                .map(|spec| spec.family.to_string())
                .collect(),
            issue_count: ARTIFACT_FAMILIES.len() as u64,
            directory_scan_truncated: false,
        };
    };

    let log_directory = json!({
        "configured": true,
        "path": log_dir.to_string_lossy(),
    });
    let entries = match fs::read_dir(&log_dir) {
        Ok(entries) => entries,
        Err(error) => {
            let reason = format!("directoryReadFailed:{}", error.kind());
            return ArtifactCollection {
                log_directory,
                families: ARTIFACT_FAMILIES
                    .iter()
                    .map(|spec| missing_artifact(spec, &reason))
                    .collect(),
                file_count: 0,
                missing_families: ARTIFACT_FAMILIES
                    .iter()
                    .map(|spec| spec.family.to_string())
                    .collect(),
                issue_count: ARTIFACT_FAMILIES.len() as u64,
                directory_scan_truncated: false,
            };
        }
    };

    let mut candidates = Vec::new();
    let mut directory_scan_truncated = false;
    for (index, entry) in entries.enumerate() {
        if index == MAX_DIRECTORY_ENTRIES {
            directory_scan_truncated = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        candidates.push(ArtifactCandidate {
            file_name,
            path: entry.path(),
            modified,
        });
    }

    let mut families = Vec::with_capacity(ARTIFACT_FAMILIES.len());
    let mut missing_families = Vec::new();
    let mut file_count = 0_u64;
    let mut issue_count = u64::from(directory_scan_truncated);
    for spec in ARTIFACT_FAMILIES {
        if spec.family == "unifiedEvents" {
            let Some(selection) = unified_run else {
                missing_families.push(spec.family.to_string());
                issue_count += 1;
                families.push(missing_artifact(spec, "activeRunNotInitialized"));
                continue;
            };
            let run_prefix = format!(
                "{}{}-{}-",
                spec.file_prefix, selection.process_id, selection.run_id
            );
            let mut run_candidates = candidates
                .iter()
                .filter(|candidate| {
                    candidate.file_name.starts_with(&run_prefix)
                        && candidate.file_name.ends_with(".jsonl")
                })
                .collect::<Vec<_>>();
            run_candidates.sort_by_key(|candidate| {
                candidate
                    .file_name
                    .strip_prefix(&run_prefix)
                    .and_then(|tail| tail.strip_suffix(".jsonl"))
                    .and_then(|tail| tail.parse::<u64>().ok())
                    .unwrap_or(u64::MAX)
            });
            if !run_candidates
                .iter()
                .any(|candidate| candidate.file_name == selection.active_file_name)
            {
                missing_families.push(spec.family.to_string());
                issue_count += 1;
                families.push(missing_artifact(spec, "activeSegmentNotFound"));
                continue;
            }
            match summarize_artifacts(spec, &run_candidates, Some(selection)) {
                Ok((summary, issues)) => {
                    file_count += run_candidates.len() as u64;
                    issue_count += issues;
                    families.push(summary);
                }
                Err(error) => {
                    missing_families.push(spec.family.to_string());
                    issue_count += 1;
                    families.push(json!({
                        "family": spec.family,
                        "expectedSchema": spec.expected_schema,
                        "present": false,
                        "activeFileName": selection.active_file_name,
                        "missingReason": format!("artifactReadFailed:{}", error.kind()),
                    }));
                }
            }
            continue;
        }
        let candidate = candidates
            .iter()
            .filter(|candidate| {
                candidate.file_name.starts_with(spec.file_prefix)
                    && candidate.file_name.ends_with(".jsonl")
            })
            .max_by(|left, right| {
                left.modified
                    .cmp(&right.modified)
                    .then_with(|| left.file_name.cmp(&right.file_name))
            });
        let Some(candidate) = candidate else {
            missing_families.push(spec.family.to_string());
            issue_count += 1;
            families.push(missing_artifact(spec, "matchingArtifactNotFound"));
            continue;
        };
        match summarize_artifacts(spec, &[candidate], None) {
            Ok((summary, issues)) => {
                file_count += 1;
                issue_count += issues;
                families.push(summary);
            }
            Err(error) => {
                missing_families.push(spec.family.to_string());
                issue_count += 1;
                families.push(json!({
                    "family": spec.family,
                    "expectedSchema": spec.expected_schema,
                    "present": false,
                    "fileName": candidate.file_name,
                    "missingReason": format!("artifactReadFailed:{}", error.kind()),
                }));
            }
        }
    }

    ArtifactCollection {
        log_directory,
        families,
        file_count,
        missing_families,
        issue_count,
        directory_scan_truncated,
    }
}

fn missing_artifact(spec: &ArtifactFamilySpec, reason: &str) -> Value {
    json!({
        "family": spec.family,
        "expectedSchema": spec.expected_schema,
        "present": false,
        "missingReason": reason,
    })
}

fn summarize_artifacts(
    spec: &ArtifactFamilySpec,
    candidates: &[&ArtifactCandidate],
    unified_run: Option<&UnifiedRunSelection>,
) -> std::io::Result<(Value, u64)> {
    let mut remaining_bytes = MAX_TAIL_BYTES;
    let mut tails = Vec::new();
    for candidate in candidates.iter().rev() {
        if remaining_bytes == 0 {
            break;
        }
        let ignore_incomplete_final_line = unified_run
            .is_some_and(|selection| selection.active_file_name == candidate.file_name)
            || (unified_run.is_none() && candidates.len() == 1);
        let tail = read_artifact_tail(candidate, remaining_bytes, ignore_incomplete_final_line)?;
        remaining_bytes = remaining_bytes.saturating_sub(tail.bytes_read as u64);
        tails.push(tail);
    }
    tails.reverse();

    let lines = tails
        .iter()
        .flat_map(|tail| tail.lines.iter())
        .collect::<Vec<_>>();
    let records_omitted_before_limit = lines.len().saturating_sub(MAX_TAIL_RECORDS);
    let selected = &lines[records_omitted_before_limit..];
    let mut records = Vec::with_capacity(selected.len());
    let mut sequences = Vec::new();
    let mut parse_error_count = 0_u64;
    let mut unknown_schema_count = 0_u64;
    for line in selected {
        match serde_json::from_slice::<Value>(line) {
            Ok(record) => {
                if record.get("schema").and_then(Value::as_str) != Some(spec.expected_schema) {
                    unknown_schema_count += 1;
                }
                if let Some(sequence) = record.get(spec.sequence_field).and_then(Value::as_u64) {
                    sequences.push(sequence);
                }
                records.push(record);
            }
            Err(_) => {
                parse_error_count += 1;
                records.push(json!({
                    "parseError": true,
                    "lineByteCount": line.len(),
                    "lineHex": encode_hex(line),
                }));
            }
        }
    }
    let sequence = sequence_summary(&sequences, spec.sequence_field, spec.sequence_assessment);
    let sequence_issue_count = sequence["duplicateCount"].as_u64().unwrap_or(0)
        + sequence["decreaseCount"].as_u64().unwrap_or(0)
        + sequence["gapCount"].as_u64().unwrap_or(0);
    let issue_count = parse_error_count + unknown_schema_count + sequence_issue_count;
    let active_file_name = unified_run
        .map(|selection| selection.active_file_name.as_str())
        .or_else(|| {
            candidates
                .last()
                .map(|candidate| candidate.file_name.as_str())
        });
    let mut summary = json!({
        "family": spec.family,
        "expectedSchema": spec.expected_schema,
        "present": true,
        "fileName": active_file_name,
        "fileNames": tails.iter().map(|tail| tail.file_name.as_str()).collect::<Vec<_>>(),
        "fileSizeBytes": tails.iter().map(|tail| tail.file_size).sum::<u64>(),
        "segmentFilesAvailable": candidates.len(),
        "segmentFilesIncluded": tails.len(),
        "segmentsOmittedBeforeTail": candidates.len().saturating_sub(tails.len()),
        "truncatedBeforeTail": tails.len() < candidates.len()
            || tails.iter().any(|tail| tail.tail_start_offset > 0),
        "bytesRead": tails.iter().map(|tail| tail.bytes_read).sum::<usize>(),
        "tailLineCount": lines.len(),
        "incompleteFinalLineIgnoredCount": tails
            .iter()
            .filter(|tail| tail.incomplete_final_line_ignored)
            .count(),
        "recordsIncluded": records.len(),
        "recordsOmittedBeforeLimit": records_omitted_before_limit,
        "recordsOmittedForBudget": 0,
        "parseErrorCount": parse_error_count,
        "unknownSchemaCount": unknown_schema_count,
        "sequence": sequence,
        "records": records,
    });
    if let Some(selection) = unified_run {
        summary["runId"] = Value::String(selection.run_id.clone());
        summary["processId"] = Value::from(selection.process_id);
        summary["activeFileName"] = Value::String(selection.active_file_name.clone());
    }

    Ok((summary, issue_count))
}

fn encode_bounded_bundle(mut payload: Value, max_bytes: usize) -> Result<Vec<u8>> {
    const SECTIONS: &[&str] = &[
        "operationalSnapshots.searches.results",
        "operationalSnapshots.uploadQueue",
        "operationalSnapshots.uploads",
        "operationalSnapshots.transfers",
        "operationalSnapshots.sharedFiles",
        "operationalSnapshots.servers",
        "operationalSnapshots.searches",
        "recentLogs",
        "diagnosticArtifacts.records",
    ];

    let mut next_section = 0_usize;
    let mut truncated_sections = BTreeSet::new();
    loop {
        payload["budget"]["truncated"] = Value::Bool(!truncated_sections.is_empty());
        payload["budget"]["truncatedSections"] = json!(truncated_sections);
        let encoded = stabilize_encoded_size(&mut payload)?;
        if encoded.len() <= max_bytes {
            return Ok(encoded);
        }

        let mut shrunk = false;
        for offset in 0..SECTIONS.len() {
            let index = (next_section + offset) % SECTIONS.len();
            if shrink_budget_section(&mut payload, SECTIONS[index]) {
                truncated_sections.insert(SECTIONS[index].to_string());
                next_section = (index + 1) % SECTIONS.len();
                shrunk = true;
                break;
            }
        }
        if !shrunk {
            bail!(
                "mandatory diagnostic bundle core requires {} bytes, exceeding requested {max_bytes}-byte max",
                encoded.len()
            );
        }
    }
}

fn stabilize_encoded_size(payload: &mut Value) -> Result<Vec<u8>> {
    loop {
        let encoded = serde_json::to_vec(payload)?;
        let reported = payload["budget"]["encodedBytes"].as_u64().unwrap_or(0) as usize;
        if reported == encoded.len() {
            return Ok(encoded);
        }
        payload["budget"]["encodedBytes"] = Value::from(encoded.len() as u64);
    }
}

fn shrink_budget_section(payload: &mut Value, section: &str) -> bool {
    match section {
        "operationalSnapshots.searches.results" => {
            let Some(searches) =
                value_at_path_mut(payload, &["operationalSnapshots", "searches", "items"])
                    .and_then(Value::as_array_mut)
            else {
                return false;
            };
            let mut shrunk = false;
            for search in searches {
                shrunk |= shrink_collection(&mut search["results"], false);
            }
            shrunk
        }
        "operationalSnapshots.uploadQueue" => {
            shrink_path_collection(payload, &["operationalSnapshots", "uploadQueue"], false)
        }
        "operationalSnapshots.uploads" => {
            shrink_path_collection(payload, &["operationalSnapshots", "uploads"], false)
        }
        "operationalSnapshots.transfers" => {
            shrink_path_collection(payload, &["operationalSnapshots", "transfers"], true)
        }
        "operationalSnapshots.sharedFiles" => {
            shrink_path_collection(payload, &["operationalSnapshots", "sharedFiles"], false)
        }
        "operationalSnapshots.servers" => {
            shrink_path_collection(payload, &["operationalSnapshots", "servers"], false)
        }
        "operationalSnapshots.searches" => {
            shrink_path_collection(payload, &["operationalSnapshots", "searches"], true)
        }
        "recentLogs" => shrink_path_collection(payload, &["recentLogs"], true),
        "diagnosticArtifacts.records" => shrink_artifact_records(payload),
        _ => false,
    }
}

fn value_at_path_mut<'a>(value: &'a mut Value, path: &[&str]) -> Option<&'a mut Value> {
    let mut current = value;
    for component in path {
        current = current.get_mut(*component)?;
    }
    Some(current)
}

fn shrink_path_collection(payload: &mut Value, path: &[&str], keep_tail: bool) -> bool {
    value_at_path_mut(payload, path)
        .is_some_and(|collection| shrink_collection(collection, keep_tail))
}

fn shrink_collection(collection: &mut Value, keep_tail: bool) -> bool {
    let Some(items) = collection.get_mut("items").and_then(Value::as_array_mut) else {
        return false;
    };
    if items.is_empty() {
        return false;
    }
    let removed = items.len().div_ceil(2);
    if keep_tail {
        items.drain(..removed);
    } else {
        items.truncate(items.len().saturating_sub(removed));
    }
    collection["included"] = Value::from(items.len() as u64);
    let omitted = collection["omittedForBudget"].as_u64().unwrap_or(0);
    collection["omittedForBudget"] = Value::from(omitted.saturating_add(removed as u64));
    true
}

fn shrink_artifact_records(payload: &mut Value) -> bool {
    let Some(families) = value_at_path_mut(payload, &["diagnosticArtifacts", "families"])
        .and_then(Value::as_array_mut)
    else {
        return false;
    };
    let mut shrunk = false;
    for family in families {
        let Some(records) = family.get_mut("records").and_then(Value::as_array_mut) else {
            continue;
        };
        if records.is_empty() {
            continue;
        }
        let removed = records.len().div_ceil(2);
        records.drain(..removed);
        family["recordsIncluded"] = Value::from(records.len() as u64);
        let omitted = family["recordsOmittedForBudget"].as_u64().unwrap_or(0);
        family["recordsOmittedForBudget"] = Value::from(omitted.saturating_add(removed as u64));
        shrunk = true;
    }
    shrunk
}

fn read_artifact_tail(
    candidate: &ArtifactCandidate,
    max_bytes: u64,
    ignore_incomplete_final_line: bool,
) -> std::io::Result<TailRead> {
    let mut file = File::open(&candidate.path)?;
    let file_size = file.metadata()?.len();
    let bytes_to_read = file_size.min(max_bytes);
    let tail_start_offset = file_size.saturating_sub(bytes_to_read);
    file.seek(SeekFrom::Start(tail_start_offset))?;
    let mut bytes = Vec::with_capacity(bytes_to_read as usize);
    file.take(bytes_to_read).read_to_end(&mut bytes)?;
    let bytes_read = bytes.len();
    if tail_start_offset > 0 {
        if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=newline);
        } else {
            bytes.clear();
        }
    }
    let incomplete_final_line_ignored =
        ignore_incomplete_final_line && bytes.last().is_some_and(|last| *last != b'\n');
    if incomplete_final_line_ignored {
        if let Some(newline) = bytes.iter().rposition(|byte| *byte == b'\n') {
            bytes.truncate(newline + 1);
        } else {
            bytes.clear();
        }
    }
    let lines = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    Ok(TailRead {
        file_name: candidate.file_name.clone(),
        file_size,
        tail_start_offset,
        bytes_read,
        incomplete_final_line_ignored,
        lines,
    })
}

fn sequence_summary(sequences: &[u64], field: &str, assessment: &str) -> Value {
    let mut seen = HashSet::new();
    let mut duplicate_count = 0_u64;
    let mut decrease_count = 0_u64;
    let mut gap_count = 0_u64;
    for (index, sequence) in sequences.iter().enumerate() {
        if !seen.insert(*sequence) {
            duplicate_count += 1;
        }
        if let Some(previous) = index.checked_sub(1).and_then(|prior| sequences.get(prior)) {
            if sequence < previous {
                decrease_count += 1;
            } else if sequence > &previous.saturating_add(1) {
                gap_count += 1;
            }
        }
    }
    json!({
        "field": field,
        "assessment": assessment,
        "observedCount": sequences.len(),
        "first": sequences.first(),
        "last": sequences.last(),
        "duplicateCount": duplicate_count,
        "decreaseCount": decrease_count,
        "gapCount": gap_count,
    })
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_collection() -> Value {
        json!({
            "total": 0,
            "included": 0,
            "omittedAfterLimit": 0,
            "omittedForBudget": 0,
            "limit": 0,
            "items": [],
        })
    }

    fn oversized_budget_fixture() -> Value {
        let search_results = (0..64)
            .map(|index| json!({"index": index, "name": "x".repeat(4_096)}))
            .collect::<Vec<_>>();
        let recent_logs = (0..32)
            .map(|index| json!({"index": index, "message": "y".repeat(4_096)}))
            .collect::<Vec<_>>();
        json!({
            "schema": DIAGNOSTIC_BUNDLE_SCHEMA,
            "status": {},
            "settings": {},
            "recentLogs": {
                "total": recent_logs.len(),
                "included": recent_logs.len(),
                "omittedBeforeLimit": 0,
                "omittedForBudget": 0,
                "limit": recent_logs.len(),
                "items": recent_logs,
            },
            "operationalSnapshots": {
                "servers": empty_collection(),
                "sharedFiles": empty_collection(),
                "searches": {
                    "total": 1,
                    "included": 1,
                    "omittedBeforeLimit": 0,
                    "omittedForBudget": 0,
                    "limit": 1,
                    "items": [{
                        "results": {
                            "total": search_results.len(),
                            "included": search_results.len(),
                            "omittedAfterLimit": 0,
                            "omittedForBudget": 0,
                            "limit": search_results.len(),
                            "items": search_results,
                        }
                    }],
                },
                "transfers": empty_collection(),
                "uploads": empty_collection(),
                "uploadQueue": empty_collection(),
            },
            "diagnosticArtifacts": {"families": []},
            "budget": {
                "maxBytes": MIN_DIAGNOSTIC_BUNDLE_BYTES,
                "encodedBytes": 0,
                "truncated": false,
                "truncatedSections": [],
            },
        })
    }

    #[test]
    fn byte_budget_is_exact_and_reports_deterministic_omissions() {
        let encoded =
            encode_bounded_bundle(oversized_budget_fixture(), MIN_DIAGNOSTIC_BUNDLE_BYTES).unwrap();
        let bundle: Value = serde_json::from_slice(&encoded).unwrap();

        assert!(encoded.len() <= MIN_DIAGNOSTIC_BUNDLE_BYTES);
        assert_eq!(bundle["budget"]["encodedBytes"], encoded.len());
        assert_eq!(bundle["budget"]["maxBytes"], MIN_DIAGNOSTIC_BUNDLE_BYTES);
        assert_eq!(bundle["budget"]["truncated"], true);
        assert!(
            bundle["budget"]["truncatedSections"]
                .as_array()
                .unwrap()
                .iter()
                .any(|section| section == "operationalSnapshots.searches.results")
        );
    }

    #[test]
    fn collection_budget_omissions_are_counted_exactly() {
        let mut collection = json!({
            "included": 4,
            "omittedForBudget": 0,
            "items": ["zero", "one", "two", "three"],
        });

        assert!(shrink_collection(&mut collection, false));

        assert_eq!(collection["included"], 2);
        assert_eq!(collection["omittedForBudget"], 2);
        assert_eq!(collection["items"], json!(["zero", "one"]));
    }

    #[test]
    fn mandatory_core_over_budget_is_rejected_instead_of_silently_truncated() {
        let mut payload = oversized_budget_fixture();
        payload["settings"] = json!({"unboundedMandatoryValue": "z".repeat(128 * 1024)});

        let error = encode_bounded_bundle(payload, MIN_DIAGNOSTIC_BUNDLE_BYTES).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("mandatory diagnostic bundle core")
        );
    }

    #[test]
    fn malformed_lines_are_preserved_as_exact_hex() {
        assert_eq!(encode_hex(b"{not-json:\xff}"), "7b6e6f742d6a736f6e3aff7d");
    }

    #[test]
    fn bounded_operational_collections_report_exact_omissions() {
        let values = ["zero", "one", "two", "three"];

        let tail = bounded_tail_collection(&values, 2, |value| json!(value));
        let prefix = bounded_prefix_collection(&values, values.len(), 2, |value| json!(value));

        assert_eq!(tail["total"], 4);
        assert_eq!(tail["included"], 2);
        assert_eq!(tail["omittedBeforeLimit"], 2);
        assert_eq!(tail["limit"], 2);
        assert_eq!(tail["items"], json!(["two", "three"]));
        assert_eq!(prefix["total"], 4);
        assert_eq!(prefix["included"], 2);
        assert_eq!(prefix["omittedAfterLimit"], 2);
        assert_eq!(prefix["limit"], 2);
        assert_eq!(prefix["items"], json!(["zero", "one"]));
    }

    #[test]
    fn disabled_writer_adds_no_bundle_health_issue() {
        let issues = diagnostic_writer_issues(&json!({
            "diagnosticWriter": {
                "enabled": false,
            }
        }));

        assert!(issues.is_empty());
    }

    #[test]
    fn unhealthy_writer_adds_explicit_bundle_health_issues() {
        let issues = diagnostic_writer_issues(&json!({
            "diagnosticWriter": {
                "enabled": true,
                "configured": true,
                "initialized": true,
                "storageAuthorityFaulted": true,
                "writerIoFaulted": true,
                "storagePolicySatisfied": false,
                "storageBlockReason": "freeSpaceProbeFailure",
                "droppedEvents": 3,
            }
        }));
        let codes = issues
            .iter()
            .map(|issue| issue["code"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            codes,
            [
                "diagnosticWriterStorageAuthorityFaulted",
                "diagnosticWriterIoFaulted",
                "diagnosticWriterStoragePolicyUnsatisfied",
                "diagnosticWriterDroppedEvents",
            ]
        );
        assert_eq!(issues[0]["reason"], "freeSpaceProbeFailure");
        assert_eq!(issues[3]["count"], 3);
    }

    #[test]
    fn artifact_summary_is_bounded_and_reports_schema_and_sequence_issues() {
        let root = test_dir("artifact-summary");
        let root_text = root.to_string_lossy().to_string();
        let file_name = "emulebb-rust-diag-42-test-run-000003.jsonl";
        let path = root.join(file_name);
        let mut content = String::new();
        for sequence in 1..=70 {
            let schema = if sequence == 69 {
                "unexpected"
            } else {
                "diag_event_v2"
            };
            content.push_str(
                &json!({
                    "schema": schema,
                    "runId": "test-run",
                    "processId": 42,
                    "segmentId": 3,
                    "seq": match sequence {
                        69 => 72,
                        70 => 68,
                        _ => sequence,
                    },
                    "streamSeq": sequence,
                    "family": "ed2k_tcp",
                    "event": "packet",
                    "keys": {"peer": "198.51.100.2:4662"},
                })
                .to_string(),
            );
            content.push('\n');
        }
        fs::write(&path, content).unwrap();

        let selection = UnifiedRunSelection {
            run_id: "test-run".to_string(),
            process_id: 42,
            active_file_name: file_name.to_string(),
        };
        let artifacts = collect_artifacts(Some(root), Some(&selection));
        let unified = artifacts
            .families
            .iter()
            .find(|family| family["family"] == "unifiedEvents")
            .unwrap();
        assert_eq!(unified["present"], true);
        assert_eq!(unified["recordsIncluded"], MAX_TAIL_RECORDS);
        assert_eq!(unified["recordsOmittedBeforeLimit"], 6);
        assert_eq!(unified["unknownSchemaCount"], 1);
        assert_eq!(unified["sequence"]["duplicateCount"], 1);
        assert_eq!(unified["sequence"]["decreaseCount"], 1);
        assert!(unified["sequence"]["gapCount"].as_u64().unwrap() > 0);
        assert!(unified.to_string().contains("198.51.100.2"));
        assert_eq!(artifacts.log_directory["path"], root_text);
        assert!(artifacts.missing_families.is_empty());
    }

    #[test]
    fn artifact_summary_preserves_malformed_lines_losslessly() {
        let root = test_dir("malformed-artifact-line");
        let file_name = "emulebb-rust-diag-42-test-run-000000.jsonl";
        let mut content = json!({
            "schema": "diag_event_v2",
            "runId": "test-run",
            "processId": 42,
            "segmentId": 0,
            "seq": 1,
        })
        .to_string()
        .into_bytes();
        content.push(b'\n');
        content.extend_from_slice(b"{not-json:\xff}\n");
        fs::write(root.join(file_name), content).unwrap();

        let selection = UnifiedRunSelection {
            run_id: "test-run".to_string(),
            process_id: 42,
            active_file_name: file_name.to_string(),
        };
        let artifacts = collect_artifacts(Some(root), Some(&selection));
        let unified = artifacts
            .families
            .iter()
            .find(|family| family["family"] == "unifiedEvents")
            .unwrap();
        assert_eq!(unified["parseErrorCount"], 1);
        assert_eq!(unified["records"][1]["lineByteCount"], 12);
        assert_eq!(unified["records"][1]["lineHex"], "7b6e6f742d6a736f6e3aff7d");
    }

    #[test]
    fn unified_summary_uses_only_the_active_run_and_ignores_a_partial_live_line() {
        let root = test_dir("active-run-summary");
        fs::write(
            root.join("emulebb-rust-diag-7-stale-run-000000.jsonl"),
            json!({
                "schema": "diag_event_v2",
                "runId": "stale-run",
                "processId": 7,
                "segmentId": 0,
                "seq": 99,
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        fs::write(
            root.join("emulebb-rust-diag-42-active-run-000000.jsonl"),
            json!({
                "schema": "diag_event_v2",
                "runId": "active-run",
                "processId": 42,
                "segmentId": 0,
                "seq": 1,
            })
            .to_string()
                + "\n",
        )
        .unwrap();
        let active_file_name = "emulebb-rust-diag-42-active-run-000001.jsonl";
        fs::write(
            root.join(active_file_name),
            format!(
                "{}\n{{\"schema\":\"diag_event_v2\"",
                json!({
                    "schema": "diag_event_v2",
                    "runId": "active-run",
                    "processId": 42,
                    "segmentId": 1,
                    "seq": 2,
                })
            ),
        )
        .unwrap();
        let selection = UnifiedRunSelection {
            run_id: "active-run".to_string(),
            process_id: 42,
            active_file_name: active_file_name.to_string(),
        };

        let artifacts = collect_artifacts(Some(root), Some(&selection));
        let unified = artifacts
            .families
            .iter()
            .find(|family| family["family"] == "unifiedEvents")
            .unwrap();
        assert_eq!(artifacts.file_count, 2);
        assert_eq!(unified["runId"], "active-run");
        assert_eq!(unified["segmentFilesAvailable"], 2);
        assert_eq!(unified["segmentFilesIncluded"], 2);
        assert_eq!(unified["recordsIncluded"], 2);
        assert_eq!(unified["sequence"]["first"], 1);
        assert_eq!(unified["sequence"]["last"], 2);
        assert_eq!(unified["parseErrorCount"], 0);
        assert_eq!(unified["incompleteFinalLineIgnoredCount"], 1);
        assert!(!unified.to_string().contains("stale-run"));
    }

    #[test]
    fn missing_artifact_families_are_explicit_when_log_directory_is_unset() {
        let artifacts = collect_artifacts(None, None);
        assert_eq!(artifacts.file_count, 0);
        assert_eq!(artifacts.missing_families.len(), ARTIFACT_FAMILIES.len());
        assert!(
            artifacts
                .families
                .iter()
                .all(|family| family["missingReason"] == "logDirectoryNotConfigured")
        );
    }

    #[test]
    fn legacy_packet_files_are_not_bundle_artifacts() {
        let root = test_dir("legacy-packet-files-ignored");
        for file_name in [
            "emulebb-rust-ed2k-tcp-dump-old.jsonl",
            "emulebb-rust-ed2k-client-udp-dump-old.jsonl",
            "emulebb-rust-ed2k-server-dump-old.jsonl",
            "emulebb-rust-kad-udp-dump-old.jsonl",
        ] {
            fs::write(root.join(file_name), "{\"schema\":\"legacy\"}\n").unwrap();
        }

        let artifacts = collect_artifacts(Some(root), None);

        assert_eq!(artifacts.file_count, 0);
        assert_eq!(artifacts.families.len(), 1);
        assert_eq!(artifacts.families[0]["family"], "unifiedEvents");
        assert_eq!(artifacts.families[0]["present"], false);
        assert_eq!(artifacts.missing_families, ["unifiedEvents"]);
    }

    fn test_dir(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "emulebb-rest-{name}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
