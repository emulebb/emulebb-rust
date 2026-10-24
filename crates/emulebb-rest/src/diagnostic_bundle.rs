use std::{
    collections::HashSet,
    fmt::Write as _,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    time::SystemTime,
};

use anyhow::Result;
use chrono::Utc;
use serde_json::{Value, json};

use crate::{
    RestState,
    handlers::logs::recent_log_values,
    responses::{app_info_response, runtime_diagnostics_response, status_response},
};

pub(crate) const DIAGNOSTIC_BUNDLE_SCHEMA: &str = "emulebb.diagnostic-bundle.v3";

const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_LOG_RECORDS: usize = 200;
const MAX_TAIL_BYTES: u64 = 256 * 1024;
const MAX_TAIL_RECORDS: usize = 64;

const ARTIFACT_FAMILIES: &[ArtifactFamilySpec] = &[ArtifactFamilySpec {
    family: "unifiedEvents",
    file_prefix: "emulebb-rust-diag-",
    expected_schema: "diag_event_v2",
    sequence_field: "seq",
    sequence_assessment: "processWideMonotonicTail",
}];

#[derive(Debug)]
pub(crate) struct DiagnosticBundleCapture {
    pub payload: Value,
    pub artifact_file_count: u64,
    pub missing_artifact_families: Vec<String>,
    pub issue_count: u64,
}

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

pub(crate) async fn capture(state: &RestState) -> Result<DiagnosticBundleCapture> {
    let status = status_response(state).await;
    let runtime_diagnostics = runtime_diagnostics_response(state).await;
    let unified_run = unified_run_selection(&runtime_diagnostics);
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

    let payload = json!({
        "schema": DIAGNOSTIC_BUNDLE_SCHEMA,
        "capturedAt": Utc::now(),
        "app": app_info_response(state.core.app_info()),
        "status": status,
        "runtimeDiagnostics": runtime_diagnostics,
        "settings": settings,
        "settingsProvenance": {
            "source": "profileState",
            "apiKeyIncluded": true,
            "sensitiveValues": "exact",
            "apiKey": state.api_key.as_str(),
        },
        "recentLogs": logs,
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
        },
    });

    Ok(DiagnosticBundleCapture {
        payload,
        artifact_file_count: artifacts.file_count,
        missing_artifact_families: artifacts.missing_families,
        issue_count: artifacts.issue_count,
    })
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

    #[test]
    fn malformed_lines_are_preserved_as_exact_hex() {
        assert_eq!(encode_hex(b"{not-json:\xff}"), "7b6e6f742d6a736f6e3aff7d");
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
