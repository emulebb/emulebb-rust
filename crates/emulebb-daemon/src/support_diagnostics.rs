//! Share-safe summaries of retained daemon logs. Raw bundles remain private.

use std::{fs, path::Path};

use anyhow::{Result, ensure};
use chrono::{DateTime, Utc};
use emulebb_diagnostics::log_tail::read_jsonl_tail;
use serde_json::{Value, json};

const MAX_SCAN: usize = 256;
const MAX_SEGMENTS: usize = 2;
const MAX_BYTES: u64 = 256 * 1024;
const MAX_RECORDS: usize = 200;

/// Read a bounded snapshot without opening settings or metadata, mutating the
/// profile, or exposing arbitrary log strings. Safe while a writer is active.
pub fn capture(profile: &Path) -> Result<Value> {
    ensure!(profile.is_absolute(), "diagnostic profile must be absolute");
    let mut records = Vec::new();
    let mut bytes_read = 0;
    let mut segments_read = 0;
    let mut malformed_records = 0;
    let mut read_issues = 0;
    let mut truncated = false;
    let directory = profile.join("logs");
    if directory.exists() {
        let profile = profile.canonicalize()?;
        ensure!(
            !fs::symlink_metadata(&directory)?.file_type().is_symlink(),
            "diagnostic log directory must be owned"
        );
        ensure!(
            directory.canonicalize()?.starts_with(&profile),
            "diagnostic logs escaped the profile"
        );
        let mut candidates = Vec::new();
        for (index, entry) in fs::read_dir(&directory)?.enumerate() {
            if index >= MAX_SCAN {
                truncated = true;
                break;
            }
            let Ok(entry) = entry else {
                read_issues += 1;
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("emulebb-rust.") || !name.ends_with(".jsonl") {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                read_issues += 1;
                continue;
            };
            if !kind.is_file() {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                read_issues += 1;
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                read_issues += 1;
                continue;
            };
            candidates.push((modified, entry.path()));
        }
        candidates.sort();
        truncated |= candidates.len() > MAX_SEGMENTS;
        let mut tails = Vec::new();
        for (_, path) in candidates.into_iter().rev().take(MAX_SEGMENTS) {
            let remaining = MAX_BYTES.saturating_sub(bytes_read);
            if remaining == 0 {
                truncated = true;
                break;
            }
            match read_jsonl_tail(&path, remaining, true) {
                Ok(tail) => {
                    bytes_read += tail.bytes_read as u64;
                    segments_read += 1;
                    truncated |= tail.tail_start_offset > 0 || tail.incomplete_final_line_ignored;
                    tails.push(tail);
                }
                Err(_) => read_issues += 1,
            }
        }
        for line in tails.into_iter().rev().flat_map(|tail| tail.lines) {
            let parsed = serde_json::from_slice::<Value>(&line).ok();
            match parsed.as_ref().and_then(project_record) {
                Some(record) => records.push(record),
                None => malformed_records += 1,
            }
        }
    }
    if records.len() > MAX_RECORDS {
        truncated = true;
        records.drain(..records.len() - MAX_RECORDS);
    }
    Ok(json!({
        "schema": "emulebb.support-diagnostics/1", "capturedAt": Utc::now(),
        "build": {"version": crate::BUILD_VERSION, "channel": crate::BUILD_CHANNEL, "sourceRevision": crate::BUILD_SOURCE_REVISION},
        "included": "Bounded timestamp, severity, component, safe event category and OS error summaries only",
        "excluded": ["credentials", "configuration", "paths", "peer identifiers", "content identifiers", "free-form messages"],
        "limits": {"maxReadBytes": MAX_BYTES, "maxSegments": MAX_SEGMENTS, "maxRecords": MAX_RECORDS},
        "snapshot": {"bytesRead": bytes_read, "segmentsRead": segments_read, "truncated": truncated, "malformedRecordsOmitted": malformed_records, "readIssues": read_issues},
        "recentLogs": records,
    }))
}

fn project_record(record: &Value) -> Option<Value> {
    let timestamp = DateTime::parse_from_rfc3339(record.get("timestamp")?.as_str()?).ok()?;
    let level = match record.get("level")?.as_str()? {
        "ERROR" => "ERROR",
        "WARN" => "WARN",
        "INFO" => "INFO",
        "DEBUG" => "DEBUG",
        "TRACE" => "TRACE",
        _ => return None,
    };
    let component = match record
        .get("target")
        .and_then(Value::as_str)
        .and_then(|target| target.split("::").next())
    {
        Some("emulebb_daemon") => "daemon",
        Some("emulebb_core") => "core",
        Some("emulebb_ed2k") => "ed2k",
        Some("emulebb_rest") => "rest",
        Some("emulebb_metadata") => "metadata",
        Some("emulebb_kad_dht") => "kad",
        _ => "dependency",
    };
    let fields = record.get("fields")?;
    // WHY: arbitrary strings can contain filenames, endpoints and credentials.
    // Emit closed categories, never copied message/error/span/config values.
    let event = match fields.get("message").and_then(Value::as_str) {
        Some("starting emulebb-rust") => "daemon_starting",
        Some("persistent logging is unavailable; continuing with console and REST logging") => {
            "persistent_logging_unavailable"
        }
        Some("automatic Kad startup failed; REST start remains available") => "kad_start_failed",
        Some("automatic ED2K/Kad startup failed; REST connect remains available") => {
            "peer_connect_failed"
        }
        Some("initial shared-directory scan failed; continuing") => "sharing_scan_failed",
        Some("empty server list remains available for manual WebUI import") => {
            "discovery_servers_unavailable"
        }
        _ => "free_form_details_omitted",
    };
    let os_error = fields
        .get("error")
        .and_then(Value::as_str)
        .and_then(|error| error.rsplit_once("(os error ").map(|(_, suffix)| suffix))
        .and_then(|suffix| suffix.strip_suffix(')'))
        .and_then(|code| code.parse::<i32>().ok())
        .filter(|code| (1..=65535).contains(code));
    Some(
        json!({"timestamp": timestamp.to_rfc3339(), "level": level, "component": component,
            "eventCode": event, "errorPresent": fields.get("error").is_some(),
            "osError": os_error.map(|code| json!({"code": code, "kind": format!("{:?}", std::io::Error::from_raw_os_error(code).kind())})),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_omits_credentials_config_paths_and_peer_content_from_all_fields() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("logs")).unwrap();
        let secret = "0123456789abcdef0123456789abcdef";
        let record = json!({"timestamp":"2026-11-13T12:00:00Z", "level":"ERROR", "target":"emulebb_daemon::private_module",
            "fields":{"message":format!("{secret} /private/profile Sample.bin 192.0.2.1"), "error":"/private/profile: denied (os error 13)", "api_key":secret},
            "span":{"file":"Sample.bin", "peer":"192.0.2.1"}});
        fs::write(
            root.path().join("logs/emulebb-rust.2026-11-13.jsonl"),
            format!("{record}\n{{unfinished"),
        )
        .unwrap();
        fs::write(
            root.path().join("emulebb-rust-settings.toml"),
            format!("api_key = '{secret}'"),
        )
        .unwrap();
        let report = capture(root.path()).unwrap();
        let encoded = serde_json::to_string(&report).unwrap();
        for private in [
            secret,
            "/private/profile",
            "Sample.bin",
            "192.0.2.1",
            "private_module",
        ] {
            assert!(!encoded.contains(private));
        }
        assert_eq!(report["recentLogs"][0]["level"], "ERROR");
        assert_eq!(report["recentLogs"][0]["osError"]["code"], 13);
        assert_eq!(report["snapshot"]["truncated"], true);
    }

    #[test]
    fn sharing_a_missing_profile_creates_nothing_and_bounds_recent_records() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("absent");
        assert_eq!(capture(&missing).unwrap()["recentLogs"], json!([]));
        assert!(!missing.exists());
        fs::create_dir(root.path().join("logs")).unwrap();
        let line = "{\"timestamp\":\"2026-11-13T12:00:00Z\",\"level\":\"INFO\",\"target\":\"emulebb_daemon\",\"fields\":{\"message\":\"starting emulebb-rust\"}}\n";
        fs::write(
            root.path().join("logs/emulebb-rust.2026-11-13.jsonl"),
            line.repeat(300),
        )
        .unwrap();
        let report = capture(root.path()).unwrap();
        assert_eq!(report["recentLogs"].as_array().unwrap().len(), MAX_RECORDS);
        assert!(report["snapshot"]["bytesRead"].as_u64().unwrap() <= MAX_BYTES);
        assert_eq!(report["recentLogs"][0]["eventCode"], "daemon_starting");
    }
}
