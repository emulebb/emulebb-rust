//! Shared, bounded JSONL diagnostics for the Rust client.
//!
//! The writer is compile-time gated by the `enabled` feature and runtime-gated
//! by `EMULEBB_RUST_LOG_DIR`. Every producer in one process calls this crate so
//! file order, process sequence numbers, stream sequence numbers, rotation,
//! retention, and writer health share one authority.

#[cfg(any(feature = "enabled", test))]
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
#[cfg(feature = "enabled")]
use std::{
    env,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

#[cfg(any(feature = "enabled", test))]
use chrono::SecondsFormat;
use serde::Serialize;
use serde_json::Value;
#[cfg(any(feature = "enabled", test))]
use tracing::warn;
#[cfg(feature = "enabled")]
use uuid::Uuid;

pub const DIAG_EVENT_SCHEMA: &str = "diag_event_v2";
pub const DIAG_EVENT_FILE_PREFIX: &str = "emulebb-rust-diag-";

#[cfg(feature = "enabled")]
const LOG_DIR_ENV: &str = "EMULEBB_RUST_LOG_DIR";
#[cfg(feature = "enabled")]
const SEGMENT_BYTES_ENV: &str = "EMULEBB_RUST_DIAG_SEGMENT_BYTES";
#[cfg(feature = "enabled")]
const SEGMENT_SECONDS_ENV: &str = "EMULEBB_RUST_DIAG_SEGMENT_SECONDS";
#[cfg(feature = "enabled")]
const RETAINED_SEGMENTS_ENV: &str = "EMULEBB_RUST_DIAG_RETAINED_SEGMENTS";
#[cfg(feature = "enabled")]
const DEFAULT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "enabled")]
const DEFAULT_SEGMENT_SECONDS: u64 = 60 * 60;
#[cfg(feature = "enabled")]
const DEFAULT_RETAINED_SEGMENTS: usize = 8;
#[cfg(feature = "enabled")]
const MIN_SEGMENT_BYTES: u64 = 1024 * 1024;
#[cfg(feature = "enabled")]
const MAX_SEGMENT_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(feature = "enabled")]
const MIN_SEGMENT_SECONDS: u64 = 60;
#[cfg(feature = "enabled")]
const MAX_SEGMENT_SECONDS: u64 = 24 * 60 * 60;
#[cfg(feature = "enabled")]
const MIN_RETAINED_SEGMENTS: usize = 2;
#[cfg(feature = "enabled")]
const MAX_RETAINED_SEGMENTS: usize = 128;

#[cfg(feature = "enabled")]
static WRITER: OnceLock<Result<Mutex<SegmentedEventWriter>, WriterInitFailure>> = OnceLock::new();

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagWriterHealth {
    pub schema: &'static str,
    pub enabled: bool,
    pub configured: bool,
    pub initialized: bool,
    pub run_id: Option<String>,
    pub process_id: u32,
    pub active_segment_id: Option<u64>,
    pub active_file_name: Option<String>,
    pub active_segment_bytes: u64,
    pub records_written: u64,
    pub bytes_written: u64,
    pub dropped_events: u64,
    pub encode_errors: u64,
    pub write_errors: u64,
    pub rotations: u64,
    pub retention_deletes: u64,
    pub retention_delete_errors: u64,
    pub max_segment_bytes: Option<u64>,
    pub max_segment_seconds: Option<u64>,
    pub retained_segments: Option<usize>,
    pub initialization_failure: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg(any(feature = "enabled", test))]
struct DiagEventRecord<'a> {
    schema: &'static str,
    client: &'static str,
    ts: String,
    run_id: &'a str,
    process_id: u32,
    segment_id: u64,
    seq: u64,
    stream_seq: u64,
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: &'a Value,
    body: &'a Value,
}

#[derive(Debug, Clone)]
#[cfg(any(feature = "enabled", test))]
struct WriterConfig {
    directory: PathBuf,
    max_segment_bytes: u64,
    max_segment_age: Duration,
    retained_segments: usize,
}

#[derive(Debug)]
#[cfg(any(feature = "enabled", test))]
struct SegmentedEventWriter {
    config: WriterConfig,
    run_id: String,
    process_id: u32,
    active_segment_id: u64,
    active_path: PathBuf,
    active_file: File,
    active_segment_started: Instant,
    active_segment_bytes: u64,
    next_seq: u64,
    stream_sequences: HashMap<&'static str, u64>,
    records_written: u64,
    bytes_written: u64,
    dropped_events: u64,
    encode_errors: u64,
    write_errors: u64,
    rotations: u64,
    retention_deletes: u64,
    retention_delete_errors: u64,
}

#[derive(Debug)]
#[cfg(feature = "enabled")]
struct WriterInitFailure {
    reason: String,
    dropped_events: AtomicU64,
}

#[cfg(any(feature = "enabled", test))]
struct PendingEvent<'a> {
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: &'a Value,
    body: &'a Value,
    seq: u64,
    stream_seq: u64,
}

/// Emit one event through the process-wide writer.
///
/// Returns `false` when diagnostics are disabled, not configured, or the event
/// could not be retained. Call sites may ignore the result because writer health
/// exposes retained and dropped counts to diagnostics consumers.
#[cfg(feature = "enabled")]
pub fn emit(
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
) -> bool {
    let writer = match WRITER.get_or_init(initialize_global_writer) {
        Ok(writer) => writer,
        Err(error) => {
            error.record_drop();
            return false;
        }
    };
    let mut writer = match writer.lock() {
        Ok(writer) => writer,
        Err(poisoned) => {
            warn!("recovering poisoned shared diagnostic event writer lock");
            poisoned.into_inner()
        }
    };
    writer.emit(family, event, severity, &keys, &body)
}

#[cfg(not(feature = "enabled"))]
pub fn emit(
    _family: &'static str,
    _event: &'static str,
    _severity: &'static str,
    _keys: Value,
    _body: Value,
) -> bool {
    false
}

/// Return a bounded writer-health snapshot without creating a diagnostics file.
pub fn writer_health() -> DiagWriterHealth {
    #[cfg(not(feature = "enabled"))]
    {
        disabled_health()
    }
    #[cfg(feature = "enabled")]
    {
        let Some(writer) = WRITER.get() else {
            return uninitialized_health();
        };
        match writer {
            Ok(writer) => match writer.lock() {
                Ok(writer) => writer.health(),
                Err(poisoned) => {
                    let mut health = poisoned.into_inner().health();
                    health.initialization_failure = Some("writerLockPoisoned".to_string());
                    health
                }
            },
            Err(error) => error.health(),
        }
    }
}

#[cfg(feature = "enabled")]
impl WriterInitFailure {
    fn new(reason: String) -> Self {
        Self {
            reason,
            dropped_events: AtomicU64::new(0),
        }
    }

    fn record_drop(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    fn health(&self) -> DiagWriterHealth {
        DiagWriterHealth {
            dropped_events: self.dropped_events.load(Ordering::Relaxed),
            initialization_failure: Some(self.reason.clone()),
            ..uninitialized_health()
        }
    }
}

#[cfg(feature = "enabled")]
fn initialize_global_writer() -> Result<Mutex<SegmentedEventWriter>, WriterInitFailure> {
    let config = WriterConfig::from_environment()
        .ok_or_else(|| WriterInitFailure::new("logDirectoryNotConfigured".to_string()))?;
    let writer = SegmentedEventWriter::new(
        config,
        Uuid::new_v4().simple().to_string(),
        std::process::id(),
    )
    .map_err(|error| {
        WriterInitFailure::new(format!("writerInitializationFailed:{}", error.kind()))
    })?;
    Ok(Mutex::new(writer))
}

#[cfg(feature = "enabled")]
impl WriterConfig {
    fn from_environment() -> Option<Self> {
        let directory = env::var_os(LOG_DIR_ENV)
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())?;
        Some(Self {
            directory,
            max_segment_bytes: environment_u64(
                SEGMENT_BYTES_ENV,
                DEFAULT_SEGMENT_BYTES,
                MIN_SEGMENT_BYTES,
                MAX_SEGMENT_BYTES,
            ),
            max_segment_age: Duration::from_secs(environment_u64(
                SEGMENT_SECONDS_ENV,
                DEFAULT_SEGMENT_SECONDS,
                MIN_SEGMENT_SECONDS,
                MAX_SEGMENT_SECONDS,
            )),
            retained_segments: environment_usize(
                RETAINED_SEGMENTS_ENV,
                DEFAULT_RETAINED_SEGMENTS,
                MIN_RETAINED_SEGMENTS,
                MAX_RETAINED_SEGMENTS,
            ),
        })
    }
}

#[cfg(any(feature = "enabled", test))]
impl SegmentedEventWriter {
    fn new(config: WriterConfig, run_id: String, process_id: u32) -> io::Result<Self> {
        fs::create_dir_all(&config.directory)?;
        let active_segment_id = 0;
        let active_path = segment_path(&config.directory, process_id, &run_id, active_segment_id);
        let active_file = create_segment(&active_path)?;
        let mut writer = Self {
            config,
            run_id,
            process_id,
            active_segment_id,
            active_path,
            active_file,
            active_segment_started: Instant::now(),
            active_segment_bytes: 0,
            next_seq: 1,
            stream_sequences: HashMap::new(),
            records_written: 0,
            bytes_written: 0,
            dropped_events: 0,
            encode_errors: 0,
            write_errors: 0,
            rotations: 0,
            retention_deletes: 0,
            retention_delete_errors: 0,
        };
        writer.enforce_retention();
        Ok(writer)
    }

    fn emit(
        &mut self,
        family: &'static str,
        event: &'static str,
        severity: &'static str,
        keys: &Value,
        body: &Value,
    ) -> bool {
        let seq = self.next_seq;
        let stream_seq = self.stream_sequences.get(family).copied().unwrap_or(1);
        let pending = PendingEvent {
            family,
            event,
            severity,
            keys,
            body,
            seq,
            stream_seq,
        };
        let mut line = match self.encode_record(&pending) {
            Ok(line) => line,
            Err(()) => {
                self.encode_errors = self.encode_errors.saturating_add(1);
                self.dropped_events = self.dropped_events.saturating_add(1);
                return false;
            }
        };
        if line.len() as u64 > self.config.max_segment_bytes {
            self.dropped_events = self.dropped_events.saturating_add(1);
            return false;
        }
        if self.should_rotate(line.len() as u64) {
            if let Err(error) = self.rotate() {
                self.write_errors = self.write_errors.saturating_add(1);
                self.dropped_events = self.dropped_events.saturating_add(1);
                warn!("failed to rotate diagnostic event segment: {error}");
                return false;
            }
            line = match self.encode_record(&pending) {
                Ok(line) => line,
                Err(()) => {
                    self.encode_errors = self.encode_errors.saturating_add(1);
                    self.dropped_events = self.dropped_events.saturating_add(1);
                    return false;
                }
            };
            if line.len() as u64 > self.config.max_segment_bytes {
                self.dropped_events = self.dropped_events.saturating_add(1);
                return false;
            }
        }
        if let Err(error) = self.active_file.write_all(&line) {
            self.write_errors = self.write_errors.saturating_add(1);
            self.dropped_events = self.dropped_events.saturating_add(1);
            warn!(
                "failed to write diagnostic event segment {}: {error}",
                self.active_path.display()
            );
            return false;
        }

        self.active_segment_bytes = self.active_segment_bytes.saturating_add(line.len() as u64);
        self.records_written = self.records_written.saturating_add(1);
        self.bytes_written = self.bytes_written.saturating_add(line.len() as u64);
        self.next_seq = self.next_seq.saturating_add(1);
        self.stream_sequences
            .insert(family, stream_seq.saturating_add(1));
        true
    }

    fn encode_record(&self, pending: &PendingEvent<'_>) -> Result<Vec<u8>, ()> {
        let record = DiagEventRecord {
            schema: DIAG_EVENT_SCHEMA,
            client: "rust",
            ts: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            run_id: &self.run_id,
            process_id: self.process_id,
            segment_id: self.active_segment_id,
            seq: pending.seq,
            stream_seq: pending.stream_seq,
            family: pending.family,
            event: pending.event,
            severity: pending.severity,
            keys: pending.keys,
            body: pending.body,
        };
        let mut line = serde_json::to_vec(&record).map_err(|_| ())?;
        line.push(b'\n');
        Ok(line)
    }

    fn should_rotate(&self, next_line_bytes: u64) -> bool {
        self.records_written > 0
            && (self.active_segment_bytes.saturating_add(next_line_bytes)
                > self.config.max_segment_bytes
                || self.active_segment_started.elapsed() >= self.config.max_segment_age)
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.active_file.flush()?;
        let next_segment_id = self.active_segment_id.saturating_add(1);
        let next_path = segment_path(
            &self.config.directory,
            self.process_id,
            &self.run_id,
            next_segment_id,
        );
        let next_file = create_segment(&next_path)?;
        self.active_segment_id = next_segment_id;
        self.active_path = next_path;
        self.active_file = next_file;
        self.active_segment_started = Instant::now();
        self.active_segment_bytes = 0;
        self.rotations = self.rotations.saturating_add(1);
        self.enforce_retention();
        Ok(())
    }

    fn enforce_retention(&mut self) {
        let run_prefix = format!(
            "{DIAG_EVENT_FILE_PREFIX}{}-{}-",
            self.process_id, self.run_id
        );
        let Ok(entries) = fs::read_dir(&self.config.directory) else {
            self.retention_delete_errors = self.retention_delete_errors.saturating_add(1);
            return;
        };
        let mut prior_run_segments = Vec::new();
        let mut current_run_segments = Vec::new();
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path == self.active_path {
                continue;
            }
            let file_name = entry.file_name().to_string_lossy().into_owned();
            if !file_name.starts_with(DIAG_EVENT_FILE_PREFIX) || !file_name.ends_with(".jsonl") {
                continue;
            }
            if let Some(segment_id) = file_name
                .strip_prefix(&run_prefix)
                .and_then(|tail| tail.strip_suffix(".jsonl"))
                .and_then(|tail| tail.parse::<u64>().ok())
            {
                current_run_segments.push((segment_id, file_name, path));
            } else {
                let modified = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                prior_run_segments.push((modified, file_name, path));
            }
        }
        prior_run_segments
            .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        current_run_segments
            .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        let total_segments = prior_run_segments.len() + current_run_segments.len() + 1;
        let delete_count = total_segments.saturating_sub(self.config.retained_segments);
        let delete_paths = prior_run_segments
            .into_iter()
            .map(|(_, _, path)| path)
            .chain(current_run_segments.into_iter().map(|(_, _, path)| path))
            .take(delete_count);
        for path in delete_paths {
            match fs::remove_file(path) {
                Ok(()) => {
                    self.retention_deletes = self.retention_deletes.saturating_add(1);
                }
                Err(_) => {
                    self.retention_delete_errors = self.retention_delete_errors.saturating_add(1);
                }
            }
        }
    }

    fn health(&self) -> DiagWriterHealth {
        DiagWriterHealth {
            schema: DIAG_EVENT_SCHEMA,
            enabled: true,
            configured: true,
            initialized: true,
            run_id: Some(self.run_id.clone()),
            process_id: self.process_id,
            active_segment_id: Some(self.active_segment_id),
            active_file_name: self
                .active_path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
            active_segment_bytes: self.active_segment_bytes,
            records_written: self.records_written,
            bytes_written: self.bytes_written,
            dropped_events: self.dropped_events,
            encode_errors: self.encode_errors,
            write_errors: self.write_errors,
            rotations: self.rotations,
            retention_deletes: self.retention_deletes,
            retention_delete_errors: self.retention_delete_errors,
            max_segment_bytes: Some(self.config.max_segment_bytes),
            max_segment_seconds: Some(self.config.max_segment_age.as_secs()),
            retained_segments: Some(self.config.retained_segments),
            initialization_failure: None,
        }
    }
}

#[cfg(any(feature = "enabled", test))]
fn segment_path(directory: &Path, process_id: u32, run_id: &str, segment_id: u64) -> PathBuf {
    directory.join(format!(
        "{DIAG_EVENT_FILE_PREFIX}{process_id}-{run_id}-{segment_id:06}.jsonl"
    ))
}

#[cfg(any(feature = "enabled", test))]
fn create_segment(path: &Path) -> io::Result<File> {
    OpenOptions::new().create_new(true).append(true).open(path)
}

#[cfg(feature = "enabled")]
fn environment_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
    let Some(raw) = env::var_os(name) else {
        return default;
    };
    let Ok(value) = raw.to_string_lossy().trim().parse::<u64>() else {
        warn!("ignoring invalid {name}; using {default}");
        return default;
    };
    if !(minimum..=maximum).contains(&value) {
        warn!("ignoring out-of-range {name}; using {default}");
        return default;
    }
    value
}

#[cfg(feature = "enabled")]
fn environment_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let Some(raw) = env::var_os(name) else {
        return default;
    };
    let Ok(value) = raw.to_string_lossy().trim().parse::<usize>() else {
        warn!("ignoring invalid {name}; using {default}");
        return default;
    };
    if !(minimum..=maximum).contains(&value) {
        warn!("ignoring out-of-range {name}; using {default}");
        return default;
    }
    value
}

fn disabled_health() -> DiagWriterHealth {
    DiagWriterHealth {
        schema: DIAG_EVENT_SCHEMA,
        enabled: false,
        configured: false,
        initialized: false,
        run_id: None,
        process_id: std::process::id(),
        active_segment_id: None,
        active_file_name: None,
        active_segment_bytes: 0,
        records_written: 0,
        bytes_written: 0,
        dropped_events: 0,
        encode_errors: 0,
        write_errors: 0,
        rotations: 0,
        retention_deletes: 0,
        retention_delete_errors: 0,
        max_segment_bytes: None,
        max_segment_seconds: None,
        retained_segments: None,
        initialization_failure: None,
    }
}

#[cfg(feature = "enabled")]
fn uninitialized_health() -> DiagWriterHealth {
    let config = WriterConfig::from_environment();
    DiagWriterHealth {
        enabled: true,
        configured: config.is_some(),
        max_segment_bytes: config.as_ref().map(|config| config.max_segment_bytes),
        max_segment_seconds: config
            .as_ref()
            .map(|config| config.max_segment_age.as_secs()),
        retained_segments: config.as_ref().map(|config| config.retained_segments),
        ..disabled_health()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        thread,
    };

    use serde_json::json;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn event_v2_records_process_run_segment_and_stream_identity() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 4096, Duration::from_secs(60), 4);

        assert!(writer.emit("ed2k_tcp", "packet", "info", &json!({}), &json!({})));
        assert!(writer.emit("kad_udp", "packet", "info", &json!({}), &json!({})));
        assert!(writer.emit("ed2k_tcp", "packet", "info", &json!({}), &json!({})));

        let records = read_records(root.path());
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["schema"], DIAG_EVENT_SCHEMA);
        assert_eq!(records[0]["runId"], "testrun");
        assert_eq!(records[0]["processId"], 42);
        assert_eq!(records[0]["segmentId"], 0);
        assert_eq!(records[0]["seq"], 1);
        assert_eq!(records[1]["seq"], 2);
        assert_eq!(records[2]["seq"], 3);
        assert_eq!(records[0]["streamSeq"], 1);
        assert_eq!(records[1]["streamSeq"], 1);
        assert_eq!(records[2]["streamSeq"], 2);
    }

    #[test]
    fn concurrent_emits_remain_strictly_process_monotonic() {
        let root = TempDir::new().unwrap();
        let writer = Arc::new(Mutex::new(test_writer(
            &root,
            1024 * 1024,
            Duration::from_secs(60),
            4,
        )));
        let mut workers = Vec::new();
        for worker_id in 0..8_u64 {
            let writer = Arc::clone(&writer);
            workers.push(thread::spawn(move || {
                for record_id in 0..500_u64 {
                    assert!(writer.lock().unwrap().emit(
                        "sched",
                        "stress",
                        "info",
                        &json!({"worker": worker_id, "record": record_id}),
                        &json!({}),
                    ));
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        let records = read_records(root.path());
        assert_eq!(records.len(), 4_000);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record["seq"], (index + 1) as u64);
            assert_eq!(record["streamSeq"], (index + 1) as u64);
        }
    }

    #[test]
    fn size_rotation_retains_only_the_configured_run_segments() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 420, Duration::from_secs(60), 3);
        for record_id in 0..40_u64 {
            assert!(writer.emit(
                "sched",
                "rotate",
                "info",
                &json!({"record": record_id}),
                &json!({"padding": "x".repeat(80)}),
            ));
        }

        let health = writer.health();
        assert_eq!(health.records_written, 40);
        assert!(health.rotations >= 10);
        assert!(health.retention_deletes >= 7);
        assert!(segment_files(root.path()).len() <= 3);
        let records = read_records(root.path());
        assert!(records.first().unwrap()["seq"].as_u64().unwrap() > 1);
        assert_eq!(records.last().unwrap()["seq"], 40);
    }

    #[test]
    fn size_rotation_keeps_an_exact_boundary_record_in_the_current_segment() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 4096, Duration::from_secs(60), 4);
        let keys = json!({"record": 1});
        let body = json!({"padding": "stable"});
        let pending = PendingEvent {
            family: "sched",
            event: "boundary",
            severity: "info",
            keys: &keys,
            body: &body,
            seq: 1,
            stream_seq: 1,
        };
        writer.config.max_segment_bytes = writer.encode_record(&pending).unwrap().len() as u64;

        assert!(writer.emit("sched", "boundary", "info", &keys, &body));
        assert_eq!(writer.active_segment_id, 0);
        assert_eq!(writer.active_segment_bytes, writer.config.max_segment_bytes);

        assert!(writer.emit("sched", "boundary", "info", &keys, &body));
        assert_eq!(writer.active_segment_id, 1);
        assert_eq!(writer.rotations, 1);
        let records = read_records(root.path());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["segmentId"], 0);
        assert_eq!(records[1]["segmentId"], 1);
        assert_eq!(records[0]["seq"], 1);
        assert_eq!(records[1]["seq"], 2);
    }

    #[test]
    fn retention_bounds_segments_across_runs_and_preserves_the_active_segment() {
        let root = TempDir::new().unwrap();
        {
            let mut writer = test_writer_for_run(&root, "run-a", 420, 2);
            for record_id in 0..20_u64 {
                assert!(writer.emit(
                    "sched",
                    "rotate",
                    "info",
                    &json!({"record": record_id}),
                    &json!({"padding": "x".repeat(80)}),
                ));
            }
            assert_eq!(segment_files_for_run(root.path(), "run-a").len(), 2);
        }

        let mut writer = test_writer_for_run(&root, "run-b", 420, 2);
        for record_id in 0..20_u64 {
            assert!(writer.emit(
                "sched",
                "rotate",
                "info",
                &json!({"record": record_id}),
                &json!({"padding": "x".repeat(80)}),
            ));
        }

        assert!(segment_files_for_run(root.path(), "run-a").is_empty());
        assert_eq!(segment_files_for_run(root.path(), "run-b").len(), 2);
        assert_eq!(segment_files(root.path()).len(), 2);
        assert!(writer.active_path.exists());
        assert!(writer.health().retention_deletes >= 2);
    }

    #[test]
    fn rollover_revalidates_size_after_segment_id_growth() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 4096, Duration::from_secs(60), 4);
        writer.active_segment_id = 999_999;
        writer.active_segment_bytes = 1;
        writer.records_written = 1;
        let keys = json!({});
        let body = json!({"padding": "stable"});
        let pending = PendingEvent {
            family: "sched",
            event: "segment_width",
            severity: "info",
            keys: &keys,
            body: &body,
            seq: writer.next_seq,
            stream_seq: 1,
        };
        writer.config.max_segment_bytes = writer.encode_record(&pending).unwrap().len() as u64;

        assert!(!writer.emit("sched", "segment_width", "info", &keys, &body));
        assert_eq!(writer.active_segment_id, 1_000_000);
        assert_eq!(writer.active_segment_bytes, 0);
        assert_eq!(writer.dropped_events, 1);
    }

    #[test]
    fn oversized_records_are_dropped_and_counted() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 128, Duration::from_secs(60), 2);

        assert!(!writer.emit(
            "sched",
            "oversized",
            "info",
            &json!({}),
            &json!({"padding": "x".repeat(512)}),
        ));
        let health = writer.health();
        assert_eq!(health.records_written, 0);
        assert_eq!(health.dropped_events, 1);
        assert!(read_records(root.path()).is_empty());
    }

    #[cfg(feature = "enabled")]
    #[test]
    fn initialization_failures_count_every_dropped_event() {
        let failure = WriterInitFailure::new("testFailure".to_string());
        failure.record_drop();
        failure.record_drop();

        let health = failure.health();
        assert!(health.enabled);
        assert!(!health.initialized);
        assert_eq!(health.dropped_events, 2);
        assert_eq!(
            health.initialization_failure.as_deref(),
            Some("testFailure")
        );
    }

    fn test_writer(
        root: &TempDir,
        max_segment_bytes: u64,
        max_segment_age: Duration,
        retained_segments: usize,
    ) -> SegmentedEventWriter {
        test_writer_for_run_with_age(
            root,
            "testrun",
            max_segment_bytes,
            max_segment_age,
            retained_segments,
        )
    }

    fn test_writer_for_run(
        root: &TempDir,
        run_id: &str,
        max_segment_bytes: u64,
        retained_segments: usize,
    ) -> SegmentedEventWriter {
        test_writer_for_run_with_age(
            root,
            run_id,
            max_segment_bytes,
            Duration::from_secs(60),
            retained_segments,
        )
    }

    fn test_writer_for_run_with_age(
        root: &TempDir,
        run_id: &str,
        max_segment_bytes: u64,
        max_segment_age: Duration,
        retained_segments: usize,
    ) -> SegmentedEventWriter {
        SegmentedEventWriter::new(
            WriterConfig {
                directory: root.path().to_path_buf(),
                max_segment_bytes,
                max_segment_age,
                retained_segments,
            },
            run_id.to_string(),
            42,
        )
        .unwrap()
    }

    fn segment_files_for_run(root: &Path, run_id: &str) -> Vec<PathBuf> {
        segment_files(root)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains(&format!("-{run_id}-")))
            })
            .collect()
    }

    fn segment_files(root: &Path) -> Vec<PathBuf> {
        let mut paths = fs::read_dir(root)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "jsonl")
            })
            .collect::<Vec<_>>();
        paths.sort();
        paths
    }

    fn read_records(root: &Path) -> Vec<Value> {
        segment_files(root)
            .into_iter()
            .flat_map(|path| {
                fs::read(path)
                    .unwrap()
                    .split(|byte| *byte == b'\n')
                    .filter(|line| !line.is_empty())
                    .map(|line| serde_json::from_slice::<Value>(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
