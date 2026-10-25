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

#[cfg(any(feature = "enabled", test))]
mod retention;

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
const MAX_TOTAL_BYTES_ENV: &str = "EMULEBB_RUST_DIAG_MAX_TOTAL_BYTES";
#[cfg(feature = "enabled")]
const MAX_RETAINED_SECONDS_ENV: &str = "EMULEBB_RUST_DIAG_MAX_RETAINED_SECONDS";
#[cfg(feature = "enabled")]
const MINIMUM_FREE_BYTES_ENV: &str = "EMULEBB_RUST_DIAG_MIN_FREE_BYTES";
#[cfg(feature = "enabled")]
const DEFAULT_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "enabled")]
const DEFAULT_SEGMENT_SECONDS: u64 = 60 * 60;
#[cfg(feature = "enabled")]
const DEFAULT_RETAINED_SEGMENTS: usize = 8;
#[cfg(feature = "enabled")]
const DEFAULT_MAX_TOTAL_BYTES: u64 = DEFAULT_SEGMENT_BYTES * DEFAULT_RETAINED_SEGMENTS as u64;
#[cfg(feature = "enabled")]
const DEFAULT_MAX_RETAINED_SECONDS: u64 =
    DEFAULT_SEGMENT_SECONDS * DEFAULT_RETAINED_SEGMENTS as u64;
#[cfg(feature = "enabled")]
const DEFAULT_MINIMUM_FREE_BYTES: u64 = 0;
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
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
#[cfg(feature = "enabled")]
const MIN_RETAINED_SECONDS: u64 = 60;
#[cfg(feature = "enabled")]
const MAX_RETAINED_SECONDS: u64 = 365 * 24 * 60 * 60;
#[cfg(feature = "enabled")]
const MAX_MINIMUM_FREE_BYTES: u64 = MAX_TOTAL_BYTES;

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
    pub retention_scan_errors: u64,
    pub free_space_probe_errors: u64,
    pub retention_policy_errors: u64,
    pub storage_policy_drops: u64,
    pub retained_segment_count: usize,
    pub retained_bytes: u64,
    pub available_bytes: Option<u64>,
    pub storage_policy_satisfied: Option<bool>,
    pub maximum_growth_bytes: Option<u64>,
    pub max_segment_bytes: Option<u64>,
    pub max_segment_seconds: Option<u64>,
    pub retained_segments: Option<usize>,
    pub max_total_bytes: Option<u64>,
    pub max_retained_seconds: Option<u64>,
    pub minimum_free_bytes: Option<u64>,
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
    max_total_bytes: u64,
    max_retained_age: Duration,
    minimum_free_bytes: u64,
}

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
    retention_scan_errors: u64,
    free_space_probe_errors: u64,
    retention_policy_errors: u64,
    storage_policy_drops: u64,
    retained_segment_count: usize,
    retained_bytes: u64,
    available_bytes: Option<u64>,
    storage_policy_satisfied: bool,
    free_space_probe: Box<FreeSpaceProbe>,
}

#[cfg(any(feature = "enabled", test))]
type FreeSpaceProbe = dyn Fn(&Path) -> io::Result<u64> + Send + Sync;

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
        let max_segment_bytes = environment_u64(
            SEGMENT_BYTES_ENV,
            DEFAULT_SEGMENT_BYTES,
            MIN_SEGMENT_BYTES,
            MAX_SEGMENT_BYTES,
        );
        let max_segment_age = Duration::from_secs(environment_u64(
            SEGMENT_SECONDS_ENV,
            DEFAULT_SEGMENT_SECONDS,
            MIN_SEGMENT_SECONDS,
            MAX_SEGMENT_SECONDS,
        ));
        let retained_segments = environment_usize(
            RETAINED_SEGMENTS_ENV,
            DEFAULT_RETAINED_SEGMENTS,
            MIN_RETAINED_SEGMENTS,
            MAX_RETAINED_SEGMENTS,
        );
        let default_max_total_bytes = max_segment_bytes
            .checked_mul(retained_segments as u64)
            .unwrap_or(DEFAULT_MAX_TOTAL_BYTES);
        let configured_max_total_bytes = environment_u64(
            MAX_TOTAL_BYTES_ENV,
            default_max_total_bytes,
            MIN_SEGMENT_BYTES,
            MAX_TOTAL_BYTES,
        );
        let max_total_bytes = if configured_max_total_bytes < max_segment_bytes {
            warn!(
                "ignoring {MAX_TOTAL_BYTES_ENV} below {SEGMENT_BYTES_ENV}; using {max_segment_bytes}"
            );
            max_segment_bytes
        } else {
            configured_max_total_bytes
        };
        let default_max_retained_seconds = max_segment_age
            .as_secs()
            .checked_mul(retained_segments as u64)
            .unwrap_or(DEFAULT_MAX_RETAINED_SECONDS);
        Some(Self {
            directory,
            max_segment_bytes,
            max_segment_age,
            retained_segments,
            max_total_bytes,
            max_retained_age: Duration::from_secs(environment_u64(
                MAX_RETAINED_SECONDS_ENV,
                default_max_retained_seconds,
                MIN_RETAINED_SECONDS,
                MAX_RETAINED_SECONDS,
            )),
            minimum_free_bytes: environment_u64(
                MINIMUM_FREE_BYTES_ENV,
                DEFAULT_MINIMUM_FREE_BYTES,
                0,
                MAX_MINIMUM_FREE_BYTES,
            ),
        })
    }
}

#[cfg(any(feature = "enabled", test))]
impl SegmentedEventWriter {
    fn new(config: WriterConfig, run_id: String, process_id: u32) -> io::Result<Self> {
        Self::new_with_free_space_probe(config, run_id, process_id, |path: &Path| {
            fs4::available_space(path)
        })
    }

    fn new_with_free_space_probe(
        config: WriterConfig,
        run_id: String,
        process_id: u32,
        free_space_probe: impl Fn(&Path) -> io::Result<u64> + Send + Sync + 'static,
    ) -> io::Result<Self> {
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
            retention_scan_errors: 0,
            free_space_probe_errors: 0,
            retention_policy_errors: 0,
            storage_policy_drops: 0,
            retained_segment_count: 1,
            retained_bytes: 0,
            available_bytes: None,
            storage_policy_satisfied: true,
            free_space_probe: Box::new(free_space_probe),
        };
        writer.enforce_retention(writer.config.max_segment_bytes);
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
        let line_bytes = line.len() as u64;
        if !self.storage_policy_satisfied
            && !self.enforce_retention(self.config.max_segment_bytes.max(line_bytes))
        {
            self.record_storage_policy_drop();
            return false;
        }
        if self.should_rotate(line_bytes) {
            match self.rotate(self.config.max_segment_bytes.max(line_bytes)) {
                Ok(true) => {}
                Ok(false) => {
                    self.record_storage_policy_drop();
                    return false;
                }
                Err(error) => {
                    self.write_errors = self.write_errors.saturating_add(1);
                    self.dropped_events = self.dropped_events.saturating_add(1);
                    warn!("failed to rotate diagnostic event segment: {error}");
                    return false;
                }
            }
            line = match self.encode_record(&pending) {
                Ok(line) => line,
                Err(()) => {
                    self.encode_errors = self.encode_errors.saturating_add(1);
                    self.dropped_events = self.dropped_events.saturating_add(1);
                    return false;
                }
            };
        } else if self.active_segment_bytes == 0
            && line_bytes > self.config.max_segment_bytes
            && !self.enforce_retention(line_bytes)
        {
            self.record_storage_policy_drop();
            return false;
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
        self.retained_bytes = self.retained_bytes.saturating_add(line.len() as u64);
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
        self.active_segment_bytes > 0
            && (self.active_segment_bytes.saturating_add(next_line_bytes)
                > self.config.max_segment_bytes
                || self.active_segment_started.elapsed() >= self.config.max_segment_age)
    }

    fn rotate(&mut self, reserved_bytes: u64) -> io::Result<bool> {
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
        Ok(self.enforce_retention(reserved_bytes))
    }

    fn enforce_retention(&mut self, reserved_bytes: u64) -> bool {
        let outcome = retention::enforce(
            &self.config.directory,
            &self.active_path,
            retention::RetentionPolicy {
                retained_segments: self.config.retained_segments,
                max_total_bytes: self.config.max_total_bytes,
                max_retained_age: self.config.max_retained_age,
                minimum_free_bytes: self.config.minimum_free_bytes,
            },
            reserved_bytes,
            SystemTime::now(),
            self.free_space_probe.as_ref(),
        );
        self.retention_deletes = self.retention_deletes.saturating_add(outcome.deleted);
        self.retention_delete_errors = self
            .retention_delete_errors
            .saturating_add(outcome.delete_errors);
        self.retention_scan_errors = self
            .retention_scan_errors
            .saturating_add(outcome.scan_errors);
        self.free_space_probe_errors = self
            .free_space_probe_errors
            .saturating_add(outcome.free_space_probe_errors);
        self.retention_policy_errors = self
            .retention_policy_errors
            .saturating_add(outcome.policy_failures);
        self.retained_segment_count = outcome.retained_segment_count;
        self.retained_bytes = outcome.retained_bytes;
        self.available_bytes = outcome.available_bytes;
        self.storage_policy_satisfied = outcome.within_limits();
        self.storage_policy_satisfied
    }

    fn record_storage_policy_drop(&mut self) {
        self.storage_policy_drops = self.storage_policy_drops.saturating_add(1);
        self.dropped_events = self.dropped_events.saturating_add(1);
        warn!("diagnostic event dropped because storage policy cannot be satisfied");
    }

    fn health(&self) -> DiagWriterHealth {
        let aggregate_growth_bytes = self
            .config
            .max_total_bytes
            .saturating_sub(self.retained_bytes);
        let maximum_growth_bytes =
            self.available_bytes
                .map_or(aggregate_growth_bytes, |available| {
                    aggregate_growth_bytes
                        .min(available.saturating_sub(self.config.minimum_free_bytes))
                });
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
            retention_scan_errors: self.retention_scan_errors,
            free_space_probe_errors: self.free_space_probe_errors,
            retention_policy_errors: self.retention_policy_errors,
            storage_policy_drops: self.storage_policy_drops,
            retained_segment_count: self.retained_segment_count,
            retained_bytes: self.retained_bytes,
            available_bytes: self.available_bytes,
            storage_policy_satisfied: Some(self.storage_policy_satisfied),
            maximum_growth_bytes: Some(maximum_growth_bytes),
            max_segment_bytes: Some(self.config.max_segment_bytes),
            max_segment_seconds: Some(self.config.max_segment_age.as_secs()),
            retained_segments: Some(self.config.retained_segments),
            max_total_bytes: Some(self.config.max_total_bytes),
            max_retained_seconds: Some(self.config.max_retained_age.as_secs()),
            minimum_free_bytes: Some(self.config.minimum_free_bytes),
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
        retention_scan_errors: 0,
        free_space_probe_errors: 0,
        retention_policy_errors: 0,
        storage_policy_drops: 0,
        retained_segment_count: 0,
        retained_bytes: 0,
        available_bytes: None,
        storage_policy_satisfied: None,
        maximum_growth_bytes: None,
        max_segment_bytes: None,
        max_segment_seconds: None,
        retained_segments: None,
        max_total_bytes: None,
        max_retained_seconds: None,
        minimum_free_bytes: None,
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
        max_total_bytes: config.as_ref().map(|config| config.max_total_bytes),
        max_retained_seconds: config
            .as_ref()
            .map(|config| config.max_retained_age.as_secs()),
        minimum_free_bytes: config.as_ref().map(|config| config.minimum_free_bytes),
        ..disabled_health()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
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
    fn aggregate_retention_bounds_total_segment_bytes() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer_with_policy(
            &root,
            "testrun",
            420,
            Duration::from_secs(60),
            100,
            900,
            Duration::MAX,
        );
        for record_id in 0..40_u64 {
            assert!(writer.emit(
                "sched",
                "rotate",
                "info",
                &json!({"record": record_id}),
                &json!({"padding": "x".repeat(80)}),
            ));
        }

        let retained_bytes = segment_bytes(root.path());
        let health = writer.health();
        assert!(retained_bytes <= 900);
        assert_eq!(health.retained_bytes, retained_bytes);
        assert_eq!(health.records_written, 40);
        assert_eq!(health.storage_policy_drops, 0);
        assert_eq!(health.storage_policy_satisfied, Some(true));
    }

    #[test]
    fn oversized_record_is_retained_when_aggregate_budget_allows_it() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer_with_policy(
            &root,
            "testrun",
            256,
            Duration::from_secs(60),
            8,
            2048,
            Duration::MAX,
        );

        assert!(writer.emit(
            "sched",
            "oversized",
            "info",
            &json!({}),
            &json!({"padding": "x".repeat(512)}),
        ));
        let health = writer.health();
        assert!(health.active_segment_bytes > 256);
        assert_eq!(health.storage_policy_drops, 0);
        assert_eq!(health.storage_policy_satisfied, Some(true));
    }

    #[test]
    fn aggregate_budget_drops_oversized_record_and_recovers_for_smaller_record() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer_with_policy(
            &root,
            "testrun",
            256,
            Duration::from_secs(60),
            8,
            600,
            Duration::MAX,
        );

        assert!(!writer.emit(
            "sched",
            "oversized",
            "info",
            &json!({}),
            &json!({"padding": "x".repeat(1024)}),
        ));
        assert_eq!(writer.health().storage_policy_satisfied, Some(false));

        assert!(writer.emit(
            "sched",
            "small",
            "info",
            &json!({}),
            &json!({"padding": "small"}),
        ));
        let health = writer.health();
        assert_eq!(health.records_written, 1);
        assert_eq!(health.dropped_events, 1);
        assert_eq!(health.storage_policy_drops, 1);
        assert_eq!(health.storage_policy_satisfied, Some(true));
    }

    #[test]
    fn minimum_free_space_blocks_writes_and_recovers_after_capacity_returns() {
        let root = TempDir::new().unwrap();
        let available_bytes = Arc::new(AtomicU64::new(500));
        let probe_available_bytes = Arc::clone(&available_bytes);
        let mut writer = SegmentedEventWriter::new_with_free_space_probe(
            WriterConfig {
                directory: root.path().to_path_buf(),
                max_segment_bytes: 256,
                max_segment_age: Duration::from_secs(60),
                retained_segments: 8,
                max_total_bytes: 2048,
                max_retained_age: Duration::MAX,
                minimum_free_bytes: 600,
            },
            "testrun".to_string(),
            42,
            move |_| Ok(probe_available_bytes.load(Ordering::Relaxed)),
        )
        .unwrap();

        assert!(!writer.emit(
            "sched",
            "blocked",
            "info",
            &json!({}),
            &json!({"padding": "small"}),
        ));
        let blocked_health = writer.health();
        assert_eq!(blocked_health.available_bytes, Some(500));
        assert_eq!(blocked_health.minimum_free_bytes, Some(600));
        assert_eq!(blocked_health.maximum_growth_bytes, Some(0));
        assert_eq!(blocked_health.storage_policy_satisfied, Some(false));
        assert_eq!(blocked_health.storage_policy_drops, 1);

        available_bytes.store(2000, Ordering::Relaxed);
        assert!(writer.emit(
            "sched",
            "recovered",
            "info",
            &json!({}),
            &json!({"padding": "small"}),
        ));
        let recovered_health = writer.health();
        assert_eq!(recovered_health.records_written, 1);
        assert_eq!(recovered_health.dropped_events, 1);
        assert_eq!(recovered_health.free_space_probe_errors, 0);
        assert_eq!(recovered_health.storage_policy_satisfied, Some(true));
        assert_eq!(recovered_health.maximum_growth_bytes, Some(1400));
    }

    #[test]
    fn free_space_probe_failure_blocks_writes() {
        let root = TempDir::new().unwrap();
        let mut writer = SegmentedEventWriter::new_with_free_space_probe(
            WriterConfig {
                directory: root.path().to_path_buf(),
                max_segment_bytes: 256,
                max_segment_age: Duration::from_secs(60),
                retained_segments: 8,
                max_total_bytes: 2048,
                max_retained_age: Duration::MAX,
                minimum_free_bytes: 600,
            },
            "testrun".to_string(),
            42,
            |_| Err(io::Error::other("probe failed")),
        )
        .unwrap();

        assert!(!writer.emit(
            "sched",
            "blocked",
            "info",
            &json!({}),
            &json!({"padding": "small"}),
        ));
        let health = writer.health();
        assert_eq!(health.records_written, 0);
        assert_eq!(health.dropped_events, 1);
        assert_eq!(health.free_space_probe_errors, 4);
        assert_eq!(health.available_bytes, None);
        assert_eq!(health.storage_policy_satisfied, Some(false));
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
    fn rollover_preserves_a_record_that_exceeds_the_segment_target_after_reencoding() {
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

        assert!(writer.emit("sched", "segment_width", "info", &keys, &body));
        assert_eq!(writer.active_segment_id, 1_000_000);
        assert!(writer.active_segment_bytes > writer.config.max_segment_bytes);
        assert_eq!(writer.dropped_events, 0);
        assert_eq!(read_records(root.path()).len(), 1);
    }

    #[test]
    fn oversized_records_are_retained_in_an_isolated_segment() {
        let root = TempDir::new().unwrap();
        let mut writer = test_writer(&root, 128, Duration::from_secs(60), 2);

        assert!(writer.emit(
            "sched",
            "oversized",
            "info",
            &json!({}),
            &json!({"padding": "x".repeat(512)}),
        ));
        assert!(writer.active_segment_bytes > writer.config.max_segment_bytes);
        assert_eq!(writer.active_segment_id, 0);

        assert!(writer.emit(
            "sched",
            "following",
            "info",
            &json!({}),
            &json!({"padding": "small"}),
        ));
        let health = writer.health();
        assert_eq!(health.records_written, 2);
        assert_eq!(health.dropped_events, 0);
        assert_eq!(health.active_segment_id, Some(1));
        assert_eq!(segment_files_for_run(root.path(), "testrun").len(), 2);
        assert_eq!(read_records(root.path()).len(), 2);
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
        test_writer_with_policy(
            root,
            run_id,
            max_segment_bytes,
            max_segment_age,
            retained_segments,
            u64::MAX,
            Duration::MAX,
        )
    }

    fn test_writer_with_policy(
        root: &TempDir,
        run_id: &str,
        max_segment_bytes: u64,
        max_segment_age: Duration,
        retained_segments: usize,
        max_total_bytes: u64,
        max_retained_age: Duration,
    ) -> SegmentedEventWriter {
        SegmentedEventWriter::new(
            WriterConfig {
                directory: root.path().to_path_buf(),
                max_segment_bytes,
                max_segment_age,
                retained_segments,
                max_total_bytes,
                max_retained_age,
                minimum_free_bytes: 0,
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

    fn segment_bytes(root: &Path) -> u64 {
        segment_files(root)
            .into_iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum()
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
