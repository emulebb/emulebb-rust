//! Regular-daemon tracing setup for console, REST, and retained JSONL output.

use std::fmt::Write;
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_appender::non_blocking::{ErrorCounter, NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::Context as LayerContext;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer, fmt};

const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::INFO;
const LOG_DIRECTORY_NAME: &str = "logs";
const LOG_FILE_PREFIX: &str = "emulebb-rust";
const LOG_FILE_SUFFIX: &str = "jsonl";
const RETAINED_LOG_FILES: usize = 8;
const FILE_BUFFERED_LINES: usize = 8192;
const DROP_MONITOR_INTERVAL: Duration = Duration::from_secs(60);

type RestSink = dyn Fn(&'static str, String, bool) + Send + Sync + 'static;

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let separator = if self.fields.is_empty() { "" } else { " " };
            let _ = write!(self.fields, "{separator}{}={value:?}", field.name());
        }
    }
}

/// Forwards tracing events into the REST recent-log ring buffer.
pub struct RestLogLayer {
    sink: Arc<RestSink>,
}

impl Default for RestLogLayer {
    fn default() -> Self {
        Self {
            sink: Arc::new(|level, message, debug| {
                emulebb_rest::record_log(level, message, debug);
            }),
        }
    }
}

impl RestLogLayer {
    #[cfg(test)]
    fn with_sink(sink: impl Fn(&'static str, String, bool) + Send + Sync + 'static) -> Self {
        Self {
            sink: Arc::new(sink),
        }
    }
}

impl<S: Subscriber> Layer<S> for RestLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) {
        let level = *event.metadata().level();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        if visitor.message.is_empty() && visitor.fields.is_empty() {
            return;
        }
        let message = match (visitor.message.is_empty(), visitor.fields.is_empty()) {
            (false, false) => format!("{} [{}]", visitor.message, visitor.fields),
            (true, false) => visitor.fields,
            _ => visitor.message,
        };
        let level_str = match level {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };
        let debug = matches!(level, Level::DEBUG | Level::TRACE);
        (self.sink)(level_str, message, debug);
    }
}

struct FileOutput {
    writer: Mutex<tracing_appender::non_blocking::NonBlocking>,
    worker_guard: WorkerGuard,
    error_counter: ErrorCounter,
    directory: PathBuf,
}

/// Owns the retained-file worker and its dropped-line monitor.
///
/// Keep this value alive until all daemon work has stopped, then call
/// [`Self::shutdown`] so the non-blocking writer can flush before process exit.
pub struct LoggingGuard {
    worker_guard: Option<WorkerGuard>,
    error_counter: Option<ErrorCounter>,
    monitor_shutdown: Option<watch::Sender<bool>>,
    monitor_task: Option<JoinHandle<()>>,
    shutdown_reported: bool,
}

impl LoggingGuard {
    /// Stops drop monitoring, reports any loss, and flushes retained logs.
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.monitor_shutdown.take() {
            let _ = shutdown.send(true);
        }
        if let Some(task) = self.monitor_task.take() {
            let _ = task.await;
        }
        if let Some(counter) = self.error_counter.as_ref() {
            let dropped = counter.dropped_lines();
            if dropped > 0 {
                tracing::warn!(
                    dropped_file_log_lines = dropped,
                    "persistent log writer dropped events before shutdown"
                );
            }
        }
        self.shutdown_reported = true;
        drop(self.worker_guard.take());
    }
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        if let Some(task) = self.monitor_task.take() {
            task.abort();
        }
        if !self.shutdown_reported
            && let Some(counter) = self.error_counter.as_ref()
        {
            let dropped = counter.dropped_lines();
            if dropped > 0 {
                eprintln!("persistent log writer dropped {dropped} event(s)");
            }
        }
    }
}

/// Installs the process-global regular-daemon subscriber.
///
/// The profile must already be validated before this function is called. File
/// setup failure is non-fatal: console and REST logging remain available.
pub fn init(profile_dir: &Path) -> Result<LoggingGuard> {
    let (filter_spec, filter_warning) = read_filter_spec();
    let mut file_warning = None;
    let file_output = match create_file_output(profile_dir) {
        Ok(output) => Some(output),
        Err(error) => {
            file_warning = Some(format!("{error:#}"));
            None
        }
    };

    let (file_layer, worker_guard, error_counter, file_directory) = match file_output {
        Some(output) => (
            Some(
                fmt::layer()
                    .json()
                    .with_ansi(false)
                    .with_current_span(true)
                    .with_span_list(true)
                    .with_writer(output.writer)
                    .with_filter(build_filter(&filter_spec)),
            ),
            Some(output.worker_guard),
            Some(output.error_counter),
            Some(output.directory),
        ),
        None => (None, None, None, None),
    };

    let console_layer = fmt::layer()
        .with_writer(io::stdout)
        .with_ansi(io::stdout().is_terminal())
        .with_filter(build_filter(&filter_spec));
    let rest_layer = RestLogLayer::default().with_filter(build_filter(&filter_spec));

    tracing_subscriber::registry()
        .with(console_layer)
        .with(rest_layer)
        .with(file_layer)
        .try_init()
        .context("failed to install the process logging subscriber")?;

    if let Some(warning) = filter_warning {
        tracing::warn!(error = %warning, "ignored invalid RUST_LOG directives");
    }
    if let Some(warning) = file_warning {
        tracing::warn!(error = %warning, "persistent logging is unavailable; continuing with console and REST logging");
    }
    if let Some(directory) = file_directory.as_ref() {
        tracing::info!(
            path = %directory.display(),
            retained_files = RETAINED_LOG_FILES,
            format = "jsonl",
            "persistent logging initialized"
        );
    }

    let (monitor_shutdown, monitor_task) = match error_counter.as_ref() {
        Some(counter) => {
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let task = tokio::spawn(monitor_dropped_lines(counter.clone(), shutdown_rx));
            (Some(shutdown_tx), Some(task))
        }
        None => (None, None),
    };

    Ok(LoggingGuard {
        worker_guard,
        error_counter,
        monitor_shutdown,
        monitor_task,
        shutdown_reported: false,
    })
}

fn read_filter_spec() -> (String, Option<String>) {
    match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(spec) => {
            let warning = filter_builder()
                .parse(&spec)
                .err()
                .map(|error| error.to_string());
            (spec, warning)
        }
        Err(std::env::VarError::NotPresent) => (String::new(), None),
        Err(std::env::VarError::NotUnicode(_)) => (
            String::new(),
            Some("RUST_LOG is not valid Unicode".to_string()),
        ),
    }
}

fn filter_builder() -> tracing_subscriber::filter::Builder {
    EnvFilter::builder().with_default_directive(DEFAULT_LOG_LEVEL.into())
}

fn build_filter(spec: &str) -> EnvFilter {
    filter_builder().parse_lossy(spec)
}

fn create_file_output(profile_dir: &Path) -> Result<FileOutput> {
    let directory = profile_dir.join(LOG_DIRECTORY_NAME);
    std::fs::create_dir_all(&directory)
        .with_context(|| format!("failed to create log directory {}", directory.display()))?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(LOG_FILE_PREFIX)
        .filename_suffix(LOG_FILE_SUFFIX)
        .max_log_files(RETAINED_LOG_FILES)
        .build(&directory)
        .with_context(|| format!("failed to open retained logs under {}", directory.display()))?;
    let (writer, worker_guard) = NonBlockingBuilder::default()
        .buffered_lines_limit(FILE_BUFFERED_LINES)
        .lossy(true)
        .thread_name("emulebb-log-writer")
        .finish(appender);
    let error_counter = writer.error_counter();
    Ok(FileOutput {
        writer: Mutex::new(writer),
        worker_guard,
        error_counter,
        directory,
    })
}

async fn monitor_dropped_lines(counter: ErrorCounter, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(DROP_MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    let mut last_dropped = 0;
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => {
                let dropped = counter.dropped_lines();
                if dropped > last_dropped {
                    tracing::warn!(
                        dropped_file_log_lines = dropped,
                        dropped_since_last_report = dropped - last_dropped,
                        "persistent log writer is dropping events"
                    );
                    last_dropped = dropped;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::Mutex;

    #[test]
    fn empty_filter_uses_info_default_and_invalid_directives_fall_back() {
        assert_eq!(build_filter("").to_string(), "info");
        assert_eq!(build_filter("foo==debug").to_string(), "info");
    }

    #[test]
    fn explicit_filter_directives_are_authoritative() {
        let filter = build_filter("emulebb_core=debug").to_string();
        assert_eq!(filter, "emulebb_core=debug");
    }

    #[test]
    fn rest_layer_preserves_levels_messages_and_structured_fields() {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink_records = Arc::clone(&records);
        let subscriber = tracing_subscriber::registry().with(RestLogLayer::with_sink(
            move |level, message, debug| {
                sink_records
                    .lock()
                    .unwrap()
                    .push((level.to_string(), message, debug));
            },
        ));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(count = 3, "catalog hydrated");
            tracing::debug!(peer_count = 7, "peer scan complete");
            tracing::warn!(retry_secs = 5, "retry scheduled");
        });

        let records = records.lock().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].0, "info");
        assert!(records[0].1.contains("catalog hydrated"));
        assert!(records[0].1.contains("count=3"));
        assert!(!records[0].2);
        assert_eq!(records[1].0, "debug");
        assert!(records[1].2);
        assert_eq!(records[2].0, "warn");
    }

    #[test]
    fn retained_file_output_is_json_lines() {
        let temp = tempfile::tempdir().unwrap();
        let FileOutput {
            writer,
            worker_guard,
            error_counter,
            directory,
        } = create_file_output(temp.path()).unwrap();
        let subscriber = tracing_subscriber::registry().with(
            fmt::layer()
                .json()
                .with_ansi(false)
                .with_writer(writer)
                .with_filter(build_filter("")),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(peer_count = 4, "file logging test");
        });
        drop(worker_guard);

        assert_eq!(error_counter.dropped_lines(), 0);
        let files = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].extension().and_then(|value| value.to_str()),
            Some("jsonl")
        );
        let line = std::fs::read_to_string(&files[0]).unwrap();
        let event: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(event["level"], "INFO");
        assert_eq!(event["fields"]["message"], "file logging test");
        assert_eq!(event["fields"]["peer_count"], 4);
    }

    #[test]
    fn retained_file_setup_failure_is_reportable() {
        let temp = tempfile::tempdir().unwrap();
        let profile_file = temp.path().join("not-a-directory");
        std::fs::write(&profile_file, "occupied").unwrap();

        let error = match create_file_output(&profile_file) {
            Ok(_) => panic!("file-backed profile unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("failed to create log directory"));
    }
}
