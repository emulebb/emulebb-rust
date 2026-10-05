//! Process-global recent-log ring buffer surfaced through `GET /api/v1/logs`.
//!
//! The daemon installs a tracing layer that calls [`record_log`]; the REST
//! `logs` handler reads [`recent_logs`]. One buffer per process matches the
//! single global logger.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_CAPACITY: usize = 2000;
const MAX_LOG_MESSAGE_BYTES: usize = 4096;
const TRUNCATION_MARKER: &str = "... [truncated]";

/// One captured log line in the eMuleBB `LogEntry` shape.
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// Unix timestamp in seconds (matches the master `CTime::GetTime`).
    pub timestamp: i64,
    pub level: String,
    pub message: String,
    pub debug: bool,
}

fn buffer() -> &'static Mutex<VecDeque<LogRecord>> {
    static LOG_BUFFER: OnceLock<Mutex<VecDeque<LogRecord>>> = OnceLock::new();
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(LOG_CAPACITY)))
}

#[cfg(test)]
pub(crate) async fn test_log_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static TEST_LOG_MUTEX: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    TEST_LOG_MUTEX
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// Records one recent log line. Called by the daemon's tracing layer.
pub fn record_log(level: impl Into<String>, message: impl Into<String>, debug: bool) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0);
    let mut buf = buffer().lock().unwrap_or_else(|poison| poison.into_inner());
    if buf.len() >= LOG_CAPACITY {
        buf.pop_front();
    }
    buf.push_back(LogRecord {
        timestamp,
        level: level.into(),
        message: truncate_message(message.into()),
        debug,
    });
}

/// Returns at most `limit` recent log records, newest first.
pub fn recent_logs(limit: usize) -> Vec<LogRecord> {
    let buf = buffer().lock().unwrap_or_else(|poison| poison.into_inner());
    buf.iter().rev().take(limit).cloned().collect()
}

fn truncate_message(mut message: String) -> String {
    if message.len() <= MAX_LOG_MESSAGE_BYTES {
        return message;
    }

    let mut truncate_at = MAX_LOG_MESSAGE_BYTES.saturating_sub(TRUNCATION_MARKER.len());
    while !message.is_char_boundary(truncate_at) {
        truncate_at -= 1;
    }
    message.truncate(truncate_at);
    message.push_str(TRUNCATION_MARKER);
    message
}

/// Clears the recent-log buffer.
pub fn clear_logs() {
    buffer()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_caps_and_clears() {
        let _guard = test_log_guard().await;
        clear_logs();
        for index in 0..(LOG_CAPACITY + 10) {
            record_log("info", format!("line {index}"), false);
        }
        let logs = recent_logs(LOG_CAPACITY);
        assert_eq!(logs.len(), LOG_CAPACITY);
        // Newest first.
        assert_eq!(logs[0].message, format!("line {}", LOG_CAPACITY + 9));
        assert!(logs[0].timestamp > 0);
        clear_logs();
        assert!(recent_logs(LOG_CAPACITY).is_empty());
    }

    #[tokio::test]
    async fn limits_without_cloning_the_whole_buffer() {
        let _guard = test_log_guard().await;
        clear_logs();
        for index in 0..10 {
            record_log("info", format!("line {index}"), false);
        }

        let logs = recent_logs(2);
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].message, "line 9");
        assert_eq!(logs[1].message, "line 8");
        clear_logs();
    }

    #[tokio::test]
    async fn truncates_large_messages_on_a_unicode_boundary() {
        let _guard = test_log_guard().await;
        clear_logs();
        record_log("info", "é".repeat(MAX_LOG_MESSAGE_BYTES), false);

        let logs = recent_logs(1);
        assert_eq!(logs.len(), 1);
        assert!(logs[0].message.len() <= MAX_LOG_MESSAGE_BYTES);
        assert!(logs[0].message.ends_with(TRUNCATION_MARKER));
        clear_logs();
    }

    #[tokio::test]
    async fn accepts_concurrent_writers_without_exceeding_capacity() {
        let _guard = test_log_guard().await;
        clear_logs();
        std::thread::scope(|scope| {
            for worker in 0..8 {
                scope.spawn(move || {
                    for line in 0..400 {
                        record_log("debug", format!("worker={worker} line={line}"), true);
                    }
                });
            }
        });

        let logs = recent_logs(LOG_CAPACITY + 1);
        assert_eq!(logs.len(), LOG_CAPACITY);
        assert!(logs.iter().all(|record| record.debug));
        clear_logs();
    }
}
