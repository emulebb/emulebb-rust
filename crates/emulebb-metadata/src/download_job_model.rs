//! Durable job identity is independent of protocol content identity.
use anyhow::{Result, ensure};
use std::{fmt, path::PathBuf, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JobId(i64);
impl JobId {
    pub fn new(value: i64) -> Result<Self> {
        ensure!(value > 0, "download job ID must be positive");
        Ok(Self(value))
    }
    pub const fn get(self) -> i64 {
        self.0
    }
}
impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for JobId {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit()),
            "download job ID must be a canonical positive decimal string"
        );
        Self::new(value.parse()?)
    }
}
impl rusqlite::ToSql for JobId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(self.0.into())
    }
}
impl rusqlite::types::FromSql for JobId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let id = value.as_i64()?;
        if id <= 0 {
            return Err(rusqlite::types::FromSqlError::OutOfRange(id));
        }
        Ok(Self(id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobToken {
    pub job_id: JobId,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadIntent {
    Started,
    Stopped,
}
impl DownloadIntent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Stopped => "stopped",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "started" => Ok(Self::Started),
            "stopped" => Ok(Self::Stopped),
            _ => anyhow::bail!("invalid download intent"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DownloadJobRequest {
    pub file_hash: String,
    pub display_name: String,
    pub expected_size_bytes: Option<u64>,
    pub category_id: Option<i64>,
    pub intent: DownloadIntent,
    pub piece_size: u64,
}

/// Physical ownership is distinct from a profile-scoped public JobId. The full
/// path and random marker are fixed before allocation; identity is established
/// after exclusive directory creation and before any payload write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobStorage {
    pub path: PathBuf,
    pub marker_id: uuid::Uuid,
    pub identity: Option<crate::NativeFileIdentity>,
}

/// Opaque storage diagnostic. Bounds are UTF-8 bytes, checked before allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobStorageFailure {
    code: String,
    message: String,
    failed_at_s: i64,
}
impl DownloadJobStorageFailure {
    pub const MAX_CODE_BYTES: usize = 64;
    pub const MAX_MESSAGE_BYTES: usize = 4096;

    pub fn new(code: &str, message: &str, failed_at_s: i64) -> Result<Self> {
        ensure!(
            !code.is_empty() && code.len() <= Self::MAX_CODE_BYTES && !code.contains('\0'),
            "storage failure code is empty, contains NUL or exceeds byte allowance"
        );
        ensure!(
            message.len() <= Self::MAX_MESSAGE_BYTES && !message.contains('\0'),
            "storage failure message contains NUL or exceeds byte allowance"
        );
        ensure!(
            failed_at_s >= 0,
            "storage failure timestamp must be nonnegative Unix seconds"
        );
        Ok(Self {
            code: code.to_owned(),
            message: message.to_owned(),
            failed_at_s,
        })
    }
    pub fn code(&self) -> &str {
        &self.code
    }
    pub fn message(&self) -> &str {
        &self.message
    }
    pub fn failed_at_s(&self) -> i64 {
        self.failed_at_s
    }
}

/// A refused callback still reports the actual current record, if it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobStorageFailureOutcome {
    pub applied: bool,
    pub job: Option<DownloadJobRecord>,
}

/// Compact pages never hydrate piece maps, sources, or historical workers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobRecord {
    pub token: JobToken,
    pub file_hash: String,
    pub display_name: String,
    pub accepted_size_bytes: Option<u64>,
    pub expected_size_bytes: Option<u64>,
    /// Sum of current persisted piece byte counts, including unverified bytes.
    /// Internal retirement removes those pieces and resets this count to zero.
    pub checkpointed_bytes: u64,
    pub category_id: Option<i64>,
    pub intent: DownloadIntent,
    pub selected_temp: Option<PathBuf>,
    pub storage: Option<DownloadJobStorage>,
    pub storage_failure: Option<DownloadJobStorageFailure>,
    pub payload_verified: bool,
    pub delivery_state: crate::MetadataTransferDeliveryState,
    pub created_at_s: i64,
    pub updated_at_s: i64,
    pub completed_at_s: Option<i64>,
    pub removed_at_s: Option<i64>,
    pub internal_storage_retired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadJobAdmission {
    pub created: bool,
    pub job: DownloadJobRecord,
}

impl DownloadJobRecord {
    /// Byte presence is independent of verification. Terminal completion remains
    /// complete after internal pieces are retired; unknown totals have no fraction.
    pub fn progress(&self) -> Option<f64> {
        let size = self.expected_size_bytes.filter(|size| *size > 0)?;
        Some(if self.completed_at_s.is_some() {
            1.0
        } else {
            self.checkpointed_bytes as f64 / size as f64
        })
    }
}
