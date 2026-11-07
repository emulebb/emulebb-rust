//! One current-schema compatibility domain for the complete profile database.
//!
//! `known_files` owns accepted content identity and its preferred index label;
//! observations retain their own claims. `transfers` owns download geometry and
//! presentation, while `verified_local_content` owns verified local evidence.
//! Paths identify native byte sequences; sort/search keys are derived projections.
//! Membership authorizes sharing only together with current fingerprint evidence.
//! Download history deliberately survives removal of content, paths, and transfers.
//!
//! Hashes are fixed-width BLOBs. Sizes and counters use nonnegative signed SQLite
//! integers; writes reject out-of-range sizes and saturate lifetime counters.
//! Full-range unsigned wire/search values use eight big-endian bytes, preserving
//! numeric ordering under SQLite BLOB comparison. Nullable values mean absent;
//! timestamp columns use Unix milliseconds and explicit event names.
//! Every persisted shape change bumps the single version. Older profiles are
//! rejected: this module contains no migration or legacy interpretation.

pub const SCHEMA_ID: &str = "emulebb.metadata";
pub const SCHEMA_VERSION: i64 = 67;
pub const SCHEMA_SQL: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests;
