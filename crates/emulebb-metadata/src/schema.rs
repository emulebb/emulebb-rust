//! One current persisted shape for the complete profile database.
//!
//! `known_files` owns accepted content identity and its first client-accepted label;
//! observations retain their own claims. It also owns explicit local metadata.
//! `download_jobs` owns execution geometry and lifecycle, while
//! `verified_local_content` owns verified local evidence.
//! Paths identify native byte sequences; sort/search keys are derived projections.
//! Membership authorizes sharing only together with current fingerprint evidence.
//! Download history deliberately survives removal of content, paths, and download_jobs.
//!
//! Hashes are fixed-width BLOBs. Sizes and counters use nonnegative signed SQLite
//! integers; writes reject out-of-range sizes and counters.
//! Full-range unsigned wire/search values use eight big-endian bytes, preserving
//! numeric ordering under SQLite BLOB comparison. Nullable values mean absent;
//! calendar timestamp columns use Unix seconds with explicit unit suffixes.
//! Every persisted shape change bumps the single current-shape version.

pub const SCHEMA_ID: &str = "emulebb.metadata";
pub const SCHEMA_VERSION: i64 = 119;
pub const SCHEMA_SQL: &str = include_str!("schema.sql");

#[cfg(test)]
mod tests;
