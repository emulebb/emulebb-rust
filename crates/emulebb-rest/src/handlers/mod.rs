//! Axum route handlers, grouped by REST domain.
//!
//! Each submodule holds the `async fn` handlers for one route family. They were
//! extracted verbatim from `lib.rs` during the maintainability restructuring;
//! behavior is unchanged. The handler functions are re-exported here so the
//! router wiring in `lib.rs` references them unqualified.

pub(crate) mod logs;

pub(crate) use logs::{clear_logs, logs};
