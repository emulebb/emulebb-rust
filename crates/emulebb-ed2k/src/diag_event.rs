//! Shared diagnostic-event facade for eD2K and core producers.
//!
//! Serialization, process-wide sequencing, segmented rotation, retention, and
//! writer health live in the dependency-neutral `emulebb-diagnostics` crate.

use serde_json::Value;

pub use emulebb_diagnostics::DiagWriterHealth;

pub fn emit(
    family: &'static str,
    event: &'static str,
    severity: &'static str,
    keys: Value,
    body: Value,
) {
    let _ = emulebb_diagnostics::emit(family, event, severity, keys, body);
}

pub fn writer_health() -> DiagWriterHealth {
    emulebb_diagnostics::writer_health()
}
