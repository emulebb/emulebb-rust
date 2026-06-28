//! Process lifecycle state surfaced by `GET /api/v1/app`.
//!
//! The core holds a small atomic so the REST `app.lifecycle.state` reflects the
//! real daemon phase (eMule has no headless equivalent; the meaningful states
//! for a serving daemon are `running` and, during graceful teardown,
//! `shuttingdown`). The daemon calls [`EmulebbCore::begin_shutdown`] when
//! teardown starts so a polling controller observes the shutdown instead of a
//! hardcoded `running`.
//!
//! WHY the exact `shuttingdown` spelling: it is the only teardown token in the
//! `/api/v1` contract enum (`[starting, running, shuttingdown, done]`), and the
//! REST `lifecycle_response` derives `shutdownInProgress` / `acceptingRest` by
//! matching it. Emitting any other spelling (e.g. `stopping`) both violates the
//! schema and silently leaves `shutdownInProgress=false` during teardown.

use std::sync::atomic::Ordering;

use crate::EmulebbCore;

// State 0 (the AtomicU8 default) is "running"; only the non-default state needs
// a named constant.
const LIFECYCLE_SHUTTING_DOWN: u8 = 1;

impl EmulebbCore {
    /// Mark the daemon as shutting down so `GET /api/v1/app` reports
    /// `shuttingdown`. Idempotent; called at the start of graceful teardown.
    pub fn begin_shutdown(&self) {
        self.lifecycle
            .store(LIFECYCLE_SHUTTING_DOWN, Ordering::SeqCst);
    }

    /// The REST `app.lifecycle.state` token for the current phase. Must stay
    /// within the contract enum `[starting, running, shuttingdown, done]`.
    pub(crate) fn lifecycle_state_name(&self) -> &'static str {
        match self.lifecycle.load(Ordering::SeqCst) {
            LIFECYCLE_SHUTTING_DOWN => "shuttingdown",
            _ => "running",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::EmulebbCore;
    use emulebb_index::FileIndex;

    #[test]
    fn lifecycle_starts_running_and_flips_to_shuttingdown() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        assert_eq!(core.app_info().lifecycle.state, "running");
        core.begin_shutdown();
        // Must be the contract enum token so the REST layer flips
        // shutdownInProgress/acceptingRest (responses.rs lifecycle_response).
        assert_eq!(core.app_info().lifecycle.state, "shuttingdown");
    }
}
