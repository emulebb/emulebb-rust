//! Process lifecycle state surfaced by `GET /api/v1/app`.
//!
//! The core holds a small atomic so the REST `app.lifecycle.state` reflects the
//! real daemon phase (eMule has no headless equivalent; the meaningful states
//! for a serving daemon are `running` and, during graceful teardown,
//! `stopping`). The daemon calls [`EmulebbCore::begin_shutdown`] when teardown
//! starts so a polling controller observes the shutdown instead of a hardcoded
//! `running`.

use std::sync::atomic::Ordering;

use crate::EmulebbCore;

// State 0 (the AtomicU8 default) is "running"; only the non-default state needs
// a named constant.
const LIFECYCLE_STOPPING: u8 = 1;

impl EmulebbCore {
    /// Mark the daemon as shutting down so `GET /api/v1/app` reports `stopping`.
    /// Idempotent; called at the start of graceful teardown.
    pub fn begin_shutdown(&self) {
        self.lifecycle.store(LIFECYCLE_STOPPING, Ordering::SeqCst);
    }

    /// The REST `app.lifecycle.state` token for the current phase.
    pub(crate) fn lifecycle_state_name(&self) -> &'static str {
        match self.lifecycle.load(Ordering::SeqCst) {
            LIFECYCLE_STOPPING => "stopping",
            _ => "running",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::EmulebbCore;
    use emulebb_index::FileIndex;

    #[test]
    fn lifecycle_starts_running_and_flips_to_stopping() {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        assert_eq!(core.app_info().lifecycle.state, "running");
        core.begin_shutdown();
        assert_eq!(core.app_info().lifecycle.state, "stopping");
    }
}
