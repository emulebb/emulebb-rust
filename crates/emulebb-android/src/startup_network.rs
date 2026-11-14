//! Cancellable network generations for one Android-hosted daemon worker.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use emulebb_daemon::NetworkStartupError;

#[derive(Default)]
struct State {
    generation: u64,
    cancelled: bool,
}

#[derive(Default)]
pub(super) struct StartupNetwork {
    state: Mutex<State>,
    changed: Condvar,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Wake {
    Changed,
    Retry,
    Cancelled,
}

impl StartupNetwork {
    pub(super) fn run(
        &self,
        mut attempt: impl FnMut(&mut bool) -> Result<()>,
        mut waiting: impl FnMut(bool) -> Result<()>,
    ) -> Result<()> {
        let mut failures = 0;
        loop {
            if self.cancelled()? {
                return Ok(());
            }
            // Snapshot before the attempt so a callback racing the native
            // probe cannot be lost between a failure and its wait.
            let generation = self.generation()?;
            let mut ready = false;
            let outcome = attempt(&mut ready);
            if self.cancelled()? {
                return Ok(());
            }
            let Err(error) = outcome else {
                return Ok(());
            };
            if ready
                || !matches!(
                    error.downcast_ref::<NetworkStartupError>(),
                    Some(NetworkStartupError::DefaultRouteUnavailable)
                )
            {
                return Err(error);
            }
            waiting(true)?;
            let wake = self.wait(generation, retry_delay(failures))?;
            waiting(false)?;
            match wake {
                Wake::Cancelled => return Ok(()),
                Wake::Changed => failures = 0,
                Wake::Retry => failures = failures.saturating_add(1),
            }
        }
    }

    fn cancelled(&self) -> Result<bool> {
        Ok(self.state.lock().map_err(|_| unavailable())?.cancelled)
    }

    pub(super) fn generation(&self) -> Result<u64> {
        Ok(self.state.lock().map_err(|_| unavailable())?.generation)
    }

    pub(super) fn changed(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| unavailable())?;
        state.generation = state.generation.wrapping_add(1);
        self.changed.notify_all();
        Ok(())
    }

    pub(super) fn cancel(&self) -> Result<()> {
        self.state.lock().map_err(|_| unavailable())?.cancelled = true;
        self.changed.notify_all();
        Ok(())
    }

    pub(super) fn wait(&self, generation: u64, delay: Duration) -> Result<Wake> {
        let state = self.state.lock().map_err(|_| unavailable())?;
        let (state, _) = self
            .changed
            .wait_timeout_while(state, delay, |state| {
                !state.cancelled && state.generation == generation
            })
            .map_err(|_| unavailable())?;
        Ok(if state.cancelled {
            Wake::Cancelled
        } else if state.generation != generation {
            Wake::Changed
        } else {
            Wake::Retry
        })
    }
}

pub(super) fn retry_delay(failures: u32) -> Duration {
    // WHY: LinkProperties callbacks can precede kernel route readiness. Retain
    // liveness without requiring another callback, with bounded probe frequency.
    Duration::from_secs((1u64 << failures.min(5)).min(30))
}

fn unavailable() -> anyhow::Error {
    anyhow!("network startup signal unavailable")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn network_change_during_attempt_cannot_be_lost_before_wait() {
        let signal = StartupNetwork::default();
        let generation = signal.generation().unwrap();
        signal.changed().unwrap();
        assert_eq!(
            signal.wait(generation, Duration::from_secs(60)).unwrap(),
            Wake::Changed
        );
    }

    #[test]
    fn stop_cancels_existing_and_future_waits_despite_late_network_changes() {
        let signal = Arc::new(StartupNetwork::default());
        let worker_signal = Arc::clone(&signal);
        let worker =
            std::thread::spawn(move || worker_signal.wait(0, Duration::from_secs(60)).unwrap());
        signal.cancel().unwrap();
        signal.changed().unwrap();
        assert_eq!(worker.join().unwrap(), Wake::Cancelled);
        assert_eq!(
            signal
                .wait(signal.generation().unwrap(), Duration::from_secs(60))
                .unwrap(),
            Wake::Cancelled
        );
    }

    #[test]
    fn absent_callback_still_allows_a_rate_limited_recheck() {
        let signal = StartupNetwork::default();
        assert_eq!(signal.wait(0, Duration::ZERO).unwrap(), Wake::Retry);
        assert_eq!(retry_delay(0), Duration::from_secs(1));
        assert_eq!(retry_delay(4), Duration::from_secs(16));
        assert_eq!(retry_delay(5), Duration::from_secs(30));
        assert_eq!(retry_delay(u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn typed_unavailable_route_waits_then_ready_attempt_completes() {
        let signal = StartupNetwork::default();
        let mut attempts = 0;
        let mut waiting = Vec::new();
        signal
            .run(
                |_| {
                    attempts += 1;
                    if attempts == 1 {
                        signal.changed()?;
                        Err(NetworkStartupError::DefaultRouteUnavailable.into())
                    } else {
                        Ok(())
                    }
                },
                |state| {
                    waiting.push(state);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(attempts, 2);
        assert_eq!(waiting, [true, false]);
    }

    #[test]
    fn permanent_failure_does_not_wait_or_retry() {
        let signal = StartupNetwork::default();
        let mut attempts = 0;
        let error = signal
            .run(
                |_| {
                    attempts += 1;
                    Err(anyhow!("invalid binding configuration"))
                },
                |_| panic!("permanent failure must not wait"),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "invalid binding configuration");
        assert_eq!(attempts, 1);
    }

    #[test]
    fn cancellation_during_attempt_and_late_callback_never_retry() {
        let signal = StartupNetwork::default();
        let mut attempts = 0;
        signal
            .run(
                |_| {
                    attempts += 1;
                    signal.cancel()?;
                    signal.changed()?;
                    Err(NetworkStartupError::DefaultRouteUnavailable.into())
                },
                |_| panic!("cancelled startup must not wait"),
            )
            .unwrap();
        signal
            .run(
                |_| panic!("late callback must not start another attempt"),
                |_| Ok(()),
            )
            .unwrap();
        assert_eq!(attempts, 1);
    }

    #[test]
    fn network_error_after_readiness_is_fatal() {
        let signal = StartupNetwork::default();
        let mut attempts = 0;
        let error = signal
            .run(
                |ready| {
                    attempts += 1;
                    *ready = true;
                    Err(NetworkStartupError::DefaultRouteUnavailable.into())
                },
                |_| panic!("a ready runtime must not enter startup waiting"),
            )
            .unwrap_err();
        assert!(error.is::<NetworkStartupError>());
        assert_eq!(attempts, 1);
    }
}
