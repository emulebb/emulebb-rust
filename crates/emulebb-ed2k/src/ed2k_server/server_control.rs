use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use anyhow::{Result, anyhow};
use tokio::sync::{Notify, watch};

/// Core-side control handle for the independently stoppable eD2k server lane.
#[derive(Clone, Debug)]
pub struct Ed2kServerControlHandle {
    enabled: Arc<AtomicBool>,
    wake: Arc<Notify>,
    requested_retirement: Arc<AtomicU64>,
    retired: watch::Receiver<u64>,
}

/// Supervisor-side endpoint that acknowledges completed server retirement.
#[derive(Debug)]
pub struct Ed2kServerControlReceiver {
    enabled: Arc<AtomicBool>,
    wake: Arc<Notify>,
    requested_retirement: Arc<AtomicU64>,
    retired: watch::Sender<u64>,
}

/// Creates one serialized control/acknowledgment channel for a server supervisor.
pub fn ed2k_server_control_channel(
    initially_enabled: bool,
) -> (Ed2kServerControlHandle, Ed2kServerControlReceiver) {
    let enabled = Arc::new(AtomicBool::new(initially_enabled));
    let wake = Arc::new(Notify::new());
    let requested_retirement = Arc::new(AtomicU64::new(0));
    let (retired, retired_rx) = watch::channel(0);
    (
        Ed2kServerControlHandle {
            enabled: Arc::clone(&enabled),
            wake: Arc::clone(&wake),
            requested_retirement: Arc::clone(&requested_retirement),
            retired: retired_rx,
        },
        Ed2kServerControlReceiver {
            enabled,
            wake,
            requested_retirement,
            retired,
        },
    )
}

impl Ed2kServerControlHandle {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// Enables the server lane and wakes an idle disabled supervisor.
    pub fn enable(&self) {
        if !self.enabled.swap(true, Ordering::SeqCst) {
            self.wake.notify_one();
        }
    }

    /// Requests a fresh server session without changing the enabled state.
    pub fn request_reconnect(&self) {
        self.wake.notify_one();
    }

    /// Wakes the supervisor after whole-runtime shutdown has been signaled.
    pub fn wake_supervisor(&self) {
        self.wake.notify_waiters();
    }

    /// Disables the server lane and waits until the supervisor has revoked the
    /// active session, joined it, and cleared its public connection state.
    pub async fn disable_and_wait(&self) -> Result<()> {
        let previous = self
            .requested_retirement
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |revision| {
                revision.checked_add(1)
            })
            .expect("ED2K server retirement revision exhausted");
        let revision = previous + 1;
        self.enabled.store(false, Ordering::SeqCst);
        self.wake.notify_one();

        let mut retired = self.retired.clone();
        if *retired.borrow() < revision {
            retired
                .wait_for(|completed| *completed >= revision)
                .await
                .map_err(|_| anyhow!("ED2K server supervisor closed before retirement ack"))?;
        }
        Ok(())
    }
}

impl Ed2kServerControlReceiver {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    pub async fn wait_for_wake(&self) {
        self.wake.notified().await;
    }

    /// Acknowledge every disable revision observed after retirement completed.
    /// Returns false when the lane was re-enabled before acknowledgment.
    pub fn acknowledge_disabled(&self) -> bool {
        if self.is_enabled() {
            return false;
        }
        let revision = self.requested_retirement.load(Ordering::SeqCst);
        self.retired.send_replace(revision);
        true
    }

    pub(super) fn enabled_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.enabled)
    }

    pub(super) fn wake_signal(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn disable_waits_for_matching_retirement_ack() {
        let (control, receiver) = ed2k_server_control_channel(true);
        let disable = tokio::spawn(async move { control.disable_and_wait().await });

        receiver.wait_for_wake().await;
        assert!(!disable.is_finished());
        assert!(receiver.acknowledge_disabled());

        tokio::time::timeout(Duration::from_secs(1), disable)
            .await
            .expect("disable should finish after retirement acknowledgment")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn each_disable_requires_a_fresh_acknowledgment() {
        let (control, receiver) = ed2k_server_control_channel(true);
        let first_control = control.clone();
        let first = tokio::spawn(async move { first_control.disable_and_wait().await });
        receiver.wait_for_wake().await;
        assert!(receiver.acknowledge_disabled());
        first.await.unwrap().unwrap();

        control.enable();
        receiver.wait_for_wake().await;
        let second_control = control.clone();
        let second = tokio::spawn(async move { second_control.disable_and_wait().await });
        receiver.wait_for_wake().await;
        assert!(!second.is_finished());
        assert!(receiver.acknowledge_disabled());
        second.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn disable_fails_if_supervisor_closes_without_acknowledging() {
        let (control, receiver) = ed2k_server_control_channel(true);
        drop(receiver);

        let error = control.disable_and_wait().await.unwrap_err();
        assert!(error.to_string().contains("closed before retirement ack"));
    }
}
