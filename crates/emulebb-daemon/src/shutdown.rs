//! Shutdown ownership for a process or an embedded application host.

use tokio::sync::watch;
use tracing::info;

/// A monotonic shutdown request. Dropping every request handle also stops its observers.
#[derive(Debug, Clone)]
pub struct ShutdownRequest(watch::Sender<bool>);

/// Read-only shutdown observation for one embedded runtime.
#[derive(Debug)]
pub struct ShutdownSignal(watch::Receiver<bool>);

impl Default for ShutdownRequest {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self(sender)
    }
}

impl ShutdownRequest {
    /// Retain Stop even when the host has not started its worker yet.
    pub fn request(&self) {
        // WHY: send() discards an update without receivers. An Android Stop
        // can arrive before the queued JNI worker subscribes to this request.
        self.0.send_replace(true);
    }

    /// Observe this request, including Stop retained before subscription.
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal(self.0.subscribe())
    }
}

impl ShutdownSignal {
    /// A lost host is a shutdown request, never permission to keep running.
    pub fn is_requested(&self) -> bool {
        *self.0.borrow() || self.0.has_changed().is_err()
    }
}

async fn wait_for_request(mut receiver: watch::Receiver<bool>) {
    // WHY: changed() alone misses Stop already present before startup or the
    // first poll. Inspect the retained value before waiting for another update.
    loop {
        let requested = *receiver.borrow_and_update();
        if requested {
            break;
        }
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

pub(crate) async fn wait_for_shutdown(
    receiver: watch::Receiver<bool>,
    host: Option<ShutdownSignal>,
) {
    let rest_shutdown = wait_for_request(receiver);
    if let Some(host) = host {
        // Embedded hosts own process signals. In particular, never replace an
        // Android VM's process handlers with the command-line daemon's handlers.
        tokio::select! {
            _ = rest_shutdown => info!("shutdown requested via REST"),
            _ = wait_for_request(host.0) => info!("shutdown requested by host"),
        }
        return;
    }

    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%error, "failed to install SIGTERM handler");
                tokio::select! {
                    _ = rest_shutdown => info!("shutdown requested via REST"),
                    result = tokio::signal::ctrl_c() => match result {
                        Ok(()) => info!("shutdown requested via Ctrl-C"),
                        Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
                    },
                }
                return;
            }
        };
        tokio::select! {
            _ = rest_shutdown => info!("shutdown requested via REST"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => info!("shutdown requested via Ctrl-C"),
                Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
            },
            _ = sigterm.recv() => info!("shutdown requested via SIGTERM"),
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = rest_shutdown => info!("shutdown requested via REST"),
            result = tokio::signal::ctrl_c() => match result {
                Ok(()) => info!("shutdown requested via Ctrl-C"),
                Err(error) => tracing::warn!(%error, "ctrl_c handler error"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn stop_before_subscribe_is_retained() {
        let request = ShutdownRequest::default();
        request.request();
        let signal = request.subscribe();
        assert!(signal.is_requested());
        tokio::time::timeout(Duration::from_secs(1), wait_for_request(signal.0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn losing_the_last_host_handle_stops_the_observer() {
        let request = ShutdownRequest::default();
        let signal = request.subscribe();
        assert!(!signal.is_requested());
        drop(request);
        assert!(signal.is_requested());
        tokio::time::timeout(Duration::from_secs(1), wait_for_request(signal.0))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn hosted_shutdown_honors_an_already_requested_rest_stop() {
        let request = ShutdownRequest::default();
        let (rest, receiver) = watch::channel(true);
        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_shutdown(receiver, Some(request.subscribe())),
        )
        .await
        .unwrap();
        drop(rest);
    }
}
