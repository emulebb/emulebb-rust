//! Closed public reasons derive from live controls, never retained source hints.
use super::*;
use crate::{core_state::CoreState, download_attempts::DownloadAttemptControl};

/// Why a queued download is not currently executing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadWaitingReason {
    Network,
    Sources,
    Resources,
}

pub(crate) struct WaitingObservation {
    network_available: bool,
    ready: Vec<JobToken>,
}

impl WaitingObservation {
    pub(crate) fn capture(
        transport_available: bool,
        state: &CoreState,
        attempts: &DownloadAttemptControl,
    ) -> Self {
        let settings = &state.settings.values().network;
        Self {
            network_available: transport_available
                && (settings.ed2k_enabled || settings.kad_enabled),
            ready: attempts.ready_preparations(),
        }
    }

    pub(super) fn reason(&self, token: JobToken) -> DownloadWaitingReason {
        if !self.network_available {
            DownloadWaitingReason::Network
        } else if self.ready.contains(&token) {
            DownloadWaitingReason::Resources
        } else {
            DownloadWaitingReason::Sources
        }
    }
}

impl EmulebbCore {
    /// Server disconnection alone does not disable direct peer networking.
    pub(crate) fn download_transport_available(&self) -> bool {
        let Some(network) = self.ed2k_network.as_ref() else {
            return false;
        };
        if self.vpn_guard_status().startup_blocked {
            return false;
        }
        let explicit_binding = network
            .p2p_bind_interface
            .as_ref()
            .is_some_and(|name| !name.trim().is_empty())
            || network.p2p_bind_ip.is_some_and(|ip| !ip.is_unspecified());
        // WHY: an interface can disappear without a VPN-policy fault. Reuse the
        // same resolver as network status once per observation, never per job.
        !explicit_binding
            || self
                .network_binding_status()
                .is_some_and(|binding| binding.resolve_result == "resolved")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_missing_interface_is_network_wait_without_a_vpn_fault() {
        let root = crate::unique_runtime_dir("download-waiting-binding");
        let mut core =
            EmulebbCore::new_in_memory("test", crate::FileIndex::in_memory().unwrap()).unwrap();
        super::super::tests::admit(&core, 302, Some(16), DownloadIntent::Started);
        let mut network = crate::tests::test_network_config_with_store(
            &root,
            Default::default(),
            Default::default(),
        );
        network.vpn_guard.enabled = false;
        network.p2p_bind_ip = None;
        core.ed2k_network = Some(std::sync::Arc::new(network.clone()));
        let page = core.download_page(Default::default()).await.unwrap();
        assert_eq!(
            page.downloads[0].waiting_reason,
            Some(DownloadWaitingReason::Sources)
        );
        drop(page);
        network.p2p_bind_interface =
            Some("missing-interface-45bf32c0-5785-4c21-9079-c4f246978653".into());
        core.ed2k_network = Some(std::sync::Arc::new(network));
        assert!(!core.vpn_guard_status().startup_blocked);
        let page = core.download_page(Default::default()).await.unwrap();
        assert_eq!(
            page.downloads[0].waiting_reason,
            Some(DownloadWaitingReason::Network)
        );
    }

    #[tokio::test]
    async fn reasons_use_live_token_evidence_and_only_queued_summaries_expose_them() {
        let core =
            EmulebbCore::new_in_memory("test", crate::FileIndex::in_memory().unwrap()).unwrap();
        let mut job = super::super::tests::admit(&core, 301, Some(16), DownloadIntent::Started);
        let guard = core
            .download_attempts
            .try_prepare(job.token, job.file_hash.parse().unwrap())
            .unwrap();
        let state = core.state.lock().await;
        let observe =
            |transport| WaitingObservation::capture(transport, &state, &core.download_attempts);
        assert_eq!(
            observe(true).reason(job.token),
            DownloadWaitingReason::Sources
        );
        guard.mark_ready(None);
        assert_eq!(
            observe(true).reason(job.token),
            DownloadWaitingReason::Resources
        );
        assert_eq!(
            observe(false).reason(job.token),
            DownloadWaitingReason::Network
        );
        let waiting = observe(true);
        let summary = summary_from_job(job.clone(), None, &[], &[], &waiting);
        assert_eq!(
            summary.waiting_reason,
            Some(DownloadWaitingReason::Resources)
        );
        let mut successor = job.token;
        successor.generation += 1;
        assert_eq!(waiting.reason(successor), DownloadWaitingReason::Sources);
        job.intent = DownloadIntent::Stopped;
        assert!(
            summary_from_job(job, None, &[], &[], &waiting)
                .waiting_reason
                .is_none()
        );
    }
}
