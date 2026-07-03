use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, vpn_guard::binding_confirmed};
use emulebb_ed2k::detect_interfaces;
use tokio::time::MissedTickBehavior;

const VPN_GUARD_RUNTIME_MONITOR_INTERVAL: Duration = Duration::from_secs(10);

/// Process exit code used when the runtime VPN Guard trips (binding lost). A distinct
/// non-zero code lets a supervisor/soak distinguish a fail-closed VPN stop from a crash.
const VPN_GUARD_BINDING_LOSS_EXIT_CODE: i32 = 3;

#[derive(Debug, Clone)]
pub(crate) struct VpnGuardRuntimeMonitor {
    bind_ip: Ipv4Addr,
    bind_interface: Option<String>,
    binding_confirmed: Arc<AtomicBool>,
}

pub(crate) fn monitor_config(network: &Ed2kNetworkConfig) -> Option<VpnGuardRuntimeMonitor> {
    if !network.vpn_guard.enabled || !network.vpn_guard.mode.eq_ignore_ascii_case("block") {
        return None;
    }
    network
        .vpn_interface_bound_runtime
        .as_ref()
        .map(|binding_confirmed| VpnGuardRuntimeMonitor {
            bind_ip: network.bind_ip,
            bind_interface: network.p2p_bind_interface.clone(),
            binding_confirmed: Arc::clone(binding_confirmed),
        })
}

pub(crate) async fn run(core: Arc<EmulebbCore>, monitor: VpnGuardRuntimeMonitor) {
    let mut interval = tokio::time::interval(VPN_GUARD_RUNTIME_MONITOR_INTERVAL);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let confirmed = detect_interfaces()
            .map(|interfaces| {
                binding_confirmed(
                    monitor.bind_ip,
                    monitor.bind_interface.as_deref(),
                    &interfaces,
                )
            })
            .unwrap_or(false);
        monitor.binding_confirmed.store(confirmed, Ordering::SeqCst);

        let guard = core.vpn_guard_status();
        if !guard.startup_blocked {
            continue;
        }
        let status = core.status().await;
        if !(status.ed2k.connected || status.kad.running) {
            continue;
        }

        tracing::error!(
            reason = %guard.startup_block_reason,
            "VPN Guard runtime monitor: VPN binding lost — closing P2P and exiting the process (fail-closed)"
        );
        // Fail-closed on runtime VPN binding loss. Close P2P first so nothing is left in
        // flight on a non-tunnel path, then HARD-EXIT the process: keeping the daemon
        // alive (even REST-only) is not leak-proof, because a later config/interface
        // change could resume public P2P off-tunnel. This mirrors eMuleBB-MFC
        // `ExitForVpnGuardFailure` (`::ExitProcess` from the bind-loss watchdog). The
        // supervisor/soak is expected to treat this non-zero exit as a guarded stop.
        core.set_kad_running(false).await;
        let _ = core.disconnect_ed2k().await;
        std::process::exit(VPN_GUARD_BINDING_LOSS_EXIT_CODE);
    }
}
