use anyhow::{Result, ensure};

use crate::{EmulebbCore, NetworkStatus, kad_status_from_running};

impl EmulebbCore {
    pub async fn set_kad_running(&self, running: bool) {
        self.state.lock().await.kad_running = running;
    }

    pub async fn start_kad(&self) -> Result<NetworkStatus> {
        // The Kademlia network must be enabled (eMule thePrefs.GetNetworkKademlia());
        // when off, Kad is refused / not started.
        ensure!(
            self.state.lock().await.preferences.network_kademlia,
            "Kademlia network is disabled in preferences (networkKademlia=false)"
        );
        let guard = self.vpn_guard_status();
        if guard.startup_blocked {
            anyhow::bail!("blocked by VPN guard: {}", guard.startup_block_reason);
        }
        self.set_kad_running(true).await;
        Ok(kad_status_from_running(self.state.lock().await.kad_running))
    }

    pub async fn bootstrap_kad(&self, address: &str, port: u16) -> Result<NetworkStatus> {
        ensure!(!address.trim().is_empty(), "address must not be empty");
        ensure!(port != 0, "port must be between 1 and 65535");
        self.start_kad().await
    }
}
