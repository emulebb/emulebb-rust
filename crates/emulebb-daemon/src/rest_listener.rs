//! Bind the control listener with enough context to distinguish it from P2P failures.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use tokio::net::TcpListener;

pub(crate) async fn bind(address: SocketAddr) -> Result<TcpListener> {
    // WHY: a bare socket error here looks like a P2P/VPN failure during startup;
    // retain its source while identifying the independently configured control listener.
    TcpListener::bind(address).await.with_context(|| {
        format!(
            "failed to bind REST/WebUI TCP listener at {address}; check that the address is local \
             and the port is available, permitted by security software, and outside Windows \
             excluded port ranges; set [rest].bind_addr in {} to select another listener",
            crate::PROFILE_SETTINGS_FILE
        )
    })
}

#[cfg(test)]
mod tests {
    use super::bind;

    #[tokio::test]
    async fn unavailable_listener_identifies_control_address_and_preserves_socket_error() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let address = listener.local_addr().unwrap();
        let error = bind(address).await.unwrap_err();

        assert!(error.to_string().contains(&address.to_string()));
        assert!(error.to_string().contains("REST/WebUI TCP listener"));
        assert!(error.to_string().contains("[rest].bind_addr"));
        assert!(error.to_string().contains(crate::PROFILE_SETTINGS_FILE));
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }
}
