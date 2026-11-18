//! Ephemeral listener discovery for package health checks; never configuration.
use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

const FILE_NAME: &str = ".emulebb-rest-listener.json";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    bound_address: SocketAddr,
    probe_host: String,
    probe_port: u16,
    instance_id: &'a str,
}

pub(crate) struct ListenerReceipt {
    path: PathBuf,
}

impl ListenerReceipt {
    /// Atomically publish the actual listener only while its profile is owned.
    /// A per-instance HTTP token makes receipts left by process death unusable
    /// against a different listener, even if its address or PID is reused.
    pub(crate) fn publish(profile: &Path, bound: SocketAddr, instance_id: &str) -> Result<Self> {
        let path = profile.join(FILE_NAME);
        let receipt = Receipt {
            bound_address: bound,
            probe_host: probe_host(bound),
            probe_port: bound.port(),
            instance_id,
        };
        let mut temporary = tempfile::NamedTempFile::new_in(profile)?;
        serde_json::to_writer(&mut temporary, &receipt)?;
        // WHY: consumers must see a whole receipt, never a partly written address
        // paired with another instance's token. This runtime output needs atomic
        // visibility, not durable publication across a machine crash.
        temporary
            .persist(&path)
            .map_err(|error| error.error)
            .context("failed to publish REST listener receipt")?;
        Ok(Self { path })
    }
}

impl Drop for ListenerReceipt {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "failed to remove REST listener receipt");
        }
    }
}

fn probe_host(bound: SocketAddr) -> String {
    match bound {
        SocketAddr::V4(address) => if address.ip().is_unspecified() {
            Ipv4Addr::LOCALHOST
        } else {
            *address.ip()
        }
        .to_string(),
        SocketAddr::V6(address) => {
            let ip = if address.ip().is_unspecified() {
                Ipv6Addr::LOCALHOST
            } else {
                *address.ip()
            };
            if address.scope_id() == 0 {
                ip.to_string()
            } else {
                format!("{ip}%{}", address.scope_id())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[tokio::test]
    async fn receipt_uses_bound_ephemeral_port_and_is_retired_with_listener_owner() {
        let root = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let path = root.path().join(FILE_NAME);
        fs::write(&path, b"interrupted old receipt").unwrap();
        let receipt = ListenerReceipt::publish(root.path(), bound, "instance-a").unwrap();
        let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["boundAddress"], bound.to_string());
        assert_eq!(value["probeHost"], "127.0.0.1");
        assert_eq!(value["probePort"], bound.port());
        assert_ne!(bound.port(), 0);
        assert_eq!(value["instanceId"], "instance-a");
        drop(receipt);
        assert!(!path.exists());
    }

    #[test]
    fn wildcard_probes_use_loopback_and_specific_ipv6_keeps_its_scope() {
        for (bound, expected) in [
            ("0.0.0.0:1234", "127.0.0.1"),
            ("[::]:1234", "::1"),
            ("127.0.0.2:1234", "127.0.0.2"),
            ("[fe80::1%3]:1234", "fe80::1%3"),
        ] {
            assert_eq!(probe_host(bound.parse().unwrap()), expected);
        }
    }
}
