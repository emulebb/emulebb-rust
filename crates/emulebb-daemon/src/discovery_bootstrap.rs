use std::{future::Future, time::Duration};

use anyhow::{Context, Result, ensure};
use emulebb_core::{DiscoveryUrlPolicy, SERVER_MET_MAX_BYTES};
use emulebb_ed2k::ed2k_server::parse_server_met;
use emulebb_metadata::{
    DiscoveryDomain, DiscoveryInitializationStatus, MetadataServer, MetadataStore,
};
use reqwest::Client;
use tracing::{info, warn};

pub(crate) const TRUSTED_SERVER_MET_URLS: &[&str] = &[
    "https://upd.emule-security.org/server.met",
    "https://emuling.gitlab.io/server.met",
    "https://www.gruk.org/server.met",
];
pub(crate) const TRUSTED_NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";

const DISCOVERY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Seeds discovery data only where the profile has no usable data already.
pub(crate) async fn seed_empty_discovery(metadata: &MetadataStore) -> Result<()> {
    let client = discovery_client_builder()?
        .build()
        .context("failed to create first-run discovery HTTP client")?;

    seed_empty_servers(metadata, &client).await
}

pub(crate) async fn seed_pending_kad(core: &emulebb_core::EmulebbCore) -> Result<()> {
    seed_kad_with(core, || {
        core.initialize_kad_discovery_url(TRUSTED_NODES_DAT_URL)
    })
    .await
}

async fn seed_kad_with<F, Fut>(core: &emulebb_core::EmulebbCore, fetch: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<usize>>,
{
    if !core.kad_discovery_pending().await? {
        return Ok(());
    }
    match fetch().await {
        Ok(count) if count > 0 => info!(count, "Kad discovery initialized"),
        Ok(_) => info!("Kad discovery source admitted no contacts"),
        Err(error) => warn!(%error, "Kad discovery import failed; retrying next launch"),
    }
    Ok(())
}

fn discovery_client_builder() -> Result<reqwest::ClientBuilder> {
    Ok(
        emulebb_core::discovery_client_builder(DiscoveryUrlPolicy::TrustedBootstrap)?
            .user_agent(concat!("eMuleBB-Rust/", env!("CARGO_PKG_VERSION")))
            .timeout(DISCOVERY_FETCH_TIMEOUT),
    )
}

async fn seed_empty_servers(metadata: &MetadataStore, client: &Client) -> Result<()> {
    seed_servers_with(metadata, |url| async move {
        fetch_bounded(client, url, SERVER_MET_MAX_BYTES).await
    })
    .await
}

async fn seed_servers_with<F, Fut>(metadata: &MetadataStore, fetch: F) -> Result<()>
where
    F: Fn(&'static str) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>>,
{
    if metadata.discovery_initialization_status(DiscoveryDomain::Servers)?
        == DiscoveryInitializationStatus::Initialized
    {
        return Ok(());
    }

    for url in TRUSTED_SERVER_MET_URLS {
        match fetch(url).await {
            Ok(bytes) => match seed_servers_from_bytes(metadata, &bytes) {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            url,
                            count, "initialized server list from trusted server.met"
                        );
                    }
                    return Ok(());
                }
                Err(error) => warn!(url, %error, "trusted server.met validation failed"),
            },
            Err(error) => warn!(url, %error, "trusted server.met download failed"),
        }
    }
    warn!("empty server list remains available for manual WebUI import");
    Ok(())
}

fn seed_servers_from_bytes(metadata: &MetadataStore, bytes: &[u8]) -> Result<usize> {
    let servers = parse_server_met(bytes).context("failed to parse server.met")?;
    ensure!(!servers.is_empty(), "server.met has no usable entries");
    let servers: Vec<MetadataServer> = servers
        .into_iter()
        .map(|server| MetadataServer {
            address: server.ip.to_string(),
            port: server.port,
            name: server.name.unwrap_or_default(),
            description: String::new(),
            server_priority: "normal".to_string(),
            static_server: false,
            enabled: true,
            failed_count: 0,
            ping_ms: None,
            users: 0,
            files: 0,
            max_users: 0,
            low_id_users: 0,
            soft_files: 0,
            hard_files: 0,
            version: String::new(),
            dynamic_host: String::new(),
            auxiliary_ports: Vec::new(),
            obfuscation_tcp_port: None,
            obfuscation_udp_port: None,
            udp_flags: None,
            udp_key: None,
            udp_key_ip: None,
        })
        .collect();
    if metadata.initialize_servers_if_pending(&servers)? {
        Ok(servers.len())
    } else {
        Ok(0)
    }
}

async fn fetch_bounded(client: &Client, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    emulebb_core::fetch_discovery_bytes(
        client,
        url,
        max_bytes,
        DISCOVERY_FETCH_TIMEOUT,
        DiscoveryUrlPolicy::TrustedBootstrap,
    )
    .await
}

#[cfg(test)]
mod tests {
    mod tls_fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../emulebb-core/tests/support/tls_fixture.rs"
        ));
    }

    #[tokio::test]
    async fn discovery_https_uses_verified_client_and_rejects_private_ca() {
        let (address, server) = tls_fixture::serve(tls_fixture::VALID).await;
        let client = super::discovery_client_builder()
            .unwrap()
            .no_proxy()
            .timeout(tls_fixture::TIMEOUT)
            .build()
            .unwrap();
        let error = super::fetch_bounded(&client, &format!("https://{address}/"), 2)
            .await
            .unwrap_err();
        let request_error = error.downcast_ref::<reqwest::Error>().unwrap();
        assert!(!request_error.is_timeout());
        assert_eq!(
            server.await.unwrap(),
            tls_fixture::Outcome::CertificateRejected
        );
    }

    use super::*;

    fn one_server_met() -> Vec<u8> {
        let mut data = vec![0x0e];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[203, 0, 113, 8]);
        data.extend_from_slice(&4661u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    #[tokio::test]
    async fn pending_kad_retries_on_next_initialization_attempt_only() {
        let core = emulebb_core::EmulebbCore::new_in_memory(
            "test",
            emulebb_index::FileIndex::in_memory().unwrap(),
        )
        .unwrap();
        seed_kad_with(&core, || async {
            Err(anyhow::anyhow!("source unavailable"))
        })
        .await
        .unwrap();
        assert!(core.kad_discovery_pending().await.unwrap());
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[7; 16]);
        bytes.extend_from_slice(&u32::from_be_bytes([192, 0, 2, 7]).to_le_bytes());
        bytes.extend_from_slice(&4672u16.to_le_bytes());
        bytes.extend_from_slice(&4662u16.to_le_bytes());
        bytes.push(0);
        seed_kad_with(&core, || core.import_kad_nodes_bytes(bytes))
            .await
            .unwrap();
        assert!(!core.kad_discovery_pending().await.unwrap());
        seed_kad_with(&core, || async {
            panic!("initialized domain fetched again")
        })
        .await
        .unwrap();
        core.drain_persistence().await.unwrap();
    }

    #[test]
    fn server_seed_populates_an_empty_store() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = MetadataStore::open(temp.path().join("metadata.db")).unwrap();

        assert_eq!(
            seed_servers_from_bytes(&metadata, &one_server_met()).unwrap(),
            1
        );
        let servers = metadata.load_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].endpoint(), "203.0.113.8:4661");
        assert!(servers[0].name.is_empty());
        assert!(servers[0].enabled);
    }

    #[tokio::test]
    async fn existing_server_list_is_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = MetadataStore::open(temp.path().join("metadata.db")).unwrap();
        seed_servers_from_bytes(&metadata, &one_server_met()).unwrap();

        seed_empty_servers(&metadata, &Client::new()).await.unwrap();

        let servers = metadata.load_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].endpoint(), "203.0.113.8:4661");
    }

    #[tokio::test]
    async fn server_initialization_retries_after_reopen_and_uses_first_valid_source() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("metadata.db");
        let metadata = MetadataStore::open(&path).unwrap();
        let calls = AtomicUsize::new(0);
        seed_servers_with(&metadata, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(b"invalid".to_vec()) }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            metadata
                .discovery_initialization_status(DiscoveryDomain::Servers)
                .unwrap(),
            DiscoveryInitializationStatus::Pending
        );
        assert_eq!(
            metadata
                .discovery_initialization_status(DiscoveryDomain::Kad)
                .unwrap(),
            DiscoveryInitializationStatus::Pending
        );
        // Startup invokes this operation once. Reopen models the next launch;
        // no background retry is scheduled by this operation.
        drop(metadata);
        let metadata = MetadataStore::open(&path).unwrap();
        calls.store(0, Ordering::SeqCst);
        seed_servers_with(&metadata, |url| {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(url, TRUSTED_SERVER_MET_URLS[attempt]);
            async move {
                if attempt < 2 {
                    Ok(b"invalid".to_vec())
                } else {
                    Ok(one_server_met())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(metadata.load_servers().unwrap().len(), 1);
        assert_eq!(
            metadata
                .discovery_initialization_status(DiscoveryDomain::Servers)
                .unwrap(),
            DiscoveryInitializationStatus::Initialized
        );
        seed_servers_with(&metadata, |_| async {
            panic!("initialized list was fetched")
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn concurrent_server_mutation_wins_over_bootstrap_response() {
        let metadata = MetadataStore::in_memory().unwrap();
        let fixture = MetadataStore::in_memory().unwrap();
        seed_servers_from_bytes(&fixture, &one_server_met()).unwrap();
        let mut operator_server = fixture.load_servers().unwrap().remove(0);
        operator_server.enabled = false;
        seed_servers_with(&metadata, |_| {
            metadata.upsert_server(&operator_server).unwrap();
            async {
                let mut bytes = one_server_met();
                bytes[5..9].copy_from_slice(&[203, 0, 113, 10]);
                Ok(bytes)
            }
        })
        .await
        .unwrap();
        let servers = metadata.load_servers().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].endpoint(), "203.0.113.8:4661");
        assert!(!servers[0].enabled);
        assert_eq!(
            metadata
                .discovery_initialization_status(DiscoveryDomain::Servers)
                .unwrap(),
            DiscoveryInitializationStatus::Initialized
        );
        seed_servers_with(&metadata, |_| async { panic!("disabled list was fetched") })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn first_valid_server_source_stops_fallbacks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let metadata = MetadataStore::in_memory().unwrap();
        let calls = AtomicUsize::new(0);
        seed_servers_with(&metadata, |url| {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(url, TRUSTED_SERVER_MET_URLS[attempt]);
            async move {
                if attempt == 0 {
                    Ok(b"invalid".to_vec())
                } else {
                    Ok(one_server_met())
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(metadata.load_servers().unwrap().len(), 1);
    }
}
