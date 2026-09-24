use std::{
    fs,
    io::{ErrorKind, Write},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use emulebb_ed2k::ed2k_server::parse_server_met;
use emulebb_kad_dht::bootstrap::parse_nodes_dat;
use emulebb_metadata::{MetadataServer, MetadataStore};
use futures_util::StreamExt;
use reqwest::{Client, redirect::Policy};
use tracing::{info, warn};

pub(crate) const TRUSTED_SERVER_MET_URLS: &[&str] = &[
    "https://upd.emule-security.org/server.met",
    "https://emuling.gitlab.io/server.met",
];
pub(crate) const TRUSTED_NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";
pub(crate) const NODES_DAT_FILE: &str = "nodes.dat";

const SERVER_MET_MAX_BYTES: usize = 4 * 1024 * 1024;
const NODES_DAT_MAX_BYTES: usize = 2 * 1024 * 1024;
const DISCOVERY_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Seeds discovery data only where the profile has no usable data already.
pub(crate) async fn seed_empty_discovery(
    metadata: &MetadataStore,
    profile_dir: &Path,
) -> Result<()> {
    let client = Client::builder()
        .user_agent(concat!("eMuleBB-Rust/", env!("CARGO_PKG_VERSION")))
        .redirect(Policy::limited(3))
        .timeout(DISCOVERY_FETCH_TIMEOUT)
        .build()
        .context("failed to create first-run discovery HTTP client")?;

    let (servers, nodes) = tokio::join!(
        seed_empty_servers(metadata, &client),
        seed_missing_nodes_dat(profile_dir, &client),
    );
    servers?;
    nodes?;
    Ok(())
}

async fn seed_empty_servers(metadata: &MetadataStore, client: &Client) -> Result<()> {
    // A disabled list is still user-owned state. Seed only a truly empty list
    // so startup never silently re-enables servers the user turned off.
    if !metadata.load_servers()?.is_empty() {
        return Ok(());
    }

    for url in TRUSTED_SERVER_MET_URLS {
        match fetch_bounded(client, url, SERVER_MET_MAX_BYTES).await {
            Ok(bytes) => match seed_servers_from_bytes(metadata, &bytes) {
                Ok(count) if count > 0 => {
                    info!(
                        url,
                        count, "seeded empty server list from trusted server.met"
                    );
                    return Ok(());
                }
                Ok(_) => warn!(url, "trusted server.met contained no usable servers"),
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
    for server in &servers {
        metadata.upsert_server(&MetadataServer {
            address: server.ip.to_string(),
            port: server.port,
            name: server
                .name
                .clone()
                .unwrap_or_else(|| format!("{}:{}", server.ip, server.port)),
            description: String::new(),
            server_priority: "normal".to_string(),
            static_server: false,
            enabled: true,
            failed_count: 0,
            ping_ms: None,
            users: 0,
            files: 0,
            soft_files: 0,
            hard_files: 0,
            version: String::new(),
            obfuscation_tcp_port: None,
            udp_flags: None,
        })?;
    }
    Ok(servers.len())
}

async fn seed_missing_nodes_dat(profile_dir: &Path, client: &Client) -> Result<()> {
    let path = profile_dir.join(NODES_DAT_FILE);
    match fs::metadata(&path) {
        Ok(metadata) if metadata.len() > 0 => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    }

    let bytes = match fetch_bounded(client, TRUSTED_NODES_DAT_URL, NODES_DAT_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(url = TRUSTED_NODES_DAT_URL, %error, "trusted nodes.dat download failed");
            return Ok(());
        }
    };
    let contacts = match parse_nodes_dat(&bytes) {
        Ok(contacts) if !contacts.is_empty() => contacts,
        Ok(_) => {
            warn!(
                url = TRUSTED_NODES_DAT_URL,
                "trusted nodes.dat contained no usable contacts"
            );
            return Ok(());
        }
        Err(error) => {
            warn!(url = TRUSTED_NODES_DAT_URL, %error, "trusted nodes.dat validation failed");
            return Ok(());
        }
    };
    write_atomic(&path, &bytes)?;
    info!(
        url = TRUSTED_NODES_DAT_URL,
        count = contacts.len(),
        path = %path.display(),
        "seeded empty Kad discovery data from trusted nodes.dat"
    );
    Ok(())
}

pub(crate) fn load_valid_nodes_dat(profile_dir: &Path) -> Result<Option<Vec<u8>>> {
    let path = profile_dir.join(NODES_DAT_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let contacts = match parse_nodes_dat(&bytes) {
        Ok(contacts) if !contacts.is_empty() => contacts,
        Ok(_) => {
            warn!(path = %path.display(), "persisted nodes.dat has no usable contacts; using Kad fallback seeds");
            return Ok(None);
        }
        Err(error) => {
            warn!(path = %path.display(), %error, "persisted nodes.dat is invalid; using Kad fallback seeds");
            return Ok(None);
        }
    };
    debug_assert!(!contacts.is_empty());
    Ok(Some(bytes))
}

async fn fetch_bounded(client: &Client, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        url.starts_with("https://"),
        "trusted discovery URL must use HTTPS"
    );
    let response = client.get(url).send().await?.error_for_status()?;
    ensure!(
        response.url().scheme() == "https",
        "trusted discovery redirect left HTTPS"
    );
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("response exceeds {max_bytes} bytes");
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            body.len().saturating_add(chunk.len()) <= max_bytes,
            "response exceeds {max_bytes} bytes"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("nodes.dat path has no file name")?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::File::create(&temporary)
        .with_context(|| format!("failed to create temporary {}", temporary.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("failed to write temporary {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync temporary {}", temporary.display()))?;
    drop(file);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_server_met() -> Vec<u8> {
        let mut data = vec![0x0e];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[203, 0, 113, 8]);
        data.extend_from_slice(&4661u16.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    fn one_nodes_dat() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&[0x11; 16]);
        data.extend_from_slice(&u32::from_be_bytes([203, 0, 113, 9]).to_le_bytes());
        data.extend_from_slice(&4672u16.to_le_bytes());
        data.extend_from_slice(&4662u16.to_le_bytes());
        data.push(9);
        data
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

    #[test]
    fn persisted_nodes_dat_is_validated_before_runtime_use() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(NODES_DAT_FILE), one_nodes_dat()).unwrap();

        let bytes = load_valid_nodes_dat(temp.path()).unwrap().unwrap();
        assert_eq!(parse_nodes_dat(&bytes).unwrap().len(), 1);
    }

    #[test]
    fn malformed_persisted_nodes_dat_falls_back_without_startup_failure() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join(NODES_DAT_FILE), b"not nodes.dat").unwrap();

        assert!(load_valid_nodes_dat(temp.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn nonempty_nodes_dat_is_never_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(NODES_DAT_FILE);
        fs::write(&path, b"operator-owned-nodes").unwrap();

        seed_missing_nodes_dat(temp.path(), &Client::new())
            .await
            .unwrap();

        assert_eq!(fs::read(path).unwrap(), b"operator-owned-nodes");
    }
}
