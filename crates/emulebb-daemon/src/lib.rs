use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use emulebb_core::{Ed2kNetworkConfig, EmulebbCore};
use emulebb_ed2k::{config::Ed2kConfig, ed2k_tcp::Ed2kSecureIdent};
use emulebb_index::FileIndex;
use emulebb_rest::{RestConfig, router};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DaemonConfig {
    pub runtime_dir: PathBuf,
    pub p2p_bind_ip: Option<Ipv4Addr>,
    pub ed2k_user_hash: Option<String>,
    pub ed2k: Ed2kConfig,
    pub rest: RestListenerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RestListenerConfig {
    pub bind_addr: Option<SocketAddr>,
    pub api_key: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            runtime_dir: PathBuf::from("runtime"),
            p2p_bind_ip: None,
            ed2k_user_hash: None,
            ed2k: Ed2kConfig::default(),
            rest: RestListenerConfig::default(),
        }
    }
}

impl Default for RestListenerConfig {
    fn default() -> Self {
        Self {
            bind_addr: None,
            api_key: "change-me".to_string(),
        }
    }
}

impl DaemonConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let path = path.context("--config is required; network bindings must come from config")?;
        if !path.exists() {
            bail!("config file does not exist: {}", path.display());
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("failed to parse config {}", path.display()))
    }

    pub fn index_path(&self) -> PathBuf {
        self.runtime_dir.join("index.sqlite")
    }

    pub fn transfer_root(&self) -> PathBuf {
        self.runtime_dir.join("transfers")
    }

    pub fn ed2k_user_hash_path(&self) -> PathBuf {
        self.runtime_dir.join("ed2k-user-hash.hex")
    }

    pub fn ed2k_secure_ident_path(&self) -> PathBuf {
        self.runtime_dir.join("ed2k-secure-ident.pk8")
    }

    pub fn ed2k_network_config(&self) -> Result<Option<Ed2kNetworkConfig>> {
        if self.ed2k.server_entries.is_empty() && self.ed2k.server_endpoints.is_empty() {
            return Ok(None);
        }
        let bind_ip = self.resolve_p2p_bind_ip()?;
        let user_hash = match self.ed2k_user_hash.as_deref() {
            Some(value) => parse_user_hash(value)?,
            None => load_or_create_user_hash(self.ed2k_user_hash_path())?,
        };
        let secure_ident = Arc::new(Ed2kSecureIdent::load_or_create(
            &self.ed2k_secure_ident_path(),
        )?);
        Ok(Some(Ed2kNetworkConfig {
            bind_ip,
            user_hash,
            secure_ident,
            config: self.ed2k.clone(),
        }))
    }

    fn resolve_p2p_bind_ip(&self) -> Result<Ipv4Addr> {
        let Some(candidate) = self.p2p_bind_ip else {
            bail!("p2pBindIp is required when ED2K servers are configured");
        };
        if candidate.is_loopback() || candidate.is_unspecified() {
            bail!("ED2K runtime bind IP must be an explicit non-loopback address, got {candidate}");
        }
        Ok(candidate)
    }

    pub fn rest_bind_addr(&self) -> Result<SocketAddr> {
        let Some(candidate) = self.rest.bind_addr else {
            bail!("rest.bindAddr is required");
        };
        match candidate.ip() {
            IpAddr::V4(ip) if ip.is_loopback() || ip.is_unspecified() => {
                bail!(
                    "REST bind address must be an explicit non-loopback address, got {candidate}"
                );
            }
            IpAddr::V6(ip) if ip.is_loopback() || ip.is_unspecified() => {
                bail!(
                    "REST bind address must be an explicit non-loopback address, got {candidate}"
                );
            }
            _ => Ok(candidate),
        }
    }
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    fs::create_dir_all(&config.runtime_dir)
        .with_context(|| format!("failed to create {}", config.runtime_dir.display()))?;
    let index = FileIndex::open(config.index_path())?;
    let ed2k_network = config.ed2k_network_config()?;
    let core = Arc::new(EmulebbCore::new_with_network(
        env!("CARGO_PKG_VERSION"),
        index,
        config.transfer_root(),
        ed2k_network,
    )?);
    let app = router(
        core,
        RestConfig {
            api_key: config.rest.api_key.clone(),
        },
    );
    let rest_bind_addr = config.rest_bind_addr()?;
    let listener = tokio::net::TcpListener::bind(rest_bind_addr).await?;
    info!("emulebb-rust REST listening on {}", rest_bind_addr);
    axum::serve(listener, app).await?;
    Ok(())
}

fn parse_user_hash(value: &str) -> Result<[u8; 16]> {
    let decoded = hex::decode(value.trim()).context("failed to decode ed2kUserHash")?;
    let bytes: [u8; 16] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("ed2kUserHash must be 16 bytes / 32 hex characters"))?;
    if bytes == [0; 16] {
        bail!("ed2kUserHash must not be all zeroes");
    }
    Ok(bytes)
}

fn load_or_create_user_hash(path: PathBuf) -> Result<[u8; 16]> {
    if path.exists() {
        return parse_user_hash(
            &fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?,
        );
    }
    let bytes = *uuid::Uuid::new_v4().as_bytes();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, hex::encode(bytes))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_server(runtime_dir: PathBuf, p2p_bind_ip: Option<Ipv4Addr>) -> DaemonConfig {
        let mut ed2k = Ed2kConfig::default();
        ed2k.server_endpoints = vec!["192.0.2.20:4661".to_string()];
        DaemonConfig {
            runtime_dir,
            p2p_bind_ip,
            ed2k,
            ..DaemonConfig::default()
        }
    }

    fn config_with_rest_bind(runtime_dir: PathBuf, bind_addr: Option<SocketAddr>) -> DaemonConfig {
        DaemonConfig {
            runtime_dir,
            rest: RestListenerConfig {
                bind_addr,
                ..RestListenerConfig::default()
            },
            ..DaemonConfig::default()
        }
    }

    #[test]
    fn load_requires_explicit_config_path() {
        let error = DaemonConfig::load(None).unwrap_err().to_string();

        assert!(error.contains("--config is required"));
    }

    #[test]
    fn load_requires_existing_config_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("missing.toml");

        let error = DaemonConfig::load(Some(path)).unwrap_err().to_string();

        assert!(error.contains("config file does not exist"));
    }

    #[test]
    fn rest_bind_addr_requires_configured_address() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_rest_bind(temp.path().to_path_buf(), None);

        let error = config.rest_bind_addr().unwrap_err().to_string();

        assert!(error.contains("rest.bindAddr is required"));
    }

    #[test]
    fn rest_bind_addr_rejects_loopback_address() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_rest_bind(
            temp.path().to_path_buf(),
            Some("127.0.0.1:13301".parse().unwrap()),
        );

        let error = config.rest_bind_addr().unwrap_err().to_string();

        assert!(error.contains("explicit non-loopback address"));
    }

    #[test]
    fn rest_bind_addr_rejects_wildcard_address() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_rest_bind(
            temp.path().to_path_buf(),
            Some("0.0.0.0:13301".parse().unwrap()),
        );

        let error = config.rest_bind_addr().unwrap_err().to_string();

        assert!(error.contains("explicit non-loopback address"));
    }

    #[test]
    fn rest_bind_addr_accepts_configured_non_loopback_address() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_rest_bind(
            temp.path().to_path_buf(),
            Some("192.0.2.10:13301".parse().unwrap()),
        );

        assert_eq!(
            config.rest_bind_addr().unwrap(),
            "192.0.2.10:13301".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn ed2k_network_config_is_absent_without_servers() {
        let temp = tempfile::tempdir().unwrap();
        let config = DaemonConfig {
            runtime_dir: temp.path().to_path_buf(),
            ..DaemonConfig::default()
        };

        assert!(config.ed2k_network_config().unwrap().is_none());
    }

    #[test]
    fn ed2k_network_config_requires_configured_bind_ip() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_server(temp.path().to_path_buf(), None);

        let error = config.ed2k_network_config().unwrap_err().to_string();
        assert!(error.contains("p2pBindIp is required"));
    }

    #[test]
    fn ed2k_network_config_rejects_loopback_bind_ip() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_server(temp.path().to_path_buf(), Some(Ipv4Addr::LOCALHOST));

        let error = config.ed2k_network_config().unwrap_err().to_string();
        assert!(error.contains("explicit non-loopback address"));
    }

    #[test]
    fn ed2k_network_config_accepts_configured_non_loopback_bind_ip() {
        let temp = tempfile::tempdir().unwrap();
        let config = config_with_server(
            temp.path().to_path_buf(),
            Some("192.0.2.10".parse().unwrap()),
        );

        let network = config.ed2k_network_config().unwrap().unwrap();

        assert_eq!(network.bind_ip, "192.0.2.10".parse::<Ipv4Addr>().unwrap());
        assert!(config.ed2k_user_hash_path().is_file());
        assert!(config.ed2k_secure_ident_path().is_file());
    }
}
