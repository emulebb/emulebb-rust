use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use emulebb_core::{Ed2kNetworkConfig, EmulebbCore};
use emulebb_ed2k::config::Ed2kConfig;
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
    pub bind_addr: SocketAddr,
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
            bind_addr: "0.0.0.0:13301".parse().expect("valid default REST bind"),
            api_key: "change-me".to_string(),
        }
    }
}

impl DaemonConfig {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
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

    pub fn ed2k_network_config(&self) -> Result<Option<Ed2kNetworkConfig>> {
        if self.ed2k.server_entries.is_empty() && self.ed2k.server_endpoints.is_empty() {
            return Ok(None);
        }
        let bind_ip = self.resolve_p2p_bind_ip()?;
        let user_hash = match self.ed2k_user_hash.as_deref() {
            Some(value) => parse_user_hash(value)?,
            None => load_or_create_user_hash(self.ed2k_user_hash_path())?,
        };
        Ok(Some(Ed2kNetworkConfig {
            bind_ip,
            user_hash,
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
    let listener = tokio::net::TcpListener::bind(config.rest.bind_addr).await?;
    info!("emulebb-rust REST listening on {}", config.rest.bind_addr);
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
