use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use emulebb_core::EmulebbCore;
use emulebb_index::FileIndex;
use emulebb_rest::{RestConfig, router};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DaemonConfig {
    pub runtime_dir: PathBuf,
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
}

pub async fn run(config: DaemonConfig) -> Result<()> {
    fs::create_dir_all(&config.runtime_dir)
        .with_context(|| format!("failed to create {}", config.runtime_dir.display()))?;
    let index = FileIndex::open(config.index_path())?;
    let core = Arc::new(EmulebbCore::new(
        env!("CARGO_PKG_VERSION"),
        index,
        config.transfer_root(),
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
