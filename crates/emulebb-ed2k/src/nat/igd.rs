use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use tokio::sync::RwLock;

use super::{
    MappedEndpoint, MappingSpec, NatConfig, NatStatus, PortMappingProvider, UPNP_IGD_BACKEND,
};

#[derive(Debug, Default)]
pub struct IgdPortMappingProvider;

#[async_trait]
impl PortMappingProvider for IgdPortMappingProvider {
    fn name(&self) -> &'static str {
        UPNP_IGD_BACKEND
    }

    async fn reconcile(
        &self,
        _config: &NatConfig,
        _mappings: &[MappingSpec],
        _status: Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        Err(anyhow!("{UPNP_IGD_BACKEND} backend not implemented yet"))
    }

    async fn release(
        &self,
        _config: &NatConfig,
        _mappings: &[MappedEndpoint],
        _status: Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        Err(anyhow!("{UPNP_IGD_BACKEND} backend not implemented yet"))
    }
}
