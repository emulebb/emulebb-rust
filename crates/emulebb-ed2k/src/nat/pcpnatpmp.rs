use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Mutex as StdMutex, mpsc},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use emulebb_pcpnatpmp::{
    Client, MappingInfo, MappingRequest, ServerSelection, TransportProtocol as PcpTransportProtocol,
};
use tokio::{sync::RwLock, task};
use tracing::{info, warn};

use super::{
    MappedEndpoint, MappingExposure, MappingSpec, NatConfig, NatStatus, PCP_NATPMP_BACKEND,
    PortMappingProvider, SelectedGateway, TransportProtocol,
};

const PCP_PORT: u16 = 5351;

enum WorkerCommand {
    Reconcile {
        config: NatConfig,
        mappings: Vec<MappingSpec>,
        response: mpsc::SyncSender<std::result::Result<ReconcileOutcome, String>>,
    },
    Release {
        timeout: Duration,
        response: mpsc::SyncSender<()>,
    },
    Shutdown,
}

#[derive(Debug)]
struct ReconcileOutcome {
    gateway: SelectedGateway,
    observed_external_addresses: Vec<String>,
    mappings: Vec<MappedEndpoint>,
    protocol: String,
    preferred_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MappingFingerprint {
    source_ip: Ipv4Addr,
    selection: ServerSelection,
    mappings: Vec<MappingSpec>,
}

#[derive(Default)]
struct WorkerState {
    client: Option<Client>,
    fingerprint: Option<MappingFingerprint>,
    active_mappings: Vec<MappingSpec>,
}

/// PCP v2 / PCP v1 / NAT-PMP v0 provider backed by the shared native fork.
pub struct PcpNatPmpPortMappingProvider {
    sender: mpsc::Sender<WorkerCommand>,
    worker: StdMutex<Option<thread::JoinHandle<()>>>,
}

impl Default for PcpNatPmpPortMappingProvider {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("emulebb-pcpnatpmp".to_string())
            .spawn(move || worker_loop(receiver))
            .expect("failed to start libpcpnatpmp worker");
        Self {
            sender,
            worker: StdMutex::new(Some(worker)),
        }
    }
}

impl Drop for PcpNatPmpPortMappingProvider {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkerCommand::Shutdown);
        if let Ok(mut worker) = self.worker.lock()
            && let Some(worker) = worker.take()
        {
            let _ = worker.join();
        }
    }
}

#[async_trait]
impl PortMappingProvider for PcpNatPmpPortMappingProvider {
    fn name(&self) -> &'static str {
        PCP_NATPMP_BACKEND
    }

    async fn reconcile(
        &self,
        config: &NatConfig,
        mappings: &[MappingSpec],
        status: std::sync::Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        if mappings.is_empty() {
            return Ok(());
        }
        let sender = self.sender.clone();
        let config = config.clone();
        let status_config = config.clone();
        let mappings = mappings.to_vec();
        let outcome = task::spawn_blocking(move || {
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            sender
                .send(WorkerCommand::Reconcile {
                    config,
                    mappings,
                    response: response_tx,
                })
                .map_err(|_| anyhow!("libpcpnatpmp worker stopped"))?;
            response_rx
                .recv()
                .map_err(|_| anyhow!("libpcpnatpmp worker dropped its response"))?
                .map_err(anyhow::Error::msg)
        })
        .await
        .context("libpcpnatpmp reconcile task failed")??;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut guard = status.write().await;
        guard.enabled = true;
        guard.gateway_discovered = true;
        guard.backend = Some(PCP_NATPMP_BACKEND.to_string());
        guard.protocol = Some(outcome.protocol);
        guard.bind_ip = status_config.bind_ip;
        guard.pcp_server_ip = status_config.pcp_server_ip;
        guard.igd_ip = status_config.igd_ip;
        guard.minissdpd_socket = status_config.minissdpd_socket;
        guard.ssdp_local_port = status_config.ssdp_local_port;
        guard.external_ip_override = status_config.external_ip_override;
        guard.gateway = Some(outcome.gateway);
        guard.observed_external_addresses = outcome.observed_external_addresses;
        guard.mappings = outcome.mappings;
        guard.last_refresh_unix_secs = Some(now);
        guard.last_error = outcome.preferred_error;
        Ok(())
    }

    async fn release(
        &self,
        config: &NatConfig,
        _mappings: &[MappedEndpoint],
        status: std::sync::Arc<RwLock<NatStatus>>,
    ) -> Result<()> {
        let sender = self.sender.clone();
        let timeout = Duration::from_secs(config.discovery_timeout_secs.max(1));
        task::spawn_blocking(move || {
            let (response_tx, response_rx) = mpsc::sync_channel(1);
            sender
                .send(WorkerCommand::Release {
                    timeout,
                    response: response_tx,
                })
                .map_err(|_| anyhow!("libpcpnatpmp worker stopped"))?;
            response_rx
                .recv()
                .map_err(|_| anyhow!("libpcpnatpmp worker dropped its release response"))
        })
        .await
        .context("libpcpnatpmp release task failed")??;
        status.write().await.mappings.clear();
        Ok(())
    }
}

fn worker_loop(receiver: mpsc::Receiver<WorkerCommand>) {
    let mut state = WorkerState::default();
    while let Ok(command) = receiver.recv() {
        match command {
            WorkerCommand::Reconcile {
                config,
                mappings,
                response,
            } => {
                let result = reconcile_blocking(&mut state, &config, &mappings)
                    .map_err(|error| format!("{error:#}"));
                let _ = response.send(result);
            }
            WorkerCommand::Release { timeout, response } => {
                if let Some(client) = state.client.as_mut() {
                    client.release_all(timeout);
                }
                state.client = None;
                state.fingerprint = None;
                state.active_mappings.clear();
                let _ = response.send(());
            }
            WorkerCommand::Shutdown => break,
        }
    }
}

fn reconcile_blocking(
    state: &mut WorkerState,
    config: &NatConfig,
    mappings: &[MappingSpec],
) -> Result<ReconcileOutcome> {
    let source_ip = source_ip(config, mappings)?;
    let selection = match config.pcp_server_ip.as_deref() {
        Some(server) => ServerSelection::Explicit(SocketAddrV4::new(
            server
                .parse::<Ipv4Addr>()
                .with_context(|| format!("invalid nat.pcpServerIp {server:?}"))?,
            PCP_PORT,
        )),
        None => ServerSelection::Automatic,
    };
    let fingerprint = MappingFingerprint {
        source_ip,
        selection,
        mappings: mappings.to_vec(),
    };
    let timeout = Duration::from_secs(config.discovery_timeout_secs.max(1));

    if state.fingerprint.as_ref() == Some(&fingerprint)
        && let Some(client) = state.client.as_mut()
    {
        let renewed = client
            .renew_all(config.lease_duration_secs, timeout)
            .context("failed to renew PCP/NAT-PMP mappings")?;
        return outcome_from_infos(config, &state.active_mappings, renewed, None);
    }

    if let Some(client) = state.client.as_mut() {
        client.release_all(timeout);
    }
    let mut client = Client::new(source_ip, selection)?;
    let mut infos = Vec::with_capacity(mappings.len());
    let mut successful_specs = Vec::with_capacity(mappings.len());
    let mut preferred_errors = Vec::new();

    for exposure in [MappingExposure::Required, MappingExposure::Preferred] {
        for spec in mappings.iter().filter(|spec| spec.exposure == exposure) {
            let internal_ip = match spec.local_addr.ip() {
                IpAddr::V4(ip) if !ip.is_unspecified() => ip,
                IpAddr::V4(_) => source_ip,
                IpAddr::V6(_) => bail!("PCP/NAT-PMP supports only IPv4 mapping addresses"),
            };
            let request = MappingRequest {
                internal_addr: SocketAddrV4::new(internal_ip, spec.local_addr.port()),
                protocol: match spec.protocol {
                    TransportProtocol::Tcp => PcpTransportProtocol::Tcp,
                    TransportProtocol::Udp => PcpTransportProtocol::Udp,
                },
                preferred_external_port: spec
                    .preferred_external_port
                    .unwrap_or_else(|| spec.local_addr.port()),
                lifetime_secs: config.lease_duration_secs,
            };
            match client.map(request, timeout) {
                Ok(info) => {
                    infos.push(info);
                    successful_specs.push(spec.clone());
                }
                Err(error) if exposure == MappingExposure::Preferred => {
                    let message = format!("preferred mapping {} failed: {error:#}", spec.name);
                    warn!("PCP/NAT-PMP {message}");
                    preferred_errors.push(message);
                }
                Err(error) => {
                    client.release_all(Duration::from_millis(250));
                    return Err(error).with_context(|| {
                        format!("required PCP/NAT-PMP mapping {} failed", spec.name)
                    });
                }
            }
        }
    }
    if infos.is_empty() {
        bail!("PCP/NAT-PMP did not establish any mappings");
    }

    let preferred_error = (!preferred_errors.is_empty()).then(|| preferred_errors.join("; "));
    let outcome = outcome_from_infos(config, &successful_specs, infos, preferred_error)?;
    state.client = Some(client);
    state.fingerprint = Some(fingerprint);
    state.active_mappings = successful_specs;
    Ok(outcome)
}

fn outcome_from_infos(
    config: &NatConfig,
    mappings: &[MappingSpec],
    infos: Vec<MappingInfo>,
    preferred_error: Option<String>,
) -> Result<ReconcileOutcome> {
    if mappings.len() != infos.len() {
        bail!(
            "libpcpnatpmp returned {} mappings for {} requests",
            infos.len(),
            mappings.len()
        );
    }
    let first = infos
        .first()
        .ok_or_else(|| anyhow!("libpcpnatpmp returned no mapping information"))?;
    let protocol = first.protocol_version.as_str().to_string();
    if infos
        .iter()
        .any(|info| info.protocol_version.as_str() != protocol)
    {
        bail!("PCP/NAT-PMP gateway negotiated inconsistent protocol versions");
    }
    let mut external_addresses = Vec::new();
    let mapped = mappings
        .iter()
        .zip(&infos)
        .map(|(spec, info)| {
            let external_ip = config
                .external_ip_override
                .as_deref()
                .map(str::parse)
                .transpose()
                .with_context(|| "invalid nat.externalIpOverride")?
                .unwrap_or_else(|| *info.external_addr.ip());
            let external_ip_text = external_ip.to_string();
            if !external_addresses.contains(&external_ip_text) {
                external_addresses.push(external_ip_text);
            }
            Ok(MappedEndpoint {
                name: spec.name.clone(),
                protocol: spec.protocol,
                local_addr: spec.local_addr,
                external_addr: SocketAddr::V4(SocketAddrV4::new(
                    external_ip,
                    info.external_addr.port(),
                )),
                lease_expires_in_secs: info.lifetime_secs,
                backend: PCP_NATPMP_BACKEND.to_string(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let server_ip = first.server_ip;
    info!(
        "PCP/NAT-PMP reconcile succeeded via {protocol} server {server_ip}: mappings={}",
        mapped.len()
    );
    Ok(ReconcileOutcome {
        gateway: SelectedGateway {
            backend: PCP_NATPMP_BACKEND.to_string(),
            control_url: format!("pcp://{server_ip}:{PCP_PORT}"),
            local_ip: Some(first.internal_addr.ip().to_string()),
            gateway_ip: Some(server_ip.to_string()),
            external_ip: external_addresses.first().cloned(),
        },
        observed_external_addresses: external_addresses,
        mappings: mapped,
        protocol,
        preferred_error,
    })
}

fn source_ip(config: &NatConfig, mappings: &[MappingSpec]) -> Result<Ipv4Addr> {
    if let Some(bind_ip) = config.bind_ip.as_deref() {
        return bind_ip
            .parse::<Ipv4Addr>()
            .with_context(|| format!("nat.bindIp must be an IPv4 address, got {bind_ip:?}"));
    }
    mappings
        .iter()
        .find_map(|mapping| match mapping.local_addr.ip() {
            IpAddr::V4(ip) if !ip.is_unspecified() => Some(ip),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!("PCP/NAT-PMP requires nat.bindIp or an explicit IPv4 mapping address")
        })
}
