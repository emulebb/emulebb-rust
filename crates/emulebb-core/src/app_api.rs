use super::*;

#[derive(Debug)]
struct CommittedSettingsRefreshFailure;

impl std::fmt::Display for CommittedSettingsRefreshFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("settings committed but runtime server-plan refresh failed")
    }
}

impl std::error::Error for CommittedSettingsRefreshFailure {}

impl EmulebbCore {
    /// Identify a saved settings update whose subsequent runtime refresh failed.
    pub fn settings_update_was_committed(error: &anyhow::Error) -> bool {
        error.is::<CommittedSettingsRefreshFailure>()
    }

    pub fn diagnostic_writer_health(&self) -> emulebb_diagnostics::DiagWriterHealth {
        emulebb_diagnostics::writer_health()
    }

    pub fn app_info(&self) -> AppInfo {
        AppInfo {
            name: "eMuleBB".to_string(),
            version: self.version.clone(),
            api_version: "v1".to_string(),
            lifecycle: AppLifecycle {
                state: self.lifecycle_state_name().to_string(),
            },
            capabilities: vec![
                "transfers".to_string(),
                "transfers.sse".to_string(),
                "transfers.sse.status".to_string(),
                "searches".to_string(),
                "servers".to_string(),
                "sharedFiles".to_string(),
                "sharedDirectories".to_string(),
                "uploads".to_string(),
                "logs".to_string(),
                "categoriesRead".to_string(),
                "categoryAssignment".to_string(),
                "categoryCrud".to_string(),
                "renameFile".to_string(),
                "transferDetails".to_string(),
                "fileRatingComment".to_string(),
                "friends".to_string(),
                "peerControls".to_string(),
            ],
        }
    }

    pub async fn core_settings(&self) -> CoreSettings {
        self.state.lock().await.core_settings.clone()
    }

    pub async fn app_settings(&self) -> Result<AppSettings> {
        let _settings_order = self.settings_update_order.lock().await;
        profile_state::load_app_settings(&self.metadata_store)
    }

    pub async fn update_app_settings(&self, mut request: AppSettingsUpdate) -> Result<AppSettings> {
        validate_app_settings_update_paths(&mut request)?;
        // WHY: admit at most one owned completion task. Cancellation while queued
        // writes nothing; cancellation after commit cannot abandon publication.
        let settings_order = Arc::clone(&self.settings_update_order).lock_owned().await;
        let core = self.clone();
        tokio::spawn(async move {
            let _settings_order = settings_order;
            core.update_app_settings_ordered(request).await
        })
        .await
        .context("settings completion task failed; inspect canonical settings")?
    }

    pub async fn update_core_settings(&self, request: CoreSettingsUpdate) -> Result<CoreSettings> {
        ensure!(
            !core_settings_update_is_empty(&request),
            "settings.core PATCH requires at least one core setting"
        );
        Ok(self
            .update_app_settings(AppSettingsUpdate {
                core: Some(request),
                ..AppSettingsUpdate::default()
            })
            .await?
            .core)
    }

    async fn update_app_settings_ordered(&self, request: AppSettingsUpdate) -> Result<AppSettings> {
        let core_changed = request.core.is_some();
        let committed = profile_state::persist_app_settings_update(&self.metadata_store, request)?;
        if core_changed {
            self.state.lock().await.core_settings = committed.core.clone();
            self.publish_committed_core_settings(&committed.core)
                .await?;
        }
        Ok(committed)
    }

    async fn publish_committed_core_settings(&self, core_settings: &CoreSettings) -> Result<()> {
        self.ed2k_transfers
            .apply_upload_queue_policy(&ed2k_upload_queue_policy_from_core_settings(
                self.ed2k_network
                    .as_ref()
                    .map(|network| &network.ed2k.upload_queue),
                core_settings,
            ))
            .await;
        self.ed2k_transfers
            .apply_download_limit(ed2k_download_limit_bytes_per_sec_from_core_settings(
                core_settings,
            ))
            .await;
        // Apply the global connection budget + per-file source caps live, like
        // the download limit (eMule GetMaxConnections / GetMaxConperFive /
        // GetConfiguredMaxSourcesPerFile core setting changes take effect at once).
        self.ed2k_transfers.apply_download_coordinator_config(
            ed2k_download_coordinator_config_from_core_settings(core_settings),
        );
        // Apply the credit-system toggle live (eMule thePrefs.GetCreditSystem()):
        // when off, upload scoring uses the neutral 1.0 credit ratio for everyone.
        self.ed2k_transfers
            .set_credit_system_enabled(core_settings.credit_system);
        if let Err(error) = self.refresh_ed2k_server_connect_plan().await {
            tracing::error!(%error, "settings committed but runtime server-plan refresh failed");
            return Err(error).context(CommittedSettingsRefreshFailure);
        }
        Ok(())
    }

    pub async fn status(&self) -> Status {
        let transfer_counts = self.ed2k_transfers.try_transfer_counts();
        let state = self.state.lock().await;
        let kad_running = state.kad_running;
        let transfer_counts = transfer_counts.unwrap_or_else(|error| {
            tracing::warn!("failed to read persisted ED2K transfer counts: {error}");
            None
        });
        let transfer_counts = transfer_counts.unwrap_or_else(|| {
            tracing::debug!("metadata transfer counts are busy; using in-memory status counts");
            let total = state.transfers.len();
            let mut active = 0;
            let mut completed = 0;
            for transfer in state.transfers.values() {
                match transfer.state.as_str() {
                    "downloading" | "queued" => active += 1,
                    "completed" => completed += 1,
                    _ => {}
                }
            }
            MetadataTransferCounts {
                active,
                completed,
                total,
            }
        });
        drop(state);

        Status {
            lifecycle: AppLifecycle {
                state: self.lifecycle_state_name().to_string(),
            },
            uptime_secs: self.started_at.elapsed().as_secs(),
            kad: self.kad_status(kad_running).await,
            ed2k: self.ed2k_status().await,
            indexing: IndexingStatus {
                enabled: true,
                backend: "sqlite-fts5".to_string(),
            },
            transfers: TransferStats {
                active: transfer_counts.active,
                completed: transfer_counts.completed,
                total: transfer_counts.total,
            },
        }
    }
}

#[cfg(test)]
mod settings_error_tests {
    use super::*;

    #[test]
    fn committed_refresh_classification_uses_the_type_not_the_message() {
        let same_message = anyhow::anyhow!(CommittedSettingsRefreshFailure.to_string());
        assert!(!EmulebbCore::settings_update_was_committed(&same_message));
        let committed = Err::<(), _>(anyhow::anyhow!("synthetic runtime refresh error"))
            .context(CommittedSettingsRefreshFailure)
            .unwrap_err();
        assert!(EmulebbCore::settings_update_was_committed(&committed));
        assert_eq!(
            committed.to_string(),
            CommittedSettingsRefreshFailure.to_string()
        );
        assert!(EmulebbCore::settings_update_was_committed(
            &committed.context("outer context")
        ));
    }
}

fn validate_app_settings_update_paths(request: &mut AppSettingsUpdate) -> Result<()> {
    if let Some(daemon) = &mut request.daemon
        && let Some(emulebb_settings::NullableUpdate::Value(path)) = &mut daemon.incoming_dir
    {
        let text = path.to_string_lossy();
        let trimmed = text.trim();
        ensure!(!trimmed.is_empty(), "incomingDir must not be empty");
        let candidate = long_path(Path::new(trimmed));
        if let Ok(metadata) = fs::metadata(&candidate) {
            ensure!(metadata.is_dir(), "incomingDir is not a directory");
        } else if let Some(parent) = candidate.parent()
            && !parent.as_os_str().is_empty()
            && parent.exists()
        {
            ensure!(parent.is_dir(), "incomingDir parent is not a directory");
        }
        *path = PathBuf::from(normal_path_display(trimmed));
    }
    if let Some(nat) = &request.nat {
        if let Some(backends) = &nat.backend_order {
            for backend in backends {
                ensure!(
                    matches!(
                        backend.as_str(),
                        emulebb_settings::PCP_NATPMP_BACKEND
                            | emulebb_settings::UPNP_MINIUPNPC_BACKEND
                    ),
                    "nat.backendOrder supports only {} and {}; unsupported backend {backend:?}",
                    emulebb_settings::PCP_NATPMP_BACKEND,
                    emulebb_settings::UPNP_MINIUPNPC_BACKEND,
                );
            }
        }
        if let Some(emulebb_settings::NullableUpdate::Value(server_ip)) = &nat.pcp_server_ip {
            server_ip.parse::<Ipv4Addr>().with_context(|| {
                format!("nat.pcpServerIp must be an IPv4 address, got {server_ip:?}")
            })?;
        }
    }
    Ok(())
}
