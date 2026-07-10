use super::*;

impl EmulebbCore {
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

    pub async fn capture_diagnostic_dump(&self, full_memory: bool) -> Result<DiagnosticDumpResult> {
        let dump_dir = self
            .transfer_root
            .parent()
            .unwrap_or(self.transfer_root.as_path())
            .join("diagnostics");
        fs::create_dir_all(&dump_dir).with_context(|| {
            format!(
                "failed to create diagnostics directory {}",
                dump_dir.display()
            )
        })?;

        let stamp = Utc::now().format("%Y%m%dT%H%M%SZ");
        let path = dump_dir.join(format!(
            "emulebb-rust-diagnostic-dump-{stamp}-{}.json",
            Uuid::new_v4()
        ));
        let payload = serde_json::to_vec_pretty(&json!({
            "app": self.app_info(),
            "status": self.status().await,
            "fullMemory": full_memory,
            "kind": "json",
            "capturedAt": Utc::now(),
        }))?;
        fs::write(&path, &payload)
            .with_context(|| format!("failed to write diagnostic dump {}", path.display()))?;
        Ok(DiagnosticDumpResult {
            ok: true,
            path: path.display().to_string(),
            full_memory,
        })
    }

    pub async fn preferences(&self) -> Preferences {
        self.state.lock().await.preferences.clone()
    }

    pub async fn update_preferences(&self, request: PreferencesUpdate) -> Result<Preferences> {
        ensure!(
            !preferences_update_is_empty(&request),
            "preferences PATCH requires at least one preference"
        );
        let preferences = {
            let mut state = self.state.lock().await;
            let mut preferences = state.preferences.clone();
            apply_preferences_update(&mut preferences, request)?;
            profile_state::persist_preferences(&self.metadata_store, &preferences)?;
            state.preferences = preferences.clone();
            preferences
        };
        self.ed2k_transfers
            .apply_upload_queue_policy(&ed2k_upload_queue_policy_from_preferences(
                self.ed2k_network
                    .as_ref()
                    .map(|network| &network.config.upload_queue),
                &preferences,
            ))
            .await;
        self.ed2k_transfers
            .apply_download_limit(ed2k_download_limit_bytes_per_sec_from_preferences(
                &preferences,
            ))
            .await;
        // Apply the global connection budget + per-file source caps live, like
        // the download limit (eMule GetMaxConnections / GetMaxConperFive /
        // GetConfiguredMaxSourcesPerFile preference changes take effect at once).
        self.ed2k_transfers.apply_download_coordinator_config(
            ed2k_download_coordinator_config_from_preferences(&preferences),
        );
        // Apply the credit-system toggle live (eMule thePrefs.GetCreditSystem()):
        // when off, upload scoring uses the neutral 1.0 credit ratio for everyone.
        self.ed2k_transfers
            .set_credit_system_enabled(preferences.credit_system);
        Ok(preferences)
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
                state: "running".to_string(),
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
