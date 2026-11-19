use super::*;

impl EmulebbCore {
    /// Ephemeral identity shared by this running core and all its handles.
    /// Hosts use it to distinguish a live listener from a stale readiness receipt.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
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
                "downloads".to_string(),
                "downloads.sse".to_string(),
                "downloads.sse.status".to_string(),
                "searches".to_string(),
                "servers".to_string(),
                "sharedFiles".to_string(),
                "libraryRoots".to_string(),
                "uploads".to_string(),
                "logs".to_string(),
                "categoriesRead".to_string(),
                "categoryAssignment".to_string(),
                "categoryCrud".to_string(),
                "renameFile".to_string(),
                "downloadParts".to_string(),
                "fileRatingComment".to_string(),
                "friends".to_string(),
                "peerControls".to_string(),
            ],
        }
    }

    /// Network/lifecycle state never waits for SQLite, including VPN monitoring.
    pub async fn status(&self) -> Status {
        let kad_running = self.state.lock().await.kad_running;

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
        }
    }

    /// WHY: the bounded runtime cohort is not retained download history. Await
    /// canonical counts under contention and propagate failures rather than
    /// publishing an empty cohort as a successful zero-count response.
    pub async fn transfer_stats(
        &self,
    ) -> Result<emulebb_ed2k::ed2k_transfer::RetainedRead<TransferStats>> {
        self.persistence_owner.check_coherent_state()?;
        let counts = self.ed2k_transfers.transfer_counts().await?;
        self.persistence_owner.check_coherent_state()?;
        counts.try_project(4096, |counts| {
            Ok(TransferStats {
                active: counts.active,
                completed: counts.completed,
                total: counts.total,
            })
        })
    }
}
