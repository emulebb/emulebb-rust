//! Bounded identity notifications. Subscribe and baseline share the publish lock.
use crate::{EmulebbCore, JobId};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DownloadEventResetReason {
    Initial,
    Reconnect,
    Lagged,
    EpochChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DownloadEvent {
    #[serde(rename = "download.changed")]
    Changed {
        id: u64,
        epoch: String,
        #[serde(rename = "downloadId", with = "crate::rest_model_serde::job_id")]
        download_id: JobId,
    },
    #[serde(rename = "download.removed")]
    Removed {
        id: u64,
        epoch: String,
        #[serde(rename = "downloadId", with = "crate::rest_model_serde::job_id")]
        download_id: JobId,
    },
    #[serde(rename = "sync.reset")]
    SyncReset {
        id: u64,
        epoch: String,
        reason: DownloadEventResetReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        missed: Option<u64>,
    },
}
impl DownloadEvent {
    pub fn id(&self) -> u64 {
        match self {
            Self::Changed { id, .. } | Self::Removed { id, .. } | Self::SyncReset { id, .. } => *id,
        }
    }
    pub fn epoch(&self) -> &str {
        match self {
            Self::Changed { epoch, .. }
            | Self::Removed { epoch, .. }
            | Self::SyncReset { epoch, .. } => epoch,
        }
    }
    pub fn cursor(&self) -> String {
        format!("{}:{}", self.epoch(), self.id())
    }
    pub fn sse_name(&self) -> &'static str {
        match self {
            Self::Changed { .. } => "download.changed",
            Self::Removed { .. } => "download.removed",
            Self::SyncReset { .. } => "sync.reset",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadEventDiagnostics {
    pub enabled: bool,
    pub stream: String,
    pub epoch: String,
    pub channel_capacity: usize,
    pub queued_event_count: usize,
    pub subscriber_count: usize,
    pub latest_event_id: u64,
    pub next_event_id: u64,
    pub resume_behavior: String,
}
pub struct DownloadEventSubscription {
    pub receiver: broadcast::Receiver<DownloadEvent>,
    pub reset: DownloadEvent,
}
struct State {
    epoch: String,
    revision: u64,
}
pub(crate) struct DownloadEvents {
    state: Mutex<State>,
    sender: broadcast::Sender<DownloadEvent>,
}
impl Default for DownloadEvents {
    fn default() -> Self {
        let (sender, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            state: Mutex::new(State {
                epoch: uuid::Uuid::new_v4().to_string(),
                revision: 0,
            }),
            sender,
        }
    }
}
impl DownloadEvents {
    pub(crate) fn changed(&self, id: JobId) {
        self.publish(id, false);
    }
    pub(crate) fn removed(&self, id: JobId) {
        self.publish(id, true);
    }
    fn publish(&self, download_id: JobId, removed: bool) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.revision == u64::MAX {
            state.epoch = uuid::Uuid::new_v4().to_string();
            state.revision = 0;
            let _ = self.sender.send(DownloadEvent::SyncReset {
                id: 0,
                epoch: state.epoch.clone(),
                reason: DownloadEventResetReason::EpochChanged,
                missed: None,
            });
        }
        state.revision += 1;
        let id = state.revision;
        let epoch = state.epoch.clone();
        let event = if removed {
            DownloadEvent::Removed {
                id,
                epoch,
                download_id,
            }
        } else {
            DownloadEvent::Changed {
                id,
                epoch,
                download_id,
            }
        };
        let _ = self.sender.send(event);
    }
    fn subscribe(
        &self,
        reason: DownloadEventResetReason,
        missed: Option<u64>,
    ) -> DownloadEventSubscription {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // Publish cannot cross receiver creation/baseline capture. A reset
        // discards the former receiver's older queued events before resuming.
        DownloadEventSubscription {
            receiver: self.sender.subscribe(),
            reset: DownloadEvent::SyncReset {
                id: state.revision,
                epoch: state.epoch.clone(),
                reason,
                missed,
            },
        }
    }
    fn diagnostics(&self) -> DownloadEventDiagnostics {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        DownloadEventDiagnostics {
            enabled: true,
            stream: "sse".into(),
            epoch: state.epoch.clone(),
            channel_capacity: CHANNEL_CAPACITY,
            queued_event_count: self.sender.len(),
            subscriber_count: self.sender.receiver_count(),
            latest_event_id: state.revision,
            next_event_id: state.revision.saturating_add(1),
            resume_behavior: "reset".into(),
        }
    }
}
impl EmulebbCore {
    pub fn subscribe_download_events(
        &self,
        reason: DownloadEventResetReason,
        missed: Option<u64>,
    ) -> DownloadEventSubscription {
        self.download_events.subscribe(reason, missed)
    }
    pub fn download_event_diagnostics(&self) -> DownloadEventDiagnostics {
        self.download_events.diagnostics()
    }
}

#[cfg(test)]
mod tests;
