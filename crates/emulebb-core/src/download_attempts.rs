//! Synchronous ownership of selected job attempts, independent of task handles.
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::{JobId, JobToken};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

const MAX_VERIFICATIONS: usize = 2;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Active,
    Preparation,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionDenied {
    Duplicate,
    Busy,
    Exhausted,
}
#[derive(Default)]
pub(crate) struct DownloadAttemptControl {
    state: Mutex<State>,
    pub(crate) changed: tokio::sync::Notify,
}
#[derive(Default)]
struct State {
    ordinary_limit: Option<u32>,
    window: crate::download_admission::AdmissionWindow,
    nonce: u64,
    entries: HashMap<JobId, Entry>,
    verifications: HashMap<JobId, VerificationEntry>,
}
struct VerificationEntry {
    token: JobToken,
    hash: Ed2kHash,
    nonce: u64,
}

impl State {
    fn active_limit(&self) -> usize {
        self.ordinary_limit.map_or(self.window.active, |limit| {
            (limit as usize).min(self.window.active)
        })
    }

    fn rare_active_limit(&self) -> usize {
        let extra = self
            .ordinary_limit
            .map_or(self.window.burst, |limit| (limit as usize).div_ceil(4))
            .min(self.window.burst);
        self.active_limit()
            .saturating_add(extra)
            .min(self.window.total)
    }
}

/// At most two operator rechecks exclude scheduler selection, including while
/// an older network execution drains. No queued job owns a waiter or task.
pub(crate) struct DownloadVerificationGuard {
    control: Arc<DownloadAttemptControl>,
    id: JobId,
    hash: Ed2kHash,
    nonce: u64,
}
struct Entry {
    kind: Kind,
    token: JobToken,
    hash: Ed2kHash,
    nonce: u64,
    cancel: CancellationToken,
    wake: Arc<tokio::sync::Notify>,
}

/// This guard owns only scalar controls. Drop needs neither an async runtime,
/// Core state nor the task set that is currently executing the attempt.
pub(crate) struct DownloadAttemptGuard {
    control: Arc<DownloadAttemptControl>,
    token: JobToken,
    nonce: u64,
    cancel: CancellationToken,
    wake: Arc<tokio::sync::Notify>,
}
impl DownloadAttemptControl {
    pub(crate) fn apply_admission_window(
        &self,
        window: crate::download_admission::AdmissionWindow,
    ) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).window = window;
    }

    pub(crate) fn admission_counts(&self) -> (crate::download_admission::AdmissionWindow, usize) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (
            state.window,
            state
                .entries
                .values()
                .filter(|entry| entry.kind == Kind::Active)
                .count(),
        )
    }
    pub(crate) fn with_limit(limit: Option<u32>) -> Self {
        let control = Self::default();
        control.apply_concurrency_limit(limit);
        control
    }
    /// A lower ceiling drains admissions; existing attempt guards stay owned.
    pub(crate) fn apply_concurrency_limit(&self, limit: Option<u32>) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .ordinary_limit = limit;
        self.changed.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn try_enter(
        self: &Arc<Self>,
        token: JobToken,
        hash: Ed2kHash,
    ) -> Result<DownloadAttemptGuard, AdmissionDenied> {
        self.enter(token, hash, Kind::Active)
    }
    pub(crate) fn try_prepare(
        self: &Arc<Self>,
        token: JobToken,
        hash: Ed2kHash,
    ) -> Result<DownloadAttemptGuard, AdmissionDenied> {
        self.enter(token, hash, Kind::Preparation)
    }
    pub(crate) fn available(&self) -> (usize, usize) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let active = state
            .entries
            .values()
            .filter(|entry| entry.kind == Kind::Active)
            .count();
        let total_free = state.window.total.saturating_sub(state.entries.len());
        (
            state.active_limit().saturating_sub(active).min(total_free),
            state
                .window
                .preparing
                .saturating_sub(state.entries.len() - active)
                .min(total_free),
        )
    }
    fn enter(
        self: &Arc<Self>,
        token: JobToken,
        hash: Ed2kHash,
        kind: Kind,
    ) -> Result<DownloadAttemptGuard, AdmissionDenied> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state
            .verifications
            .values()
            .any(|entry| entry.token.job_id == token.job_id || entry.hash == hash)
        {
            return Err(AdmissionDenied::Busy);
        }
        if state.entries.contains_key(&token.job_id) {
            return Err(AdmissionDenied::Duplicate);
        }
        // WHY: a removed job may still own protocol source leases for this
        // content. Its actual task must retire before a new job reuses them.
        let limit = if kind == Kind::Active {
            state.active_limit()
        } else {
            state.window.preparing
        };
        if state
            .entries
            .values()
            .filter(|entry| entry.kind == kind)
            .count()
            >= limit
            || state.entries.len() >= state.window.total
            || state.entries.values().any(|entry| entry.hash == hash)
        {
            return Err(AdmissionDenied::Busy);
        }
        let nonce = state
            .nonce
            .checked_add(1)
            .ok_or(AdmissionDenied::Exhausted)?;
        state.nonce = nonce;
        let cancel = CancellationToken::new();
        let wake = Arc::new(tokio::sync::Notify::new());
        state.entries.insert(
            token.job_id,
            Entry {
                kind,
                token,
                hash,
                nonce,
                cancel: cancel.clone(),
                wake: Arc::clone(&wake),
            },
        );
        Ok(DownloadAttemptGuard {
            control: Arc::clone(self),
            token,
            nonce,
            cancel,
            wake,
        })
    }
    pub(crate) fn owns(&self, token: JobToken) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .get(&token.job_id)
            .is_some_and(|entry| {
                entry.kind == Kind::Active && entry.token == token && !entry.cancel.is_cancelled()
            })
    }
    /// Preparation may record peer observations, but never grants payload or
    /// passive-request authority (which continues to require `owns`).
    pub(crate) fn owns_observation(&self, token: JobToken) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .get(&token.job_id)
            .is_some_and(|entry| entry.token == token && !entry.cancel.is_cancelled())
    }
    /// Capture authority before a passive request starts network work.
    pub(crate) fn selected_token(&self, hash: [u8; 16]) -> Option<JobToken> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .values()
            .find(|entry| {
                entry.kind == Kind::Active && entry.hash.0 == hash && !entry.cancel.is_cancelled()
            })
            .map(|entry| entry.token)
    }
    pub(crate) fn snapshot(&self) -> Vec<(JobToken, bool)> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .values()
            .filter(|entry| entry.kind == Kind::Active)
            .map(|entry| (entry.token, entry.cancel.is_cancelled()))
            .collect()
    }
    /// Wake only a currently selected execution. Queued rows own no notifier.
    pub(crate) fn wake(&self, token: JobToken) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state
            .entries
            .get(&token.job_id)
            .filter(|entry| entry.token == token && !entry.cancel.is_cancelled())
        {
            entry.wake.notify_one();
        }
    }
    pub(crate) fn cancel(&self, job_id: JobId) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state.entries.get(&job_id) {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }
    /// A delayed execution result may cancel only its own generation. User
    /// actions use job-level cancellation; callbacks carry captured authority.
    pub(crate) fn cancel_execution(&self, token: JobToken) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state
            .entries
            .get(&token.job_id)
            .filter(|entry| entry.token == token)
        {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }
    /// Operator controls retire executions no newer than their durable cut.
    /// A newer explicit start must survive a delayed stop's publication.
    pub(crate) fn cancel_through(&self, token: JobToken) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state
            .entries
            .get(&token.job_id)
            .filter(|entry| entry.token.generation <= token.generation)
        {
            entry.cancel.cancel();
            true
        } else {
            false
        }
    }
    pub(crate) fn cancel_all(&self) {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        for entry in state.entries.values() {
            entry.cancel.cancel();
        }
    }

    pub(crate) fn try_verify(
        self: &Arc<Self>,
        token: JobToken,
        hash: Ed2kHash,
    ) -> Result<DownloadVerificationGuard, AdmissionDenied> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.verifications.contains_key(&token.job_id) {
            return Err(AdmissionDenied::Duplicate);
        }
        if state.verifications.len() >= MAX_VERIFICATIONS
            || state.verifications.values().any(|entry| entry.hash == hash)
        {
            return Err(AdmissionDenied::Busy);
        }
        let nonce = state
            .nonce
            .checked_add(1)
            .ok_or(AdmissionDenied::Exhausted)?;
        state.nonce = nonce;
        state
            .verifications
            .insert(token.job_id, VerificationEntry { token, hash, nonce });
        for entry in state
            .entries
            .values()
            .filter(|entry| entry.token.job_id == token.job_id || entry.hash == hash)
        {
            entry.cancel.cancel();
        }
        Ok(DownloadVerificationGuard {
            control: Arc::clone(self),
            id: token.job_id,
            hash,
            nonce,
        })
    }

    pub(crate) fn verifications(&self) -> Vec<JobToken> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .verifications
            .values()
            .map(|entry| entry.token)
            .collect()
    }
}

impl DownloadVerificationGuard {
    pub(crate) async fn wait_for_execution(&self) {
        loop {
            let changed = self.control.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let draining = self
                .control
                .state
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entries
                .values()
                .any(|entry| entry.token.job_id == self.id || entry.hash == self.hash);
            if !draining {
                return;
            }
            changed.await;
        }
    }
    pub(crate) fn rebind(&self, token: JobToken) {
        let mut state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(entry) = state
            .verifications
            .get_mut(&self.id)
            .filter(|entry| entry.nonce == self.nonce)
        {
            entry.token = token;
        }
    }
}

impl Drop for DownloadVerificationGuard {
    fn drop(&mut self) {
        let mut state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        if state
            .verifications
            .get(&self.id)
            .is_some_and(|entry| entry.nonce == self.nonce)
        {
            state.verifications.remove(&self.id);
        }
        drop(state);
        self.control.changed.notify_waiters();
        self.control.changed.notify_one();
    }
}
impl DownloadAttemptGuard {
    /// Avoid spending a peer reask on readiness the current cohort cannot admit.
    /// Native reservations and promotion still recheck after the network wait.
    pub(crate) fn preparation_has_headroom(&self, construction_starts: usize) -> bool {
        let state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        let active = state
            .entries
            .values()
            .filter(|entry| entry.kind == Kind::Active)
            .count();
        let preparing = state.entries.len() - active;
        state.entries.get(&self.token.job_id).is_some_and(|entry| {
            entry.nonce == self.nonce && entry.token == self.token && !entry.cancel.is_cancelled()
        }) && state.entries.len() <= state.window.total
            && preparing <= state.window.preparing
            && preparing <= construction_starts
    }

    /// Promote the same ownership record before resident/storage admission.
    /// Refusal leaves preparation owned; it never drops/recreates the guard.
    pub(crate) fn promote(&self) -> bool {
        self.promote_ready(false)
    }

    /// Rarity only relaxes the ordinary count ceiling. The same owner and
    /// cohort accounting remain in force; Native admission still owns bytes.
    pub(crate) fn promote_ready(&self, rare: bool) -> bool {
        let mut state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = state.entries.get(&self.token.job_id).filter(|entry| {
            entry.nonce == self.nonce && entry.token == self.token && !entry.cancel.is_cancelled()
        }) else {
            return false;
        };
        if entry.kind == Kind::Active {
            return true;
        }
        let active = state
            .entries
            .values()
            .filter(|entry| entry.kind == Kind::Active)
            .count();
        let limit = if rare {
            state.rare_active_limit()
        } else {
            state.active_limit()
        };
        if active >= limit || state.entries.len() > state.window.total {
            return false;
        }
        state
            .entries
            .get_mut(&self.token.job_id)
            .expect("owned preparation")
            .kind = Kind::Active;
        true
    }

    pub(crate) fn token(&self) -> JobToken {
        self.token
    }

    pub(crate) fn hash(&self) -> Ed2kHash {
        self.control
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entries
            .get(&self.token.job_id)
            .filter(|entry| entry.nonce == self.nonce)
            .expect("owned download attempt disappeared")
            .hash
    }

    /// Bind the reserved slot to the generation issued by initial allocation.
    /// Cancellation survives this handoff; no later start can revive this guard.
    pub(crate) fn rebind(&mut self, token: JobToken) -> bool {
        if token.job_id != self.token.job_id || token.generation < self.token.generation {
            return false;
        }
        let mut state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(entry) = state
            .entries
            .get_mut(&token.job_id)
            .filter(|entry| entry.nonce == self.nonce && entry.token == self.token)
        else {
            return false;
        };
        // WHY: native Begin may commit before cancellation wins its reply.
        // Remember that exact generation for retirement without reactivating
        // the canceled attempt or granting its callbacks new authority.
        let active = !entry.cancel.is_cancelled();
        entry.token = token;
        self.token = token;
        active
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub(crate) async fn notified(&self) {
        self.wake.notified().await;
    }
}
impl Drop for DownloadAttemptGuard {
    fn drop(&mut self) {
        let mut state = self.control.state.lock().unwrap_or_else(|p| p.into_inner());
        if state
            .entries
            .get(&self.token.job_id)
            .is_some_and(|entry| entry.nonce == self.nonce)
        {
            state.entries.remove(&self.token.job_id);
            drop(state);
            self.control.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests;
