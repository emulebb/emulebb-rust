//! Metadata ownership on a listener-owned socket; no outbound permit or dial.
use super::*;
use crate::ed2k_tcp::hello::DecodedHelloProfile;

pub(in crate::ed2k_tcp) struct AcceptedFileProbeOptions<'a> {
    pub dispatcher: &'a mut Ed2kPeerDispatcher,
    pub peer_addr: SocketAddr,
    pub hello_identity: Ed2kHelloIdentity,
    pub secure_ident: &'a Ed2kSecureIdent,
    pub runtime: &'a Ed2kTransferRuntime,
    pub job_token: emulebb_metadata::JobToken,
    pub file_hash: Ed2kHash,
    pub file_size: u64,
    pub profile: DecodedHelloProfile,
    pub connection_state: DownloadConnectionState,
    pub timeout: Duration,
}

pub(in crate::ed2k_tcp) enum AcceptedFileProbeOutcome {
    Deferred,
    /// No availability proof. The established socket ended or timed out and
    /// must be closed, never reused after a possibly interrupted framed read.
    Incomplete,
    FileNotFound(Box<DownloadConnectionState>),
    Available(Box<AcceptedFilePreparation>),
}

/// Linear metadata and preparation quota. The listener retains socket ownership
/// while this value is inspected or held for an admission decision.
pub(in crate::ed2k_tcp) struct AcceptedFilePreparation {
    metadata: exchange::PreparedPeerMetadata,
    _preparation: tokio::sync::OwnedSemaphorePermit,
}
impl AcceptedFilePreparation {
    pub(in crate::ed2k_tcp) fn availability(&self) -> &Ed2kPeerAvailability {
        &self.metadata.availability
    }

    /// Consume once after admission; release preparation quota while preserving
    /// the packet and security state for the normal session on the same socket.
    pub(in crate::ed2k_tcp) fn into_session(
        mut self: Box<Self>,
        source_exchange_allowed: bool,
    ) -> (PreparedDownloadSession, DownloadConnectionState) {
        self.metadata.state.startup_file_requests_sent = true;
        self.metadata.state.source_exchange_allowed = source_exchange_allowed;
        let connection = self.metadata.state.connection_state();
        (
            PreparedDownloadSession {
                state: self.metadata.state,
                metadata: self.metadata.metadata,
            },
            connection,
        )
    }
}

/// Probe an already accepted/identified connection under the shared preparation
/// quota. No manifest/storage is hydrated. Any error or cancellation requires
/// the caller to close the socket: a cancelled framed read cannot be resumed.
pub(in crate::ed2k_tcp) async fn probe_accepted_file(
    options: AcceptedFileProbeOptions<'_>,
) -> Result<AcceptedFileProbeOutcome> {
    let Some(preparation) = options.runtime.try_admit_source_probe() else {
        return Ok(AcceptedFileProbeOutcome::Deferred);
    };
    let Some(job) = options
        .runtime
        .download_job(options.job_token.job_id)
        .await?
    else {
        return Ok(AcceptedFileProbeOutcome::Deferred);
    };
    anyhow::ensure!(
        job.token == options.job_token
            && job.file_hash == options.file_hash.to_string()
            && job.expected_size_bytes == Some(options.file_size),
        "callback probe differs from captured job"
    );
    drop(job);
    let Some(parts) = options
        .runtime
        .download_verified_parts(options.job_token)
        .await?
    else {
        return Ok(AcceptedFileProbeOutcome::Deferred);
    };
    anyhow::ensure!(
        parts.file_size_bytes == options.file_size,
        "callback probe differs from job geometry"
    );
    let part_count = usize::try_from(options.file_size.div_ceil(ED2K_PART_SIZE))?;
    anyhow::ensure!(
        options.file_size > 0
            && part_count < usize::from(u16::MAX)
            && parts.verified_parts.len() == part_count,
        "invalid callback probe geometry"
    );
    let state = DownloadSessionState::new(
        true,
        true,
        false,
        Some(options.profile.identity.user_hash),
        Some(options.profile.connect_options),
        Some(&options.connection_state),
    );
    let observed = tokio::time::timeout(
        options.timeout,
        exchange_probe(
            options.dispatcher,
            ProbeExchangeOptions {
                peer_addr: options.peer_addr,
                file_hash: options.file_hash,
                file_size: options.file_size,
                verified_parts: &parts.verified_parts,
                job_token: Some(options.job_token),
                hello_identity: options.hello_identity,
                secure_ident: options.secure_ident,
                runtime: options.runtime,
                parts: part_count,
            },
            state,
            Some(options.profile),
        ),
    )
    .await;
    // WHY: a known callback execution already owns an established peer. EOF or
    // timeout settles that attempt as incomplete; neither is availability proof.
    // In particular a timeout may interrupt a frame, so the socket must close.
    let observed = match observed {
        Err(_) => return Ok(AcceptedFileProbeOutcome::Incomplete),
        Ok(result) => result?,
    };
    Ok(match observed {
        ProbeExchangeOutcome::Closed(_) => AcceptedFileProbeOutcome::Incomplete,
        ProbeExchangeOutcome::FileNotFound(connection) => {
            AcceptedFileProbeOutcome::FileNotFound(connection)
        }
        ProbeExchangeOutcome::Available(metadata) => {
            AcceptedFileProbeOutcome::Available(Box::new(AcceptedFilePreparation {
                metadata: *metadata,
                _preparation: preparation,
            }))
        }
    })
}
