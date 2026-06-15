//! Active eD2k peer download support.

pub(in crate::ed2k_tcp) mod aich_request;
pub(in crate::ed2k_tcp) mod blocks;
pub(in crate::ed2k_tcp) mod session;
pub(in crate::ed2k_tcp) mod startup;
pub(in crate::ed2k_tcp) mod window;

pub(in crate::ed2k_tcp) use aich_request::{AichRecoveryRequestState, pump_aich_recovery_requests};
pub(in crate::ed2k_tcp) use blocks::{
    PendingCompressedPart, ReadyDownloadBlocks, flush_buffered_download_prefixes,
    flush_ready_download_blocks, reconcile_download_manifest_metadata,
};
pub use session::Ed2kPeerDownloadOutcome;
pub(in crate::ed2k_tcp) use session::{DownloadSessionOptions, drive_download_session};
pub use startup::{Ed2kPeerDownloadOptions, download_file_from_peer};
pub(in crate::ed2k_tcp) use window::{
    ActiveDownloadPiece, DownloadRequestWindowState, PendingPartRequest,
    next_download_read_timeout, pump_download_request_window,
};
#[cfg(test)]
pub(in crate::ed2k_tcp) use window::{DownloadWindowLimits, select_download_window_limits};
