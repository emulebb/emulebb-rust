//! Scalar callback authority shared by selected and waiting downloads.
use emulebb_ed2k::{
    ed2k_server::Ed2kFoundSource,
    ed2k_transfer::{Ed2kCallbackDownload, Ed2kCallbackPreparationId, Ed2kSourceHint},
};
use emulebb_kad_proto::Ed2kHash;
use emulebb_metadata::JobToken;

/// Callback dispatch needs content and execution authority, not a hydrated transfer.
pub(crate) struct CallbackDownloadTarget {
    pub token: JobToken,
    pub hash: Ed2kHash,
    pub name: String,
    pub size_bytes: u64,
    pub preparation_id: Option<Ed2kCallbackPreparationId>,
}

impl CallbackDownloadTarget {
    pub(crate) fn download_for_source(&self, source: &Ed2kFoundSource) -> Ed2kCallbackDownload {
        Ed2kCallbackDownload {
            preparation_id: self.preparation_id,
            job_token: self.token,
            file_hash: self.hash,
            display_name: self.name.clone(),
            file_size: self.size_bytes,
            source: Ed2kSourceHint {
                ip: source.ip.to_string(),
                tcp_port: source.tcp_port,
                user_hash: source.user_hash.map(hex::encode),
                connect_options: source.obfuscation_options,
                file_comment: String::new(),
                file_rating: 0,
            },
        }
    }
}
