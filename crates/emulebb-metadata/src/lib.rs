//! SQLite metadata store for the Rust eMuleBB client.

mod aich_recovery_store;
mod content_identity;
mod download_availability;
pub use download_availability::{
    AvailabilitySource, DownloadAvailabilityAdmission, LocalContentAvailability,
    MetadataAvailabilityCandidate, MetadataAvailabilityChanged, MetadataAvailabilityCut,
    MetadataAvailabilityStep, MetadataLocalContentChoiceRequired,
};
mod delivery_exclusion_store;
mod discovery_store;
mod download_cleanup_store;
pub use download_cleanup_store::MetadataDownloadCleanupSnapshot;
mod download_execution_store;
mod download_hash_store;
mod download_history_model;
mod download_history_store;
mod download_job_model;
mod download_job_query;
pub use download_job_query::{
    DownloadJobCounts, DownloadJobPage, DownloadJobQuery, DownloadJobView,
};
mod download_job_store;
mod download_payload_store;
mod download_peer_store;
pub use download_payload_store::{MetadataDownloadPayload, MetadataDownloadPayloadPage};
mod download_progress_store;
pub use download_execution_store::{
    MetadataDownloadExecutionHeader, MetadataDownloadExecutionRow, MetadataDownloadGeometry,
};
pub use download_job_model::{
    DownloadIntent, DownloadJobAdmission, DownloadJobRecord, DownloadJobRequest,
    DownloadJobStorage, DownloadJobStorageFailure, DownloadJobStorageFailureOutcome, JobId,
    JobToken,
};
pub use download_peer_store::{
    MetadataDownloadNameEntry, MetadataDownloadPeerChange, MetadataDownloadPeerDelta,
    MetadataDownloadSourceEndpoint, MetadataDownloadSourceEntry, MetadataDownloadSourceSelector,
};
mod identity_model;
mod identity_store;
mod kad_publish_model;
mod kad_publish_store;
mod kad_routing_store;
mod library_projection;
mod local_catalog;
pub use local_catalog::MetadataPartialOffer;
mod local_file_store;
mod local_ingest_store;
pub use local_ingest_store::{
    MetadataIngestCommit, MetadataIngestCommitUncertain, MetadataIngestJob,
    MetadataIngestJobChanged, MetadataIngestPathChanged, MetadataIngestProjection,
    MetadataIngestRoot,
};
mod model;
mod native_file;
mod native_path;
mod peer_model;
mod peer_store;
mod profile_import;
mod profile_model;
mod profile_ownership;
mod profile_store;
mod schema;
mod schema_validation;
mod search_model;
mod search_store;
mod shared_membership_store;
mod snapshot;
mod sql_value;
mod store;
mod text;
mod transfer_model;
mod transfer_store;
mod transfer_validation;

pub use aich_recovery_store::MetadataAichRecoverySet;
pub use discovery_store::{DiscoveryDomain, DiscoveryInitializationStatus};
pub use download_history_model::{
    MetadataCurrentSharedFile, MetadataDownloadHistoryEntry, MetadataSharedCopyCandidate,
};
pub use identity_model::MetadataLocalIdentity;
pub use identity_store::KadNodeId;
pub use kad_publish_model::{
    MetadataKadKeywordPublish, MetadataKadNotePublish, MetadataKadOutboundPublish,
    MetadataKadOutboundPublishKind, MetadataKadOutboundPublishSchedule, MetadataKadPublishCache,
    MetadataKadSourcePublish,
};
pub use kad_routing_store::{
    KAD_ROUTING_MAX_CONTACTS, KadRoutingContact, KadRoutingContactType, KadRoutingSnapshot,
};
pub use local_file_store::{
    MetadataContentConflict, MetadataLocalFileInstance, MetadataLocalShareEntry,
    MetadataSharedFileCursor, MetadataSharedFilePage, MetadataSharedFileQuery,
    MetadataVerifiedLocalContent,
};
pub use model::{MetadataIndexedFile, MetadataIndexedFileOrigin, MetadataSharedDirectoryRoot};
pub use native_file::{
    NativeFileFingerprint, NativeFileIdentity, NativeFileIdentityEvidence, NativeFileTimestamp,
};
pub use native_path::NativePath;
pub use peer_model::MetadataPeerCredit;
pub use profile_model::{MetadataCategory, MetadataFriend, MetadataServer};
pub use profile_ownership::ProfileLeaseGuard;
pub use profile_store::{FriendWriteTiming, valid_category_name};
pub use schema::{SCHEMA_ID, SCHEMA_SQL, SCHEMA_VERSION};
pub use search_model::{
    MetadataSearch, MetadataSearchResult, MetadataSearchResultObservation, MetadataSearchSpec,
};
pub use search_store::normalized_search_query;
pub use shared_membership_store::ObservedRootChanged;
pub use store::{InitialProfileStorage, MetadataStore};
pub use text::normalize_search_text;
pub use transfer_model::{
    MetadataDeliveryOutputReservation, MetadataDownloadRetirement, MetadataFileImportRecord,
    MetadataPartialShare, MetadataSharedSourceFailure, MetadataTransferAichIdentity,
    MetadataTransferCatalogEntry, MetadataTransferCounts, MetadataTransferDeletionTombstone,
    MetadataTransferDeletionTombstonePhase, MetadataTransferDeliveryAttempt,
    MetadataTransferDeliveryAttemptPhase, MetadataTransferDeliveryOwnership,
    MetadataTransferDeliveryState, MetadataTransferDirectoryDeletionAuthority,
    MetadataTransferFileNameObservation, MetadataTransferManifest, MetadataTransferMediaMetadata,
    MetadataTransferPiece, MetadataTransferPublishEntry, MetadataTransferRange,
    MetadataTransferSource,
};

pub use download_hash_store::MetadataDownloadAichState;
