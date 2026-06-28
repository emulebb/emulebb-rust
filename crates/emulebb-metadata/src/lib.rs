//! SQLite metadata store for the Rust eMuleBB client.

mod identity_model;
mod identity_store;
mod kad_publish_model;
mod kad_publish_store;
mod migrations;
mod model;
mod peer_model;
mod peer_store;
mod profile_model;
mod profile_store;
mod schema;
mod search_model;
mod search_store;
mod store;
mod text;
mod transfer_model;
mod transfer_store;

pub use identity_model::MetadataLocalIdentity;
pub use kad_publish_model::{
    MetadataKadKeywordPublish, MetadataKadNotePublish, MetadataKadOutboundPublish,
    MetadataKadOutboundPublishKind, MetadataKadOutboundPublishSchedule, MetadataKadPublishCache,
    MetadataKadSourcePublish,
};
pub use model::{MetadataIndexedFile, MetadataSharedDirectoryRoot};
pub use peer_model::MetadataPeerCredit;
pub use profile_model::{MetadataCategory, MetadataFriend, MetadataServer};
pub use schema::{SCHEMA_ID, SCHEMA_SQL, SCHEMA_VERSION};
pub use search_model::{MetadataSearch, MetadataSearchResult};
pub use search_store::normalized_search_query;
pub use store::MetadataStore;
pub use text::normalize_search_text;
pub use transfer_model::{
    MetadataShareInPlaceReloadEntry, MetadataTransferCatalogEntry, MetadataTransferCounts,
    MetadataTransferManifest, MetadataTransferPiece, MetadataTransferPublishEntry,
    MetadataTransferRange, MetadataTransferShareEntry, MetadataTransferSource,
};
