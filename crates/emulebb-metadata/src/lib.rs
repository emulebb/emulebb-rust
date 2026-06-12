//! SQLite metadata store for the Rust eMuleBB client.

mod identity_model;
mod identity_store;
mod model;
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
pub use model::{MetadataIndexedFile, MetadataSharedDirectoryRoot};
pub use profile_model::{MetadataCategory, MetadataFriend, MetadataServer};
pub use search_model::{MetadataSearch, MetadataSearchResult};
pub use search_store::normalized_search_query;
pub use schema::{SCHEMA_ID, SCHEMA_SQL, SCHEMA_VERSION};
pub use store::MetadataStore;
pub use text::normalize_search_text;
pub use transfer_model::{
    MetadataTransferManifest, MetadataTransferPiece, MetadataTransferRange, MetadataTransferSource,
};
