//! SQLite metadata store for the Rust eMuleBB client.

mod model;
mod schema;
mod store;
mod text;

pub use model::{MetadataIndexedFile, MetadataSharedDirectoryRoot};
pub use schema::{SCHEMA_ID, SCHEMA_SQL, SCHEMA_VERSION};
pub use store::MetadataStore;
pub use text::normalize_search_text;
