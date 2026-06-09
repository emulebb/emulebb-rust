//! Kad routing table implementation with oracle-style zone splitting and
//! anti-clustering limits.
//!
//! The routing crate owns the long-lived contact topology used by lookups and
//! publishes. Its public API should stay explicit about why insertions fail so
//! higher layers can expose routing-state decisions instead of generic errors.

pub mod bin;
pub mod contact;
pub mod error;
pub mod table;
pub mod zone;

pub use bin::RoutingBin;
pub use contact::{Contact, ContactType};
pub use error::{RoutingError, RoutingSplitDeniedReason, RoutingSubnetLimitScope};
pub use table::{DEFAULT_MAX_SIZE, RoutingTable};
pub use zone::RoutingZone;
