//! Kad routing table implementation with oracle-style zone splitting and
//! anti-clustering limits.
//!
//! The routing crate owns the long-lived contact topology used by lookups and
//! publishes. Its public API should stay explicit about why insertions fail so
//! higher layers can expose routing-state decisions instead of generic errors.

pub mod bin;
pub mod contact;
pub mod error;
pub mod maintenance;
pub mod table;
pub mod zone;

pub use bin::RoutingBin;
pub use contact::{
    CONTACT_TYPE_DEAD, Contact, ContactType, KAD_LOCAL_QUALITY_REPLACEMENT_MARGIN,
    KAD_LOCAL_QUALITY_WEAK_THRESHOLD, kad_version_quality,
};
pub use error::{RoutingError, RoutingSplitDeniedReason, RoutingSubnetLimitScope};
pub use maintenance::{ProbeCandidate, SmallTimerOutcome};
pub use table::{DEFAULT_MAX_SIZE, RoutingTable};
pub use zone::{AddOutcome, RoutingZone};
