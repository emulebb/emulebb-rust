//! Kad2 wire primitives, packet codecs, and protocol constants shared by the
//! eMuleBB Rust runtime.
//!
//! This crate owns the byte-level contract with the Kad network. Types here
//! should describe oracle semantics as well as field widths so higher layers do
//! not need to reverse-engineer protocol intent from packet layouts alone.

pub mod constants;
pub mod error;
pub mod hash;
pub mod node_id;
pub mod packet;
pub mod tag;

pub use constants::{
    ALPHA, K, KAD_VERSION, KBASE, KK, OP_KADEMLIAHEADER, REPUBLISH_INTERVAL_SECS,
    SEARCH_TIMEOUT_SECS, STORE_KEYWORD_TIMEOUT_SECS, STORE_NOTES_TIMEOUT_SECS,
    STORE_PUBLISH_TARGET_CONTACTS, STORE_SOURCE_TIMEOUT_SECS, STORE_STOP_GRACE_SECS,
    STORE_TIMEOUT_SECS, opcode, tag_name,
};
pub use error::ProtoError;
pub use hash::{Ed2kHash, KadUdpKey};
pub use node_id::NodeId;
pub use packet::{
    BootstrapRes, CallbackReq, ContactEntry, FindBuddyReq, FindBuddyRes, FirewallUdp,
    Firewalled2Req, FirewalledAckRes, FirewalledReq, FirewalledRes, HelloReq, HelloRes,
    HelloResAck, KadPacket, Ping, Pong, PublishEntry, PublishKeyReq, PublishNotesReq, PublishRes,
    PublishResAck, PublishSourceReq, Req, Res, SearchKeyReq, SearchNotesReq, SearchRes,
    SearchResultEntry, SearchSourceReq,
};
pub use tag::{Tag, TagName, TagValue};
