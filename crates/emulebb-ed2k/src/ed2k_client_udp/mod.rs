//! Client-to-client eD2k UDP source reask (the `OP_REASKFILEPING` family).
//!
//! eMule keeps an upload-queue position warm for hours by disconnecting and
//! periodically *reasking* over UDP instead of holding a TCP socket per queued
//! source. This module is the pure, transport-free foundation for that
//! behaviour in emulebb-rust (see `docs/design/udp-source-reask.md`):
//!
//! - [`codec`]: wire encode/decode of the four HighID reask opcodes.
//! - [`registry`]: the `(ip, udp_port)` anti-spoof pending-reply gate.
//! - [`state`]: per-source reask state, cadence policy, and the downloader-side
//!   reaction table.
//! - [`reciprocity`]: the uploader-side answer decision for inbound reasks.
//!
//! The client-UDP transport + per-transfer reask ticker that call these (and the
//! shared-vs-separate UDP-port decision) are the gated next slice. The re-exports
//! below are the public surface that transport will consume; until it lands they
//! are unused by design.
#![allow(dead_code, unused_imports)]

pub(crate) mod buddy_relay;
pub(crate) mod codec;
pub(crate) mod dispatch;
pub(crate) mod outbound;
pub(crate) mod reciprocity;
pub(crate) mod registry;
pub(crate) mod runtime;
pub(crate) mod service;
pub(crate) mod source_set;
pub(crate) mod state;

pub(crate) use codec::{
    OP_FILENOTFOUND, OP_QUEUEFULL, OP_REASKACK, OP_REASKCALLBACKUDP, OP_REASKFILEPING, ReaskAck,
    ReaskCallbackUdp, ReaskFilePing, decode_reask_ack, decode_reask_callback_udp,
    decode_reask_file_ping, encode_reask_ack, encode_reask_callback_udp, encode_reask_file_ping,
};
pub(crate) use dispatch::{InboundReaskMessage, parse_inbound_reask_datagram};
pub(crate) use outbound::{
    OutboundReaskTarget, build_file_not_found_datagram, build_queue_full_datagram,
    build_reask_ack_datagram, build_reask_callback_udp_datagram, build_reask_file_ping_datagram,
};
pub(crate) use reciprocity::{InboundReaskAnswer, InboundReaskRequest, answer_inbound_reask};
pub(crate) use registry::{PendingReask, ReaskPendingRegistry};
pub use runtime::{
    ReaskCommand, ReaskCommandReceiver, ReaskEvent, ReaskEventReceiver, ReaskEventSender,
    ReaskSourceHandle, reask_command_channel, reask_event_channel, run_ed2k_udp_reask_loop,
};
pub(crate) use service::{
    ReaskInboundOutcome, ReaskService, ReaskTickOutput, TransferReaskInfo,
};
pub(crate) use source_set::ReaskSourceSet;
pub(crate) use state::{
    FILE_REASK_TIME, MIN_REQUEST_TIME, ReaskAction, ReaskReply, ReaskSource, UDP_MAX_QUEUE_TIME,
    apply_reask_reply, reask_interval, should_fall_back_to_tcp, udp_reask_eligible,
};
