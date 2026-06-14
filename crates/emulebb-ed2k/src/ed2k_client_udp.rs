//! Client-to-client eD2k UDP reask codec (the `OP_REASKFILEPING` family).
//!
//! eMule keeps an upload-queue position warm for hours by disconnecting and
//! periodically *reasking* over UDP instead of holding a TCP socket per queued
//! source. This module encodes/decodes the four HighID reask opcodes exactly as
//! `emulebb-main` frames them (see `docs/design/udp-source-reask.md`). All four
//! are `OP_EMULEPROT` opcodes on the *client UDP* socket; they are disambiguated
//! from the same numeric opcodes on other sockets purely by socket + protocol
//! byte, so a client-UDP dispatcher keys on that context.
//!
//! Wire bodies (after the `[OP_EMULEPROT][opcode]` UDP header, pre-obfuscation):
//! - `OP_REASKFILEPING` (downloader -> source):
//!   `hash16` + (sender udp_version > 3: partstatus) + (sender udp_version > 2:
//!   `u16` complete-source count).
//! - `OP_REASKACK` (source -> downloader): (source udp_version > 3: partstatus)
//!   + `u16` queue position.
//! - `OP_QUEUEFULL`, `OP_FILENOTFOUND`: empty body.
//!
//! `partstatus` is `u16 part_count` + a `ceil(part_count / 8)` bitfield, LSB-first
//! within each byte (the same layout as OP_FILESTATUS). A `part_count` of 0 means
//! "no partfile" (request) or "complete file" (answer).
//!
//! NOTE: this is the codec slice; the client-UDP transport + per-transfer reask
//! ticker (which call these encoders/decoders) land in the following slices.
#![allow(dead_code)]

use anyhow::{Result, bail};
use emulebb_kad_proto::Ed2kHash;

/// `OP_EMULEPROT` reask opcodes on the client UDP socket.
pub(crate) const OP_REASKFILEPING: u8 = 0x90;
pub(crate) const OP_REASKACK: u8 = 0x91;
pub(crate) const OP_FILENOTFOUND: u8 = 0x92;
pub(crate) const OP_QUEUEFULL: u8 = 0x93;

/// Decoded `OP_REASKFILEPING` request (uploader/reciprocity side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReaskFilePing {
    pub file_hash: Ed2kHash,
    /// Sender's part availability, when it advertised one (udp_version > 3 and it
    /// holds a partfile). `None` means no partfile / not advertised.
    pub part_status: Option<Vec<bool>>,
    /// Sender's reported complete-source count (udp_version > 2), else `None`.
    pub complete_source_count: Option<u16>,
}

/// Decoded `OP_REASKACK` reply (downloader side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReaskAck {
    /// Uploader's part availability, when advertised (peer udp_version > 3).
    pub part_status: Option<Vec<bool>>,
    /// Our position in the uploader's queue.
    pub queue_position: u16,
}

/// Encodes a `partstatus` field: `u16 count` + LSB-first bitfield. `None` (no
/// partfile / complete file) encodes as `u16 0`.
fn encode_part_status(part_status: Option<&[bool]>) -> Vec<u8> {
    let Some(parts) = part_status else {
        return 0u16.to_le_bytes().to_vec();
    };
    let count = u16::try_from(parts.len()).unwrap_or(u16::MAX);
    let mut out = count.to_le_bytes().to_vec();
    let mut current = 0u8;
    for (index, &present) in parts.iter().enumerate() {
        if present {
            current |= 1 << (index % 8);
        }
        if index % 8 == 7 {
            out.push(current);
            current = 0;
        }
    }
    if parts.len() % 8 != 0 {
        out.push(current);
    }
    out
}

/// Decodes a `partstatus` field, returning the bitmap (`None` when count is 0)
/// and the remaining bytes.
fn decode_part_status(buf: &[u8]) -> Result<(Option<Vec<bool>>, &[u8])> {
    if buf.len() < 2 {
        bail!("short reask partstatus header");
    }
    let count = usize::from(u16::from_le_bytes([buf[0], buf[1]]));
    if count == 0 {
        return Ok((None, &buf[2..]));
    }
    let bitfield_len = count.div_ceil(8);
    let end = 2 + bitfield_len;
    if buf.len() < end {
        bail!("short reask partstatus bitfield ({count} parts)");
    }
    let bitfield = &buf[2..end];
    let bitmap = (0..count)
        .map(|index| (bitfield[index / 8] >> (index % 8)) & 1 == 1)
        .collect();
    Ok((Some(bitmap), &buf[end..]))
}

/// Encodes the `OP_REASKFILEPING` body. `sender_udp_version` is *our* advertised
/// UDP version (gates the optional tails, matching eMule's `UDPReaskForDownload`).
pub(crate) fn encode_reask_file_ping(
    file_hash: &Ed2kHash,
    part_status: Option<&[bool]>,
    complete_source_count: u16,
    sender_udp_version: u8,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + 4);
    body.extend_from_slice(&file_hash.0);
    if sender_udp_version > 3 {
        body.extend_from_slice(&encode_part_status(part_status));
    }
    if sender_udp_version > 2 {
        body.extend_from_slice(&complete_source_count.to_le_bytes());
    }
    body
}

/// Decodes an `OP_REASKFILEPING` body. `sender_udp_version` is the *peer's*
/// advertised UDP version (learned at hello time).
pub(crate) fn decode_reask_file_ping(body: &[u8], sender_udp_version: u8) -> Result<ReaskFilePing> {
    if body.len() < 16 {
        bail!("short OP_REASKFILEPING body ({})", body.len());
    }
    let file_hash = Ed2kHash::from_bytes(body[..16].try_into()?);
    let mut rest = &body[16..];
    let mut part_status = None;
    if sender_udp_version > 3 {
        let (bitmap, tail) = decode_part_status(rest)?;
        part_status = bitmap;
        rest = tail;
    }
    let mut complete_source_count = None;
    if sender_udp_version > 2 {
        if rest.len() < 2 {
            bail!("short OP_REASKFILEPING complete-source count");
        }
        complete_source_count = Some(u16::from_le_bytes([rest[0], rest[1]]));
    }
    Ok(ReaskFilePing {
        file_hash,
        part_status,
        complete_source_count,
    })
}

/// Encodes the `OP_REASKACK` body. `peer_udp_version` is the *downloader's*
/// version (we are the uploader answering): it gates the leading partstatus.
pub(crate) fn encode_reask_ack(
    part_status: Option<&[bool]>,
    queue_position: u16,
    peer_udp_version: u8,
) -> Vec<u8> {
    let mut body = Vec::new();
    if peer_udp_version > 3 {
        body.extend_from_slice(&encode_part_status(part_status));
    }
    body.extend_from_slice(&queue_position.to_le_bytes());
    body
}

/// Decodes an `OP_REASKACK` body. `our_udp_version` is our advertised version
/// (the source gated the leading partstatus on it).
pub(crate) fn decode_reask_ack(body: &[u8], our_udp_version: u8) -> Result<ReaskAck> {
    let mut rest = body;
    let mut part_status = None;
    if our_udp_version > 3 {
        let (bitmap, tail) = decode_part_status(rest)?;
        part_status = bitmap;
        rest = tail;
    }
    if rest.len() < 2 {
        bail!("short OP_REASKACK queue position");
    }
    let queue_position = u16::from_le_bytes([rest[0], rest[1]]);
    Ok(ReaskAck {
        part_status,
        queue_position,
    })
}

use std::time::Duration;

/// Nominal per-source reask interval (`FILEREASKTIME`, eMuleBB opcodes.h).
pub(crate) const FILE_REASK_TIME: Duration = Duration::from_secs(29 * 60);
/// Minimum spacing between reasks to one source (`MIN_REQUESTTIME`).
pub(crate) const MIN_REQUEST_TIME: Duration = Duration::from_secs(10 * 60);
/// Uploader-side: how long a just-asked slot is held warm (`UDPMAXQUEUETIME`).
pub(crate) const UDP_MAX_QUEUE_TIME: Duration = Duration::from_secs(20);
/// Failure-ratio backoff gate: stop UDP-reasking a source once it has had more
/// than this many attempts and the failure ratio exceeds `UDP_FAILURE_RATIO`.
const UDP_FAILURE_MIN_ATTEMPTS: u32 = 3;
const UDP_FAILURE_RATIO: f64 = 0.3;

/// Per-source reask interval: nominal `FILE_REASK_TIME`, doubled for
/// no-needed-parts sources, never below `MIN_REQUEST_TIME` (mirrors
/// `CUpDownClient::GetTimeUntilReask`-style spacing).
pub(crate) fn reask_interval(no_needed_parts: bool) -> Duration {
    let base = if no_needed_parts {
        FILE_REASK_TIME.saturating_mul(2)
    } else {
        FILE_REASK_TIME
    };
    base.max(MIN_REQUEST_TIME)
}

/// Whether a queued source is eligible for UDP reask (eMuleBB
/// `UDPReaskForDownload` preconditions): the source advertised a UDP port and a
/// non-zero udp_version, we have a local UDP port, we are not firewalled, there
/// is no live TCP socket to it, and no proxy is configured.
pub(crate) fn udp_reask_eligible(
    source_udp_port: u16,
    source_udp_version: u8,
    have_local_udp_port: bool,
    self_firewalled: bool,
    has_live_tcp_socket: bool,
    proxy_configured: bool,
) -> bool {
    source_udp_port != 0
        && source_udp_version != 0
        && have_local_udp_port
        && !self_firewalled
        && !has_live_tcp_socket
        && !proxy_configured
}

/// Whether UDP reask for a source should fall back to TCP because its UDP
/// failure ratio is bad (`total > 3 && failed/total > 0.3`).
pub(crate) fn should_fall_back_to_tcp(udp_total: u32, udp_failed: u32) -> bool {
    udp_total > UDP_FAILURE_MIN_ATTEMPTS
        && f64::from(udp_failed) / f64::from(udp_total) > UDP_FAILURE_RATIO
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash() -> Ed2kHash {
        Ed2kHash::from_bytes([
            0x9e, 0xce, 0xd4, 0x7d, 0xf2, 0xed, 0xfb, 0xd7, 0x2f, 0x29, 0xf9, 0x34, 0x47, 0xd6,
            0x0b, 0x7b,
        ])
    }

    #[test]
    fn part_status_round_trip_lsb_first() {
        // 10 parts: have 0,1,3,9 -> byte0 = 0b0000_1011, byte1 = 0b0000_0010.
        let parts = [true, true, false, true, false, false, false, false, false, true];
        let encoded = encode_part_status(Some(&parts));
        assert_eq!(encoded[0..2], 10u16.to_le_bytes());
        assert_eq!(encoded[2], 0b0000_1011);
        assert_eq!(encoded[3], 0b0000_0010);
        let (decoded, rest) = decode_part_status(&encoded).unwrap();
        assert_eq!(decoded.unwrap(), parts);
        assert!(rest.is_empty());
    }

    #[test]
    fn part_status_none_is_u16_zero() {
        assert_eq!(encode_part_status(None), vec![0, 0]);
        let (decoded, rest) = decode_part_status(&[0, 0, 0xAB]).unwrap();
        assert!(decoded.is_none());
        assert_eq!(rest, &[0xAB]);
    }

    #[test]
    fn reask_file_ping_v4_round_trip_with_partstatus_and_count() {
        let parts = [true, false, true];
        let body = encode_reask_file_ping(&hash(), Some(&parts), 7, 4);
        let decoded = decode_reask_file_ping(&body, 4).unwrap();
        assert_eq!(decoded.file_hash, hash());
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.complete_source_count, Some(7));
    }

    #[test]
    fn reask_file_ping_v2_has_count_but_no_partstatus() {
        // udp_version 3: > 2 (count present) but not > 3 (no partstatus).
        let body = encode_reask_file_ping(&hash(), Some(&[true]), 2, 3);
        assert_eq!(body.len(), 16 + 2); // hash + u16 count only
        let decoded = decode_reask_file_ping(&body, 3).unwrap();
        assert!(decoded.part_status.is_none());
        assert_eq!(decoded.complete_source_count, Some(2));
    }

    #[test]
    fn reask_file_ping_v1_is_hash_only() {
        let body = encode_reask_file_ping(&hash(), Some(&[true]), 9, 2);
        assert_eq!(body.len(), 16);
        let decoded = decode_reask_file_ping(&body, 2).unwrap();
        assert!(decoded.part_status.is_none());
        assert!(decoded.complete_source_count.is_none());
    }

    #[test]
    fn reask_ack_v4_round_trip() {
        let parts = [false, true, true, false, true];
        let body = encode_reask_ack(Some(&parts), 42, 4);
        let decoded = decode_reask_ack(&body, 4).unwrap();
        assert_eq!(decoded.part_status.unwrap(), parts);
        assert_eq!(decoded.queue_position, 42);
    }

    #[test]
    fn reask_ack_low_version_is_position_only() {
        let body = encode_reask_ack(Some(&[true]), 5, 3);
        assert_eq!(body, 5u16.to_le_bytes());
        let decoded = decode_reask_ack(&body, 3).unwrap();
        assert!(decoded.part_status.is_none());
        assert_eq!(decoded.queue_position, 5);
    }

    #[test]
    fn short_bodies_are_rejected() {
        assert!(decode_reask_file_ping(&[0u8; 4], 4).is_err());
        assert!(decode_reask_ack(&[], 2).is_err());
        assert!(decode_part_status(&[1]).is_err());
    }

    #[test]
    fn reask_interval_doubles_for_no_needed_parts() {
        assert_eq!(reask_interval(false), FILE_REASK_TIME);
        assert_eq!(reask_interval(true), FILE_REASK_TIME * 2);
        // Nominal interval always clears the minimum spacing floor.
        assert!(reask_interval(false) >= MIN_REQUEST_TIME);
    }

    #[test]
    fn udp_eligibility_requires_all_preconditions() {
        // All good -> eligible.
        assert!(udp_reask_eligible(4672, 4, true, false, false, false));
        // Each disqualifier individually blocks UDP reask.
        assert!(!udp_reask_eligible(0, 4, true, false, false, false)); // no source UDP port
        assert!(!udp_reask_eligible(4672, 0, true, false, false, false)); // udp_version 0
        assert!(!udp_reask_eligible(4672, 4, false, false, false, false)); // no local UDP port
        assert!(!udp_reask_eligible(4672, 4, true, true, false, false)); // firewalled
        assert!(!udp_reask_eligible(4672, 4, true, false, true, false)); // live TCP socket held
        assert!(!udp_reask_eligible(4672, 4, true, false, false, true)); // proxy configured
    }

    #[test]
    fn failure_ratio_backoff_threshold() {
        assert!(!should_fall_back_to_tcp(0, 0));
        assert!(!should_fall_back_to_tcp(3, 3)); // not > 3 attempts yet
        assert!(!should_fall_back_to_tcp(10, 3)); // 0.3 ratio, not > 0.3
        assert!(should_fall_back_to_tcp(10, 4)); // 0.4 > 0.3
        assert!(should_fall_back_to_tcp(4, 2)); // 0.5 > 0.3, > 3 attempts
    }
}
