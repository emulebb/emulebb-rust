//! Builders that turn inbound Kad search requests into snoop-queue entries.

use chrono::{DateTime, Utc};
use emulebb_index::SnoopEntry;
use emulebb_kad_proto::{SearchKeyReq, SearchNotesReq, SearchSourceReq};

pub(crate) fn build_keyword_snoop_entry(req: &SearchKeyReq, now: DateTime<Utc>) -> SnoopEntry {
    let restrictive_payload_hex =
        (!req.restrictive_payload.is_empty()).then(|| hex::encode(&req.restrictive_payload));
    SnoopEntry::Keyword {
        logical_key: keyword_logical_key(req),
        target: req.target.to_string(),
        start_position: req.start_position,
        restrictive_payload_hex,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

pub(crate) fn build_source_snoop_entry(req: &SearchSourceReq, now: DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Source {
        logical_key: source_logical_key(req),
        target: req.target.to_string(),
        start_position: req.start_position,
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

pub(crate) fn build_notes_snoop_entry(req: &SearchNotesReq, now: DateTime<Utc>) -> SnoopEntry {
    SnoopEntry::Notes {
        logical_key: notes_logical_key(req),
        target: req.target.to_string(),
        size: req.size,
        hit_count: 1,
        first_seen: now,
        last_seen: now,
        last_drained_at: None,
    }
}

fn keyword_logical_key(req: &SearchKeyReq) -> String {
    let payload_hex = if req.restrictive_payload.is_empty() {
        String::new()
    } else {
        hex::encode(&req.restrictive_payload)
    };
    format!(
        "keyword:{}:{:04x}:{}",
        req.target, req.start_position, payload_hex
    )
}

fn source_logical_key(req: &SearchSourceReq) -> String {
    format!(
        "source:{}:{:04x}:{}",
        req.target, req.start_position, req.size
    )
}

fn notes_logical_key(req: &SearchNotesReq) -> String {
    format!("notes:{}:{}", req.target, req.size)
}
