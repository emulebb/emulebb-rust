---
id: RUST-BUG-076
title: Keep diag_event JSONL records line-atomic across shims
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-076: Keep diag_event JSONL records line-atomic across shims

## Problem

The hide.me live-wire run `rust-hideme-20260618T230806Z` captured one malformed
`emulebb-rust-diag-<pid>.jsonl` line: a `sched/source_dropped` event and a
`kad_udp/packet` event were concatenated on one physical line. Both JSON objects
were complete, but there was no newline between them.

The Rust diagnostics architecture intentionally has two `diag_event_v1` shims:
one in `emulebb-ed2k` for eD2K/core events and one in `emulebb-kad-net` for Kad
events. They write the same file. Each shim had its own mutex, but record output
was still split into a JSON write and a newline write, so the other shim could
append between those two writes.

## Acceptance

- [x] eD2K/core `diag_event_v1` writes encode the JSON object and trailing
      newline into one byte buffer before appending.
- [x] Kad `diag_event_v1` writes encode the JSON object and trailing newline
      into one byte buffer before appending.
- [x] Focused unit coverage proves both shims produce exactly one parseable JSON
      object followed by one newline.
- [x] The diagnostic filename and event schema stay unchanged.

## Implementation Notes

- Added `encode_record_line` helpers in both diagnostic shims.
- The helpers use `serde_json::to_vec`, append `b'\n'`, then the emit path writes
  that one buffer to the append-mode file.
- This keeps the existing dependency boundaries intact; no new shared crate or
  dependency was introduced.

## Evidence

- `cargo test -p emulebb-ed2k diag_event --locked`
- `cargo test -p emulebb-kad-net diag_event --locked`
- `cargo fmt --all --check`
- `python tools/rust_quality_gate.py quick`
- hide.me live-wire run `rust-hideme-20260618T232801Z`: packet diagnostics
  captured 5,286 `diag_event_v1` records and every non-empty line parsed as one
  JSON object.
