---
id: RUST-BUG-005
workflow: local
title: ed2k packet dumps silently disabled for a run when first-access precedes EMULEBB_RUST_LOG_DIR
status: DONE
priority: Major
category: bug
labels: [diagnostics, packet-dump, parity, soak]
milestone: release-0.1.0-beta.1
created: 2026-07-06
source: soak forensics — current run produced zero ed2k_packet_v1 records despite 2 GB of uploads
---

# RUST-BUG-005 — ed2k packet dumps could be permanently disabled for a run

## Symptom

In a live soak the rust client did ~2 GB of uploads across 14 peers plus a full
server + Kad session, yet the `ed2k_packet_v1` dumps (`ed2k-tcp`, `ed2k-server`,
`ed2k-client-udp`) held **zero** current-run records — only the Kad `wire_dump`
(a different writer) produced output. This blocked the rust↔MFC eD2K wire-parity
diff that the soak exists to run.

## Root cause

All three eD2K converged dumpers opened their JSONL file **inside**
`OnceLock::get_or_init` and cached the resulting `Option<File>` for the process
lifetime. A single early first-access before the daemon made `EMULEBB_RUST_LOG_DIR`
visible cached `None`, silently disabling the dump for the entire run. The Kad
`wire_dump` writer does not use this pattern, which is why only it survived.

## Fix

Split each writer's open into `open_*_dump_file() -> Option<fs::File>` and
initialise the `OnceLock` cell to `None`; the record writers re-attempt the open
whenever the handle is still `None`, so a later env/dir availability is picked up
and a transient early failure can never kill the dump. Applied to `ed2k_tcp`,
`ed2k_server`, and `ed2k_client_udp` dumpers. Commit `faa7cc2`; feature-on clippy
cleanup `82eec2c`.

Regression test `dump_recovers_when_log_dir_appears_after_first_access`: an access
before `EMULEBB_RUST_LOG_DIR` appears must still write once it is set (fails on the
old code, passes on the new).

## Comparability check (rust ↔ MFC)

Verified the parity diff is sound once dumps flow: MFC (`Log.cpp:688`) and rust
both emit `ed2k_packet_v1` with identical diff-relevant fields
(`ts_utc/event_seq/flow/trace_key/direction/remote_addr/transport_mode/protocol/
protocol_marker/opcode/opcode_name/payload_len/payload_hex/payload_hex_truncated`);
`source` differs by design (`emulebb` vs `emulebb-rust`). Rust emits a superset
(adds `state_label/phase/raw_hex/note`). `packet_trace_diff.py` keys on the wire
identity `(protocol_marker, opcode, payload_hex)` — not the per-client name tables
— and normalises flow labels onto a shared taxonomy, so rust's extras are ignored
and the two dumps diff 1:1.

## Follow-up (diagnostics hygiene, separate)

Dump files are PID-named singletons in a shared dir; PID reuse across runs makes
old and new records collide in the same filenames. Isolating dumps per campaign
(under the reports dir) would make per-run analysis unambiguous.
