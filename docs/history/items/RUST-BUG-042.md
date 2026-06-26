---
id: RUST-BUG-042
status: done
type: bug
area: rest
---

# RUST-BUG-042: Align upload detail not-found messages

## Problem

MFC reports different not-found messages for upload detail routes:
`GET /api/v1/uploads/{clientId}` returns `active upload client not found`, while
`GET /api/v1/upload-queue/{clientId}` returns `upload queue client not found`.
Rust reused the queue message for both routes.

## Resolution

- Kept the queue route message unchanged.
- Changed the active upload detail route to return the MFC `active upload client
  not found` message.
- Added route coverage for both not-found responses.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest uploads_and_upload_queue_use_canonical_envelopes --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
