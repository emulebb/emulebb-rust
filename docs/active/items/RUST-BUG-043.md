---
id: RUST-BUG-043
status: done
type: bug
area: rest
---

# RUST-BUG-043: Report already-shared local files on create

## Problem

MFC reports `alreadyShared=true` from `POST /api/v1/shared-files` when the
requested file is already present in the shared-file surface. Rust always
returned `alreadyShared=false`, even when the second request resolved to the
same shared file.

## Resolution

- Captured the visible shared-file hashes before ingesting the requested file.
- Returned `alreadyShared=true` when the resulting share hash was already
  present.
- Added REST contract coverage for repeated shared-file creation.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest shared_files_use_canonical_route_and_envelope --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
