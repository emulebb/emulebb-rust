---
id: RUST-BUG-083
title: Gate SX2 requests on the MFC soft source cap
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-083: Gate SX2 requests on the MFC soft source cap

## Problem

The hide.me live-wire run `rust-hideme-20260619T021252Z` showed Rust sending
many embedded `OP_REQUESTSOURCES2` packets while the transfer already had a high
initial source count.

Comparing against eMuleBB MFC showed that `CUpDownClient::IsSourceRequestAllowed`
does not ask a peer for SX2 sources unless the requested file still needs more
sources:

- the peer must support the extended protocol and SX2;
- `m_reqfile->GetMaxSourcePerFileSoft() > partfile->GetSourceCount()` must hold;
- the rarity and client/file timing predicates must also pass.

Rust only checked a per-peer 40-minute SX2 throttle before setting
`source_exchange_allowed`, so it could ask SX2-capable peers for more sources
even after the file was already at the soft source cap.

## Acceptance

- [x] Rust suppresses outbound SX2 requests when the file's live source count is
      at or above the soft per-file source cap.
- [x] A cap-denied SX2 decision does not consume the peer/file SX2 reask
      throttle.
- [x] Existing per-peer SX2 reask throttling still applies below the cap.
- [x] The direct-download scheduler still uses the same source count basis as
      the existing MFC-style source-engagement cap.

## Implementation Notes

- Threaded the current live per-file source count from the core direct-download
  orchestration into the ED2K peer download startup options.
- `Ed2kTransferRuntime::should_request_source_exchange` now checks the existing
  `can_engage_file_source` soft-cap predicate before updating the SX2 request
  throttle map.
- Added unit coverage for both the existing peer/file throttle and the new
  soft-cap denial.

## Evidence

- MFC comparison:
  `srchybrid/DownloadClient.cpp` `CUpDownClient::IsSourceRequestAllowed`.
- Live behavior exposing the issue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T021252Z`.
- `cargo test -p emulebb-ed2k source_exchange -- --nocapture`
