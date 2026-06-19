---
id: RUST-BUG-098
title: Do not gate download startup on pending secure-ident keys
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-098: Do not gate download startup on pending secure-ident keys

## Problem

Live hide.me packet captures showed direct peer sessions reaching the
secure-ident public-key path and then closing before file metadata or upload
startup progressed. Rust still treated a missing peer public key or pending
local signature as a blocker for download startup, hashset request, hashset
fallback, and `OP_STARTUPLOADREQ`.

MFC does not make the file request depend on secure-ident completion:
`CUpDownClient::ConnectionEstablished()` transitions the download state and
calls `SendFileRequest()` immediately. `OP_SECIDENTSTATE`, `OP_PUBLICKEY`, and
`OP_SIGNATURE` are handled as a side-band identity exchange. If the peer public
key is not known yet, `SendSignaturePacket()` returns and is retried after
`ProcessPublicKeyPacket()`.

## Acceptance

- [x] A small-file peer receives the startup file request before Rust has the
      peer public key needed for a local secure-ident signature.
- [x] Large-file hashset request and upload-start fallback are not gated on
      pending secure-ident key/signature state.
- [x] Existing download queue, range, compressed-frame, reconnect, and payload
      validation tests do not depend on secure-ident completion unless they are
      explicitly testing secure-ident ordering.

## Implementation Notes

- Removed the download-session secure-ident wait predicate from startup,
  source-exchange, AICH, hashset, hashset-fallback, and upload-start gates.
- Left the secure-ident state machine intact: Rust still sends the probe,
  answers `OP_SECIDENTSTATE`, records `OP_PUBLICKEY`, and sends `OP_SIGNATURE`
  when the peer key is available.
- Updated downloader fixtures and focused tests so routine transfer behavior is
  not blocked by an artificial secure-ident challenge.

## Evidence

- Compared against MFC `CUpDownClient::ConnectionEstablished`,
  `CUpDownClient::SendPublicKeyPacket`, `CUpDownClient::SendSignaturePacket`,
  `CUpDownClient::ProcessPublicKeyPacket`, and the `ListenSocket.cpp`
  `OP_SECIDENTSTATE` dispatch.
- Live-wire clue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T070912Z`
  showed peer sessions closing after secure-ident public-key traffic and before
  useful download startup on some sources.
- `cargo test -p emulebb-ed2k ed2k_tcp::tests::download -- --nocapture`
