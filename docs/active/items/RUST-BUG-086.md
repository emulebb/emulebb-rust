---
id: RUST-BUG-086
title: Do not block download startup on peer secure-ident signature
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-086: Do not block download startup on peer secure-ident signature

## Problem

The hide.me live-wire run `rust-hideme-20260619T032114Z` stayed VPN-bound and
connected to ED2K/Kad, but did not complete a transfer. Packet diagnostics
showed multiple direct peers reaching:

`OP_HELLOANSWER -> OP_SECIDENTSTATE -> OP_PUBLICKEY`

and then timing out without Rust sending the file-startup requests. Rust's
download startup gate waited for the peer's `OP_SIGNATURE` after requesting the
peer key/signature. eMuleBB MFC handles secure identification asynchronously:
`OP_SECIDENTSTATE` may trigger `SendPublicKeyPacket` / `SendSignaturePacket`,
and `OP_PUBLICKEY` may trigger `SendSignaturePacket`, but file exchange is not
blocked waiting for the peer's later signature verification packet.

## Acceptance

- [x] Superseded by `RUST-BUG-098`: download startup no longer waits for missing
      peer public key or pending local signature state.
- [x] Download startup no longer waits for the peer's `OP_SIGNATURE` after our
      side has enough state to continue.
- [x] Peer signatures are still processed and verified when they arrive later.

## Implementation Notes

- `RUST-BUG-086` originally reduced the secure-ident startup wait to missing
  peer public key and pending local signature state.
- `RUST-BUG-098` later removed the remaining startup wait entirely, matching MFC
  side-band secure-ident behavior.
- Kept `OP_SIGNATURE` handling unchanged; late peer signatures still update the
  secure-ident verification diagnostics and credit binding path.

## Evidence

- Live behavior exposing the issue:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T032114Z`.
- MFC comparison:
  `ListenSocket.cpp` `OP_SECIDENTSTATE`, `OP_PUBLICKEY`, `OP_SIGNATURE` handling
  and `BaseClient.cpp` `ProcessPublicKeyPacket`.
- `cargo test -p emulebb-ed2k secure_ident_wait -- --nocapture`
