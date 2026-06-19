---
id: RUST-BUG-094
title: Filter client UDP diagnostic noise and dump replies
status: done
priority: Minor
category: bug
workflow: local
---

# RUST-BUG-094: Filter client UDP diagnostic noise and dump replies

## Problem

After adding retained client-UDP packet diagnostics, the shared Kad UDP socket's
foreign-datagram path also wrote unrelated undecodable datagrams as
`flow="client_udp"` / `opcode_name="UNKNOWN"`. That made the packet report noisy
and could be misread as unknown eD2K client-UDP protocol traffic. The first slice
also only dumped downloader-side reask sends, not uploader-side reciprocity
replies emitted after inbound `OP_REASKFILEPING` / relayed callback requests.

## Acceptance

- [x] Inbound client-UDP packet diagnostics skip datagrams that are neither
      plaintext nor decryptable eMule client-UDP frames.
- [x] Plaintext or decryptable eMule client-UDP frames are still retained,
      including unknown opcodes on the actual client-UDP protocol marker.
- [x] Uploader-side reciprocity replies preserve packet metadata and are dumped
      after successful sends.

## Implementation Notes

- `dump_client_udp_recv` now returns without a packet record when the shared
  socket hands it non-client UDP noise.
- `build_reciprocity_reply_packet` returns `ClientUdpDatagram`, preserving the
  raw bytes plus opcode/payload metadata for `OP_REASKACK`, `OP_QUEUEFULL`, and
  `OP_FILENOTFOUND`.
- Runtime and buddy-relay answer paths dump reciprocity replies only after the
  raw datagram is successfully sent.

## Evidence

- Follow-up from live-wire report:
  `EMULEBB_WORKSPACE_OUTPUT_ROOT\live-wire\rust-hideme-20260619T055435Z`.
- `cargo test -p emulebb-ed2k ed2k_client_udp --features packet-diagnostics -- --nocapture`
- `cargo test -p emulebb-ed2k reask_reciprocity --features packet-diagnostics -- --nocapture`
