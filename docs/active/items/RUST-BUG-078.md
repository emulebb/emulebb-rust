---
id: RUST-BUG-078
title: Do not immediately downgrade failed obfuscated ED2K peers
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-078: Do not immediately downgrade failed obfuscated ED2K peers

## Problem

The hide.me live-wire runs `rust-hideme-20260618T235505Z` and
`rust-hideme-20260619T001217Z` stayed VPN-bound and completed transfers, but
the obfuscation-enabled pass showed Rust immediately re-dialing the same ED2K
peer in plaintext after an obfuscated direct-download connection failed.

Comparing against eMuleBB MFC showed the parity rule:

- `CUpDownClient::Connect` enables TCP obfuscation when the peer supports it,
  local obfuscation is enabled, and either the peer requests it or local
  preferences prefer it.
- `CClientReqSocket::OnConnect` and `CClientReqSocket::Disconnect` tear down
  failed sockets through `CUpDownClient::Disconnected`.
- The client connection path does not immediately retry the same failed
  obfuscated socket as plaintext. Normal source scheduling may later retry
  sources through its ordinary timers and source records.

Rust therefore must not synthesize an immediate plaintext source after a failed
obfuscated attempt. A plaintext connection is still valid when an independent
source record is actually plaintext.

## Acceptance

- [x] Failed obfuscated direct-download attempts do not enqueue an immediate
      plaintext downgrade for the same endpoint.
- [x] Independent plaintext source records remain eligible through the normal
      source selection path.
- [x] Existing direct-download retry behavior for other peers still works.
- [x] Required-crypto peers are not downgraded.

## Implementation Notes

- Removed the direct scheduler's `plaintext_fallback_for_obfuscated_source`
  downgrade path.
- Removed the helper and the obsolete required-crypto guard constant that only
  existed for that downgrade path.
- Replaced the old fallback test with a regression test proving a failed
  obfuscated source is attempted once and its error is retained.

## Evidence

- Live evidence source: `rust-hideme-20260618T235505Z`,
  `rust-hideme-20260619T001217Z`.
- Live log counts before the fix: 9 immediate plaintext fallbacks in
  `rust-hideme-20260618T235505Z` obfuscation-on, 19 in
  `rust-hideme-20260619T001217Z` obfuscation-on, and 1 in that run's
  obfuscation-off pass due an obfuscated source record discovered while local
  obfuscation was off.
- Post-fix live proof: `rust-hideme-20260619T005416Z` passed, VPN-bound
  (`10.55.68.38`), ED2K HighID, Kad connected, packet diagnostics captured, 20
  downloads started, 1 completed, and `scheduling plaintext fallback` had zero
  matches.
- Post-fix transfer store: one `Verified` piece with 839,813 bytes, no completed
  bitmap leftovers, and the completed transfer row marked completed.
- `cargo test -p emulebb-core direct_download_scheduler_does_not_downgrade_failed_obfuscated_peer --locked`
- `cargo test -p emulebb-core direct_download_scheduler --locked`
- `python -m emule_workspace build clients --client emulebb-rust --diagnostics`
- `python scripts/rust-live-wire-hideme.py --inputs live-wire-inputs.local.json --max-terms 3 --max-concurrent 20 --download-timeout 600 --require-packet-diagnostics --reask`
