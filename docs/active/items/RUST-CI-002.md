---
id: RUST-CI-002
workflow: local
title: Rationalize and close the core MFC parity evidence gate
status: OPEN
priority: Major
category: ci
labels: [parity, tests, evidence, release]
milestone: phase-0
created: 2026-06-19
source: core parity closure review (2026-06-19)
---

# RUST-CI-002 - Rationalize and close the core MFC parity evidence gate

## Summary

Close the emulebb-rust vs eMuleBB MFC **core client parity** lane with one
authoritative, reproducible evidence gate. The close target is core eD2K/Kad
client behavior, REST contract parity, deterministic local cross-client
interoperation, and a manual public-network smoke witness. It is not the full
Phase 0 product gate: indexer, Arr/Torznab, Docker, SSE, and the automated
tunnel-down leak test remain separately tracked.

This item exists to prevent the parity closure decision from being spread across
ad hoc reports. It owns the close checklist, evidence freshness rule, and test
rationalization.

## Current State

- The Rust parity bug train through `RUST-BUG-099` is done on `main`.
- Deterministic local evidence under the retained overnight and local parity
  reports is green but older than the latest June 19 parity fixes.
- The latest public hide.me live-wire run passed after `RUST-BUG-098`; it is a
  useful smoke witness, not a substitute for the automated leak-test gate.
- Open or in-progress owners remain:
  `RUST-BUG-001`, `RUST-FEAT-001`, `RUST-FEAT-003`, and `RUST-FEAT-005`.
- Forward product work remains in `RUST-FEAT-002`, `RUST-FEAT-004`,
  `RUST-FEAT-006`, and `RUST-FEAT-007`; those are not blockers for core parity
  closure.

## Intended Shape

Use `emulebb-rust-overnight` as the authoritative core parity close campaign.
The regular/manual campaign can stay informational unless its manual evidence
rows are converted to JSON-backed evidence and evaluated consistently.

The close gate is:

1. `python -m emule_workspace workspace-status`
2. `python -m emule_workspace validate`
3. `python tools\check_rust_client_policy.py` from `repos\emulebb-rust`
4. Build the MFC release and tracing-harness executables through
   `repos\emulebb-build` orchestration.
5. `python -m emule_workspace test release-campaign --campaign emulebb-rust-overnight --execute --continue-on-failure`
6. Targeted UDP reask proof:
   `python scripts\emulebb-rust-reask-cross-client.py --lan-bind-addr %X_LOCAL_IP%`
7. Optional long-form byte-level confirmation with
   `emulebb-rust-reask-capture-emulebb.py`.
8. Optional public hide.me live-wire smoke using operator-local inputs. Accept it
   only when both obfuscation modes pass with VPN-bound P2P, eD2K/Kad
   connectivity, packet diagnostics, source-exchange evidence, and a completed
   download.

## Scope Constraints

- Core parity closure does not claim full Phase 0 completion.
- Public live-wire remains manual and nonblocking until `RUST-FEAT-005` adds the
  automated tunnel-down leak-test.
- MFC source-seam, community/reference parity, VM proof, and public-network live
  proof stay out of the forward suite gate unless explicitly requested.
- All public-network proof must follow the workspace live-test network policy
  and must not commit operator-owned live search terms, media names, private
  addresses, or machine paths.

## Acceptance Criteria

- [ ] Overnight campaign evidence is regenerated after the current Rust HEAD and
      current MFC/tracing-harness build inputs.
- [ ] The retained campaign result records the Rust overnight local client
      pytest proof, local ED2K protocol-combination matrix, private parity
      modules, Rust/eMuleBB bidirectional transfer, Rust/Rust bidirectional
      transfer, Rust/aMule bidirectional transfer, total parity audit, and REST
      contract parity as passed.
- [ ] The close decision explicitly states that `RUST-FEAT-002`,
      `RUST-FEAT-004`, `RUST-FEAT-006`, and `RUST-FEAT-007` are forward Phase 0
      or later work, not core MFC parity blockers.
- [ ] `RUST-FEAT-005` remains open and release-blocking for the suite safety
      claim until the dynamic tunnel-down leak-test exists and is blocking.
- [ ] The regular release campaign is either documented as informational or its
      manual rows are converted to JSON evidence so it cannot contradict the
      authoritative overnight gate.

## Validation

Required for closing this item:

- `python -m emule_workspace workspace-status`
- `python -m emule_workspace validate`
- `python tools\check_rust_client_policy.py`
- `python -m emule_workspace build app --variant main --config Release --platform x64 --build-output-mode ErrorsOnly`
- `python -m emule_workspace build app --variant tracing-harness --config Release --platform x64 --build-output-mode ErrorsOnly`
- `python -m emule_workspace test release-campaign --campaign emulebb-rust-overnight --execute --continue-on-failure`

Optional smoke:

- `python scripts\rust-live-wire-hideme.py --inputs live-wire-inputs.local.json`

## Notes

- This item is local because it records the evidence gate and close decision
  rather than a product feature. If the gate needs public workflow visibility,
  promote it to a GitHub-tracked CI item before closure.
- Related owners: `RUST-FEAT-001` for UDP reask live validation,
  `RUST-FEAT-003` for VPN egress pinning validation, `RUST-FEAT-005` for dynamic
  no-leak automation, and `RUST-BUG-001` for isolated Kad swarm CI debt.
