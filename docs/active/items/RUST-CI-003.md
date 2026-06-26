---
id: RUST-CI-003
workflow: local
title: Wire the /api/v1 OpenAPI conformance/drift check into CI
status: OPEN
priority: Minor
category: ci
labels: [rest, contract, openapi, ci, drift]
milestone: phase-0
created: 2026-06-26
source: docs/rest/README.md contract-drift TODO
---

# RUST-CI-003 - Wire the /api/v1 OpenAPI conformance/drift check into CI

## Summary

`docs/rest/REST-API-OPENAPI.yaml` is the source of truth for the one
capability-gated eMuleBB `/api/v1` contract, and emulebb-rust owns the superset.
Today nothing automatically verifies that the daemon's live responses match the
document, so the spec and the implementation can silently drift even though the
contract policy requires changing both in the same change. This item wires a
conformance/drift check into this repo's CI so the contract stays honest.

## Why This Matters

TrackMuleBB drives both emulebb-rust and the frozen MFC purely from
`GET /api/v1/capabilities` plus the contract; if a response shape diverges from
the spec, consumers break with no early signal. A drift gate converts the
"remember to update the YAML" convention into an enforced invariant.

## Intended Shape

- Validate live daemon responses against `docs/rest/REST-API-OPENAPI.yaml`,
  scoped per advertised capability (only assert operations the instance
  advertises via `GET /api/v1/capabilities`).
- Run it from the shared `emulebb-build-tests` suite against a locally launched
  daemon bound to `X_LOCAL_IP`; do not fork a parallel per-client suite.
- Fail on a response that violates the schema, an advertised operation missing
  from the spec, or a spec operation advertised-but-unimplemented.
- Keep `x-contract-version` handling consistent with the additive/breaking bump
  rules in `docs/rest/README.md`.

## Scope Constraints

- Conformance only; do not broaden or weaken the contract.
- Adapter surfaces (`/api/v2` qBit-compat, Torznab) are out of scope for this
  native-contract gate.
- No new tracked PowerShell; harness in Python via the shared suite.

## Acceptance Criteria

- [ ] A conformance check validates live `/api/v1` responses against
      `REST-API-OPENAPI.yaml`, gated by advertised capabilities.
- [ ] It runs in this repo's CI / the shared `emulebb-build-tests` suite, not a
      forked suite.
- [ ] Drift fails the gate (schema violation, advertised-but-unspecified, or
      specified-but-unadvertised operation).
- [ ] `docs/rest/README.md` no longer carries an untracked TODO; it points at
      this item.

## Validation

- Run the check against a locally launched daemon bound to `X_LOCAL_IP`; confirm
  it passes on a clean HEAD and fails on an injected schema/spec mismatch.

## Notes

- Local item: it records an internal CI gate rather than a product feature.
  Promote to a GitHub-tracked CI item if it needs public workflow visibility.
- Provenance: the "TODO: wire the conformance check" note in
  `docs/rest/README.md`.
