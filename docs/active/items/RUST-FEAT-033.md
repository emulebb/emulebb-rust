---
id: RUST-FEAT-033
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: Release - first usable release rust-v0.1.0-beta.1 (scope doc, GH release workflow, soak-gated tag)
status: OPEN
priority: Critical
category: feature
labels: [release, packaging, docs, ci]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: Operator decision 2026-07-05 (plan fuzzy-wondering-moore); WORKSPACE-POLICY release + network-safety rules
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-033 - First usable release `rust-v0.1.0-beta.1`

## Summary

Ship the first usable emulebb-rust release: an unsigned Windows x64 zip built
by a GitHub Actions release workflow, tagged `rust-v0.1.0-beta.1`, with the
supported/omitted/deferred surface documented unambiguously. Packaging is
**workflow-only by operator direction (2026-07-05)** — no local packaging
scripts.

## Locked Decisions

- Version `0.1.0-beta.1` (`[workspace.package]`, own semver line decoupled from
  MFC `0.7.x`/`0.8.x` and from the REST `x-contract-version`).
- Tag scheme `rust-vX.Y.Z[-pre.N]`, distinct from MFC `emulebb-v*`.
- Artifact `emulebb-rust-v<version>-windows-x64.zip` + `SHA256SUMS`, always
  unsigned.
- A **full converged rust-vs-MFC soak blocks the tag**; the annotated tag is
  created only after soak-evidence review and an explicit operator go.

## Intended Shape

1. **Scope doc** `docs/RELEASE-SCOPE.md` — the human-facing authority, checked
   entry-for-entry against `policy/rust-client-omissions.toml` (which stays the
   machine-readable authority): supported surface; permanent omissions;
   deferred-not-omitted list (A4AF [parked pending design], IPv6 [parked],
   Docker RUST-FEAT-006, SSE RUST-FEAT-007, indexer/Arr RUST-FEAT-002/004,
   parser fuzzing, UPnP-IGD backend stub); platform tier (Windows x64
   release-supported; Linux runtime-proven unpackaged; macOS compile-only).
2. **Version bump** `0.0.3` -> `0.1.0-beta.1` + regenerated `Cargo.lock`.
3. **Release workflow** `.github/workflows/release.yml` on `rust-v*` tags:
   windows runner, `cargo build --release --locked -p emulebb-daemon` with
   default features (assert the `egress-audit` test feature is absent from the
   resolved feature set), stage exe + `emulebb-rust.example.toml` (fail-closed
   VPN defaults verified) + `RELEASE-SCOPE.md` + `LICENSE`, zip + `SHA256SUMS`,
   attach to the GitHub release.
4. **Release documentation:** version-specific changelog (compact
   one-line-per-item, operational focus) + release notes.

## Release Gate (all must hold before the tag)

- [ ] RUST-FEAT-025/030/031/032 closed; A3 registered as an omission.
- [ ] RUST-FEAT-005 closed (dynamic leak evidence incl. the operator
      tunnel-pull gate).
- [ ] RUST-REF-002 parity sweep: zero undispositioned findings.
- [ ] Converged soak gate passed: multi-day rust-vs-MFC soak on the candidate
      build, `diag_event_diff` clean (incl. FEAT-025 `repeatCount` alignment),
      live witness of UDP reask / buddy-callback / firewall-check
      (closes or materially advances RUST-CI-002), HighID + LowID coverage,
      finished-file delivery observed end-to-end, REST responsive throughout.
- [ ] `RELEASE-SCOPE.md` drift-checked against the omissions registry.
- [ ] Operator gives the explicit tagging go.

## Notes

- The INDEX scope note "emulebb-rust is out of RC2 ship scope" remains true for
  the MFC RC2 train; this item creates the rust client's own release gate.
- Docker/GHCR (RUST-FEAT-006) intentionally stays out of this release.
