# Converged Soak Runbook — `rust-v0.1.0-beta.1` release gate

RUST-FEAT-033 Phase-4 gate. This is the operator-driven live validation that
must pass before the `rust-v0.1.0-beta.1` tag. The parity baseline is validated
(RUST-REF-002 done; see `PARITY-REVIEW-2026-07-05.md`); this soak witnesses the
shipped behavior on the live network and captures the release evidence.

Live-wire conduct is binding: **be gentle** — a few widely-spaced actions, no
run spamming ([[live-wire-be-gentle-no-ban]]); both clients ALWAYS on the
operator server + Kad ([[both-clients-operator-server-and-kad]]); LAN in the
hide.me `ExcludeIPRanges` so REST (`X_LOCAL_IP`) stays reachable while P2P
tunnels; well-sourced ubuntu/linux ISO fixtures only ([[live-test-content-well-sourced]]);
**no private data / real media titles** in any recorded evidence.

## Pre-requisites

1. **Rust diagnostics candidate** (built this session):
   `cargo build --release --locked -p emulebb-daemon --bin emulebb-rust-diagnostics --features packet-diagnostics`
   → `%EMULEBB_WORKSPACE_OUTPUT_ROOT%\builds\rust\target\release\emulebb-rust-diagnostics.exe`.
   The soak harness resolves it via `resolve_rust_diagnostics_exe`.
2. **MFC diagnostics build** (operator, MSVC): the `main` variant Release
   `--diagnostics` build → `builds/app/main/x64/Release/diagnostics/bin/emulebb-diagnostics.exe`
   via `python -m emule_workspace build app --variant main --config Release --platform x64 --diagnostics`.
   Must be current (post the FEAT-025 oracle seams).
3. **Operator inputs** — `live-wire-inputs.local.json` (operator-owned, gitignored):
   `mfc_profile.profile_dir` set to the persisted MFC profile (rust auto-mirrors
   its `config\shareddir.dat` shared set); linux `search_terms.generic_open`
   (`ubuntu iso` / `linux iso` / …); `deterministic_downloads` (auto-populated).
4. **`vpn-guard-live.local.json`** (gitignored, beside the inputs): the hide.me
   `allowedPublicIpCidrs` allowlist + `p2pBindInterfaceName: hide.me`. The harness
   activates VPN Guard `Block` on **both** clients from this file and validates the
   exit against it — no manual profile edit needed.
5. **hide.me VPN** connected, LAN `192.168.1.0/24` in `ExcludeIPRanges`.

## Run

From `repos/emulebb-build-tests` (the shared harness):

```
python scripts/converged-soak-live.py --inputs <path>\live-wire-inputs.local.json --duration 4h
```

Defaults already target the operator server (`--rust-server` / `--mfc-server` =
`45.82.80.155:5687`) and Kad, with persistent isolated profiles under `soak/`,
a 5 s REST poll, and 5-minute stability/coverage checkpoints. The harness
launches both clients, drives synchronized actions, and runs the
observe-and-correlate `soak_action_diff` + `diag_event_diff`.

On start it also, automatically: (1) enforces VPN Guard `Block` on both clients,
then reads each client's **own** guard verdict over REST (`data.network.vpnGuard`)
— the client runs the bound HTTP + STUN egress probes itself (eMuleBB
`PublicIpProbe` / rust RUST-FEAT-034) and validates its public IP against the
allowlist; the harness aborts if either client's guard is inactive, startup-blocked,
or (rust) reports `egressVerified=false`; (2) seeds the **12 most-sourced common linux downloads**
(`--seed-downloads 12`) on both clients and records them as deterministic
fixtures for re-runs. The rust runtime persists at
`%EMULEBB_WORKSPACE_OUTPUT_ROOT%\soak\rust-runtime` (`--fresh-rust-runtime` for a
clean per-campaign profile).

## Gate criteria (record all as release evidence)

- [ ] **Parity diff clean** — `diag_event_diff` shows no unregistered
      divergence; in particular the FEAT-025 `upload_duplicate_done_block_rejected`
      / `_queued_` events align with MFC on `repeatCount` + `windowSeconds` (the
      exact conformance check that caught the original revert).
- [ ] **Subsystem witness** — UDP source reask, buddy / buddy-relayed callback,
      and Kad UDP+TCP firewall self-check observed live (advances/closes
      RUST-CI-002). HighID **and** LowID sessions both covered.
- [ ] **Finished-file delivery** — a download completes and is materialized by
      name into `incomingDir`/category end-to-end.
- [ ] **REST responsive throughout** — no control-plane starvation under
      hashing / Kad-publish load ([[rest-starvation-root-causes]]).
- [ ] **VPN exit validated (automated, client-side)** — each client's own VPN
      Guard reports active + not blocked, and rust's `egressVerified=true` (bound
      HTTP+STUN probes resolved an allowlisted public IP); recorded under
      `vpnExitValidation` in the run summary.
- [ ] **Leak gate (operator wire-truth)** — with the daemon bound to the live
      hide.me tunnel, pull the tunnel mid-soak and confirm (pktmon on the
      physical NIC) **zero** off-tunnel eD2K/Kad packets. This is the Windows
      wire-truth complement to the CI socket-truth leak test (RUST-FEAT-005);
      `tools/vpn_leak_local_gate.py` is the intended harness (to be scripted if
      not yet present).

## On pass

Record the evidence bundle, then (and only then) the operator gives the explicit
tag go: annotate `rust-v0.1.0-beta.1` on the reviewed commit → the
`release.yml` workflow builds and publishes the unsigned Windows x64 zip.
Close RUST-FEAT-005 (leak gate witnessed) and RUST-FEAT-033.
