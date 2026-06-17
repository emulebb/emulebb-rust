---
id: RUST-FEAT-007
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: REST push - Server-Sent Events stream for live transfer updates (+ transfers.sse capability)
status: OPEN
priority: Minor
category: feature
labels: [rest, push, sse, controller, contract]
milestone: phase-2
created: 2026-06-17
source: TrackMuleBB dashboard design discussion (2026-06-17); see trackmulebb TMBB-FEAT-014 and docs/design/MVP-UNIFIED-TRANSFERS.md
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-007 - REST push: Server-Sent Events stream for live transfer updates

## Summary

Add a **push** path to `/api/v1` so a controller (TrackMuleBB) gets transfer state
changes without polling. Expose `GET /api/v1/events` as a `text/event-stream`
(Server-Sent Events) that emits transfer change events (add / update / remove),
and advertise the `transfers.sse` capability via `GET /capabilities`. The existing
`GET /api/v1/transfers` full-poll stays as the baseline + fallback.

SSE is chosen over WebSocket because the dashboard need is **unidirectional
server -> client**: commands (pause/resume/add) already flow through normal REST
`POST`s, so a bidirectional socket would be pure overhead. SSE is plain HTTP,
reuses the `X-API-Key` header, and supports resume via `Last-Event-ID`.

## Why This Matters

`/transfers` re-serializes the whole list every poll; push delivers only changes,
near-instantly, and scales with churn rather than library size. emulebb-rust is
already event-driven internally (it is the source of truth), so the events exist —
this just surfaces them.

## Intended Shape

- `GET /api/v1/events` -> `text/event-stream`; each event carries a monotonically
  increasing id and a JSON payload of the changed transfer(s) (same field shape as
  the `Transfer` DTO) plus a `removed` form keyed by hash.
- Internal **Tokio `broadcast` bus**: the transfer manager publishes change events;
  the SSE handler fans them out to subscribers. Periodic heartbeat/comment line to
  keep the connection alive through proxies.
- Resume: honour `Last-Event-ID` (replay-from or signal "re-baseline via
  `/transfers`"). Auth unchanged (`X-API-Key`).
- `GET /capabilities` advertises `transfers.sse` so a controller gates on it and
  falls back to poll when absent.
- (Considered, not chosen) a delta-**pull** `GET /api/v1/sync?rid=N` mirroring
  qBittorrent's `/sync/maindata`; recorded as the lower-effort alternative if a
  long-lived stream is undesirable.

## Acceptance Criteria

- [ ] `GET /api/v1/events` streams add/update/remove transfer events as SSE with
      incrementing event ids; survives a quiet period via heartbeats.
- [ ] `Last-Event-ID` either replays missed events or instructs a `/transfers`
      re-baseline; no silent gaps.
- [ ] `GET /capabilities` lists `transfers.sse`; `/transfers` is unchanged.
- [ ] Auth via `X-API-Key`; contract version (`x-contract-version`) bumped.

## Notes

- **RC2 soft-freeze:** this is a *forward-lineage* `/api/v1` contract addition, not
  a parity/release-blocking fix. Design now, **schedule after the freeze** (the
  backlog explicitly stages design work; emulebb-rust is out of RC2 ship scope).
- Controller side: trackmulebb **TMBB-FEAT-014** (capability-gated push adapter,
  poll fallback). qBittorrentBB has no SSE; its push-ish path is the `/sync/maindata`
  delta (trackmulebb TMBB-FEAT-005) — both unify behind one adapter abstraction.
