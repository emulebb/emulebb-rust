---
id: RUST-BUG-060
title: Accept ED2K UDP search replies from any requested server
status: done
priority: Major
category: bug
workflow: local
---

# RUST-BUG-060: Accept ED2K UDP search replies from any requested server

## Problem

Rust accepted `OP_GLOBSEARCHRES` packets only when they came from the server
currently occupying the active per-server wait slot.

eMuleBB MFC records every server IP that was sent a UDP search request and
accepts search answers from any of those requested IPs. A valid reply that
arrives after the timer has advanced to a later server should therefore still
be processed.

## Acceptance

- [x] UDP keyword search replies are accepted from any server IP already queried
      during the active global search.
- [x] Unrequested server IPs remain ignored.
- [x] The acceptance rule is covered by focused unit coverage.

## Implementation Notes

- Tracked resolved servers after each successful UDP keyword request.
- Matched incoming UDP search answers against the requested server IP set instead
  of only the current per-server wait slot.

## Evidence

- `cargo test -p emulebb-ed2k udp_keyword_search_accepts_replies_from_any_queried_server_ip --locked`
- `cargo test -p emulebb-ed2k ed2k_server --locked`
