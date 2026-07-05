---
id: RUST-FEAT-030
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: Kad - implement KADEMLIA_FIND_VALUE_MORE re-ask in lookup traversal
status: OPEN
priority: Minor
category: feature
labels: [kad, traversal, search, parity]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: Protocol & internals parity review 2026-07-02 (finding A1); 0.1.0-beta.1 release program (2026-07-05)
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-030 - Kad `KADEMLIA_FIND_VALUE_MORE` re-ask

## Summary

Implement the stock Kad lookup fallback: when a FIND_VALUE lookup stalls with
its two closest tried contacts unresponsive, re-ask the closest *responded*
contact with contact count `KADEMLIA_FIND_VALUE_MORE` (11) instead of the
normal `KADEMLIA_FIND_VALUE` (2), and admit the larger response only from that
contact. Missing today; slightly lowers keyword/source search recall in sparse
result neighborhoods vs MFC.

## Oracle

`srchybrid/kademlia/kademlia/Search.cpp:288-304, 1334-1341, 352`: during
JumpStart, if no re-ask has happened yet, request count == FIND_VALUE (2),
>= 3*2 contacts tried, and none of the 2 closest tried contacts responded ->
re-ask the closest responded contact with count 11, remember that contact; the
inbound guard then admits <= 11 contacts from exactly that contact.

## Intended Shape

- `crates/emulebb-kad-dht/src/traversal.rs`: add `more_asked: Option<NodeId>`
  to the lookup-phase state; trigger inside the jumpstart/idle path over the
  distance-sorted candidates (first 2 tried are Failed, some later candidate is
  Responded); send one extra query with count 11; set `more_asked` once per
  lookup.
- Widen `insert_response_contacts` sanitize limit to `KADEMLIA_FIND_NODE` (11)
  only when the responding contact is `more_asked`; every other contact keeps
  the configured `req_count` cap.

## Acceptance Criteria

- [ ] Unit test: stalled FIND_VALUE lookup with dead best-2 fires exactly one
      re-ask with count 11 to the closest responded contact.
- [ ] Unit test: an 11-contact response is accepted from the more-asked contact
      and truncated/dropped from any other contact.
- [ ] Existing traversal tests unaffected; wire shape unchanged
      (`KADEMLIA2_SEARCH_KEY/SOURCE` req count byte only).
