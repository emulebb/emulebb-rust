---
id: RUST-BUG-045
status: done
type: bug
area: tests
---

# RUST-BUG-045: Keep legacy Kad challenge tests loopback-local

## Problem

Two legacy Kad challenge unit tests used documentation-only public IPv4 ranges
as UDP send targets while exercising the real DHT socket. On Windows hosts
without a route to those ranges, the tests failed with `NetworkUnreachable`
before they could assert the challenge-tracker behavior.

## Resolution

- Switched the real UDP send targets in those tests to loopback.
- Kept the tests focused on legacy challenge tracking and contact verification.

## Evidence

- `cargo test -p emulebb-kad-dht node::legacy_challenge --locked`
