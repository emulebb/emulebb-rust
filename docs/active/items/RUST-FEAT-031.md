---
id: RUST-FEAT-031
workflow: github
github_issue: TBD - file on emulebb/emulebb-rust when scheduled
title: Kad - handle inbound legacy KADEMLIA_FIREWALLED_ACK_RES (0x59)
status: OPEN
priority: Minor
category: feature
labels: [kad, firewall-check, legacy-interop, parity]
milestone: release-0.1.0-beta.1
created: 2026-07-05
source: Protocol & internals parity review 2026-07-02 (finding A2, corrected 2026-07-05); 0.1.0-beta.1 release program (2026-07-05)
---

> Workflow status is tracked in GitHub. This local document is retained as an engineering spec/evidence record.

# RUST-FEAT-031 - Inbound legacy `KADEMLIA_FIREWALLED_ACK_RES` (0x59)

## Summary

Add the missing inbound dispatch arm for the legacy Kad firewall-check ack
(0x59). The **outbound** helper leg already exists (`f3787bd`, 2026-06-16):
`spawn_kad_firewalled_response` (`crates/emulebb-core/src/kad_hello.rs:289-317`)
TCP-probes a legacy `FIREWALLED_REQ` (0x50) requester and sends
`KadPacket::FirewalledAckRes` on success. Decode exists in
`emulebb-kad-proto/src/packet.rs`, but core has no dispatch arm for the inbound
packet, so a legacy helper's ack is silently dropped.

## Oracle

`srchybrid/kademlia/net/KademliaUDPListener.cpp:1707`
(`Process_KADEMLIA_FIREWALLED_ACK_RES`): validates zero length and calls
`CKademlia::GetPrefs()->IncFirewalled()`. MFC keys the outbound ack channel on
peer Kad version (`ClientList.cpp:653-667`); rust keys it on request opcode
(0x50 -> UDP 0x59, 0x53 -> TCP `OP_KAD_FWTCPCHECK_ACK`), behaviorally
equivalent since only v7+ peers emit FIREWALLED2_REQ.

## Intended Shape

- Dispatch arm in `crates/emulebb-core/src/lib.rs` beside the existing
  `FirewalledReq`/`Firewalled2Req`/`FirewalledRes` arms, routing into the Kad
  TCP-recheck ack accounting.
- Source-validate against the currently probed helper (stricter than MFC's
  unvalidated `IncFirewalled()`, consistent with rust's anti-spoof posture on
  the FirewalledRes path).

## Acceptance Criteria

- [ ] Unit test: 0x59 from the probed helper is accepted and counted by the
      firewall-check accounting.
- [ ] Unit test: 0x59 from an unrelated source is dropped.
- [ ] No change to the outbound legs (0x50->0x59, 0x53->TCP ack), which stay
      covered by existing tests.

## Notes

Practical impact is legacy tolerance + diagnostics only: rust advertises a
modern Kad version, so live helpers answer its own checks over TCP.
