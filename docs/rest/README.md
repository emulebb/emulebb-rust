# Forward `/api/v1` contract (emulebb-rust owned)

`REST-API-OPENAPI.yaml` here is the **source of truth for the forward eMuleBB
`/api/v1` contract**, owned by emulebb-rust (split decision 2026-06-15).

- It is baselined on the frozen eMuleBB `0.7.3` contract and evolves on its own
  independent **contract version** (`x-contract-version`, semver), decoupled from
  any product release tag and from the frozen MFC client.
- emulebb-rust is the only forward implementer; **TrackMuleBB** is the consumer.
  TrackMuleBB targets a contract version range and degrades by capability.
- Change the spec **in the same change** as the implementation; an OpenAPI
  conformance/drift check (validating live responses against this document)
  belongs in this repo's CI. (TODO: wire the conformance check.)
- Adapter surfaces (`/api/v2` qBit-compat, Torznab) must not broaden or weaken
  this native contract.

The frozen `0.7.3` lineage (MFC client + aMuTorrent) lives at
`emulebb-tooling/docs/rest/REST-API-OPENAPI.yaml` and does not evolve. Split and
versioning policy: `emulebb-tooling/docs/active/API-V1-COMPATIBILITY.md`.
