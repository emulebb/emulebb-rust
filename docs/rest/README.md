# `/api/v1` contract — canonical superset (emulebb-rust owned)

`REST-API-OPENAPI.yaml` here is the **source of truth for the one capability-gated
eMuleBB `/api/v1` contract**. There is a single contract; implementations differ
by the **capabilities** they advertise, not by a separate spec. emulebb-rust is
the **superset** (it leads the contract version and adds indexing/Arr
capabilities); the frozen eMuleBB MFC client is a **subset** that advertises
fewer capabilities.

- It is baselined on the eMuleBB `0.7.3` contract and evolves on its own
  independent **contract version** (`x-contract-version`, semver), decoupled from
  any product release tag. Additive endpoints/fields bump the minor; breaking
  changes bump the major with a documented migration.
- **TrackMuleBB** is the consumer: it reads `GET /api/v1/capabilities`, targets a
  contract-version range, and **only calls advertised operations** — so the same
  controller drives both emulebb-rust (full) and the MFC (frozen `core.*` subset)
  with no per-client branching.
- Change the spec **in the same change** as the implementation; an OpenAPI
  conformance/drift check (validating live responses against this document, per
  advertised capability) belongs in this repo's CI. (TODO: wire the conformance
  check.)
- Adapter surfaces (`/api/v2` qBit-compat, Torznab) must not broaden or weaken
  the native contract.

Contract model and capability policy:
`emulebb-tooling/docs/active/API-V1-COMPATIBILITY.md` (supersedes the prior
"two divergent lineages" split). The frozen MFC ships the same contract's
`core.*` subset (plus `GET /api/v1/capabilities` for discovery) and does not
evolve.
