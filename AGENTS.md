# Rules

- Read
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first.
- For work in this repo, also read the routed
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust\reference\AGENT-POLICY.md`
  annex.

Everything below is this repo's local delta only.

**Lifecycle:** `rust-v0.1.0-beta.2` is the active corrective release line and
the active experimental product-development lane. Beta status is not a
production-readiness claim. Do not rewrite published beta tags or artifacts.

- This repo owns the Rust headless client and embedded SPA WebUI. Keep the
  controller aligned with the Rust-forward `/api/v1` contract under tooling
  docs. Route or DTO changes update daemon code, OpenAPI, validators, WebUI
  models, and tests together. The frozen MFC REST contract is not a forward
  compatibility constraint.
- Do not bump `apiVersion` or REST `contractVersion` without a deliberate
  freeze or release-boundary decision. Do not add speculative compatibility
  aliases, legacy shapes, or MFC/legacy-GUI naming.
- The embedded SPA is the active UI target. Slint/native UI is frozen unless the
  operator explicitly requests removal or revival.
- Keep the current-only persistence model. Every change touching persisted data
  must review whether the checked-in schema remains the clean current model and
  evolve it when warranted.
- Product code must not migrate, repair, reset, delete, move, replace, or
  partially accept an incompatible profile. A stale schema fails visibly and
  instructs the end user to create an entirely fresh profile.
- Backup-first Python migrations in `repos\emulebb-build-tests` are internal
  support for known persisted test/soak schemas only. Never present them as an
  end-user migration or recovery path.
- Retired REST, settings, and metadata fields are hard errors; do not ignore,
  alias, remap, or bridge them.
- `policy\rust-client.toml` and its omission registry own machine-readable
  platform, protocol, long-path, and omission policy. Do not duplicate their
  implementation detail here.
- Follow the tooling
  `docs\products\emulebb-rust\reference\CODE-QUALITY.md` policy for source
  structure, test placement, maintainability, and lint suppressions.
