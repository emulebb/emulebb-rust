# Rules

- Read `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first; it is authoritative for workspace-wide rules.
- Start from
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\AGENT-CHECKLIST.md`
  for the repeatable operating path.

Everything below is this repo's local deltas only:

- This repo owns the Rust headless eMuleBB client. Keep the public controller
  surface aligned with the Rust-forward `/api/v1` contract in
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust\api`;
  do not treat the frozen emulebb-mfc contract as a forward compatibility
  constraint. Before an explicit Rust API-freeze decision, there is no external
  Rust REST consumer: evolve daemon routes, DTOs, OpenAPI, route/body validators,
  embedded SPA WebUI models, and tests together when a cleaner contract is useful;
  do not keep compatibility aliases or awkward legacy shapes for hypothetical
  consumers. Rust is not an MFC, stock GUI, legacy WebServer, or legacy
  preference mirror: preserve eD2K/Kad protocol-operational parity, but design
  local REST, UI, scheduling, diagnostics, and preference surfaces as clean
  Rust-native async daemon concepts with Rust-native names. Broadband-oriented
  async IO is the daemon baseline, not a compatibility preference or runtime
  toggle.
- Until an explicit Rust API-freeze or release-candidate decision, do not bump
  `apiVersion` or REST `contractVersion` for each route, DTO, validator, or
  OpenAPI cleanup. During this development phase, evolve the implementation,
  OpenAPI artifact, embedded SPA WebUI, and tests together; reserve version
  bumps for deliberate freeze/release boundaries.
- The embedded SPA WebUI is the active UI completeness target. Slint/native UI
  work is a frozen/abandoned experiment unless the operator explicitly requests
  removal or revival work; do not spend UI feature effort there by default.
- Until an explicit Rust freeze or release-candidate decision, Rust development
  cleanup assumes clean state for code, settings, metadata/schema, REST, and UI
  surfaces. Do not add compatibility shims, legacy aliases, old-name remapping,
  compatibility readers, Rust schema migrations, or version bumps for
  development-phase cleanup. When a local persisted development profile must be
  preserved, use an explicit one-off SQLite/Python update against that
  operator-local DB (for example a soak `emulebb-rust-metadata.db`) instead of encoding
  the compatibility path in product code.
- Rust metadata DB schema is current-only. Product Rust code must require the
  checked-in schema exactly; do not add Rust-side schema migrations, fallback
  reads for retired columns, legacy field support, or silent startup repair.
  Persisted live-soak profiles may be repaired only by an explicit ad-hoc Python
  migration in `repos\emulebb-build-tests`, with a backup, leaving the database
  at the current schema. A stale unmigrated DB should fail visibly.
- Retired Rust REST, settings, and metadata fields are hard errors. Do not
  deserialize-and-ignore, alias, remap, or bridge old field names in Rust code.
  If a persisted live-soak profile or harness still emits retired fields, fix it
  outside the Rust product path.
- Follow the responsibility-based source-structure and test-placement policy in
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\products\emulebb-rust\reference\CODE-QUALITY.md`.
  Source length is advisory; split by responsibility, keep substantial tests
  outside production modules, and do not add line-count allowlists.
- BUILD OUTPUT: every `cargo build`/`test`/`run` (debug AND release, orchestrated
  or ad-hoc) MUST set
  `CARGO_TARGET_DIR=%EMULEBB_WORKSPACE_OUTPUT_ROOT%\builds\rust\target`.
  Never let cargo create `target\` in this repo or anywhere under `c:\prj`. A
  `repos\emulebb-rust\target` directory is a policy violation — delete it. See
  WORKSPACE-POLICY.md "Generated build … output belongs under
  EMULEBB_WORKSPACE_OUTPUT_ROOT".
- WINDOWS LONG-PATH SCOPE (binds future work): long-path (>260 char) support is
  for ONLY these operator-facing content path classes — (1) shared-directory
  trees (the configured shared roots + every file scanned/ingested under them),
  (2) incoming downloads (the download/incoming output destination +
  completed-file paths), (3) category paths (per-category download/incoming
  directories). EVERYTHING ELSE STAYS SHORT-PATH ON PURPOSE: config, logs, the
  SQLite metadata DB, the hash-named per-transfer piece-store dirs
  (`transfer_dir(file_hash)`/`pieces.bin`), and all other internals — do NOT add
  long-path handling there. Mechanism (two parts): (A) the daemon EXE embeds a
  `<ws2:longPathAware>true</ws2:longPathAware>` manifest via `embed-manifest` in
  `crates/emulebb-daemon/build.rs` (Windows-gated, no-op elsewhere); (B) the
  `emulebb_ed2k::long_path::long_path(&Path) -> PathBuf` helper rewrites an
  absolute path to its verbatim `\\?\` form (drive + `\\?\UNC\` for UNC) on
  Windows and is identity on non-Windows, applied ONLY at the three content
  boundaries above. NOTE on the current model: completed downloads are
  DELIVERED by name into an operator-facing directory
  (`emulebb_ed2k::ed2k_transfer::deliver` + `emulebb-core/src/delivery.rs`):
  the transfer's `Category.path` when set, otherwise the configured
  `incomingDir`. Delivery hard-links on the same volume (or copies + atomically
  renames across volumes) and keeps the internal short-path piece store as the
  seeding source; both destination classes go through `long_path`.
