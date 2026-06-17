# Rules

- Read `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\WORKSPACE-POLICY.md`
  first; it is authoritative for workspace-wide rules.
- Start from
  `EMULEBB_WORKSPACE_ROOT\repos\emulebb-tooling\docs\reference\AGENT-CHECKLIST.md`
  for the repeatable operating path.

Everything below is this repo's local deltas only:

- This repo owns the Rust headless eMuleBB client. Keep the public controller
  surface aligned with the canonical eMuleBB `/api/v1` REST contract.
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
  boundaries above. NOTE on the current model: there is no separate operator
  download/incoming output path — completed payloads live in the internal
  short-path piece store — and `Category.path` is validated/stored but not yet
  used to open output files; the helper is wired where a category path is
  consumed so the boundary is ready when category-rooted output lands.
