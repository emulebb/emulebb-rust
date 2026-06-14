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
