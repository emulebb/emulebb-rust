// Diagnostics-named flavor of the daemon binary. Identical source to
// `emulebb-rust.rs`, emitted under a distinct name so a packet-diagnostics build
// is never confused with the plain release exe (mirrors the MFC emulebb.exe vs
// emulebb-diagnostics.exe split). This is a thin shim rather than a second
// [[bin]] pointed at the same file because cargo warns when one source path
// backs two build targets; `include!` gives this target its own source path
// while keeping `emulebb-rust.rs` the single source of truth.
include!("emulebb-rust.rs");
