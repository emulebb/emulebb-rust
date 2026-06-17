//! Build script for the `emulebb-rust` daemon binary.
//!
//! On Windows it embeds an application manifest that declares
//! `<ws2:longPathAware>true</ws2:longPathAware>`. Together with the OS-level
//! `LongPathsEnabled` registry switch (Windows 10 1607+), this lets the standard
//! library's filesystem APIs accept operator-facing paths longer than the legacy
//! `MAX_PATH` (260) limit. The verbatim `\\?\` boundary helper in
//! `emulebb-ed2k` (`long_path`) is the complementary, per-path part of the
//! long-path support; this manifest is the process-global enabler.
//!
//! The long-path scope is bound by the operator rule recorded in `AGENTS.md`
//! and `policy/rust-client.toml`: only operator-facing content path classes
//! (shared-directory trees, incoming downloads, category paths) get long-path
//! handling; config/logs/the SQLite DB/internal piece-store dirs stay short.
//!
//! On every non-Windows target this build script is a no-op (the manifest is a
//! Windows-only concept), so it never affects Linux/macOS builds.

fn main() {
    // Re-run only when this script itself changes; the embedded manifest has no
    // external inputs.
    println!("cargo:rerun-if-changed=build.rs");

    // `CARGO_CFG_WINDOWS` is set by cargo when the *target* is Windows, which is
    // the correct gate for a Windows-only manifest (host-independent, so a cross
    // build still embeds it for a Windows target and skips it otherwise).
    #[cfg(windows)]
    {
        use embed_manifest::manifest::Setting;
        use embed_manifest::{embed_manifest, new_manifest};

        if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
            embed_manifest(new_manifest("EmulebbRust").long_path_aware(Setting::Enabled))
                .expect("failed to embed longPathAware Windows manifest");
        }
    }
}
