//! Windows manifest and executable resources for the daemon targets.
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
//! Non-Windows targets do not embed Windows resources.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // The existing manifest integration runs on Windows hosts. Version and
    // icon resources use the Windows SDK for the supported MSVC targets.
    #[cfg(windows)]
    {
        use embed_manifest::manifest::Setting;
        use embed_manifest::{embed_manifest, new_manifest};

        if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
            embed_manifest(new_manifest("EmulebbRust").long_path_aware(Setting::Enabled))
                .expect("failed to embed longPathAware Windows manifest");
            if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
                embed_windows_resources();
            }
        }
    }
}

#[cfg(windows)]
fn embed_windows_resources() {
    use std::{env, fs, path::PathBuf, process::Command};

    const ICON: &str = "resources/windows/application.ico";
    println!("cargo:rerun-if-changed={ICON}");
    println!("cargo:rerun-if-changed=resources/windows/version.rc.in");
    println!("cargo:rerun-if-env-changed=EMULEBB_RELEASE_VERSION");
    println!("cargo:rerun-if-env-changed=EMULEBB_RELEASE_CHANNEL");
    println!("cargo:rerun-if-env-changed=EMULEBB_SOURCE_REVISION");
    println!("cargo:rerun-if-env-changed=WindowsSdkDir");
    println!("cargo:rerun-if-env-changed=WindowsSDKVersion");

    let architecture = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture");
    let sdk = find_msvc_tools::find_windows_sdk(&architecture)
        .expect("install the Windows SDK to compile daemon executable resources");
    let compiler = sdk
        .path()
        .map(|directory| directory.join("rc.exe"))
        .find(|path| path.is_absolute() && path.is_file())
        .expect("install the Windows SDK resource compiler (rc.exe) for the build host");

    // Match BUILD_VERSION and keep the SemVer string safe in the RC literal.
    let version = match env::var("EMULEBB_RELEASE_VERSION") {
        Ok(version) => version,
        Err(env::VarError::NotPresent) => env!("CARGO_PKG_VERSION").to_owned(),
        Err(error) => panic!("invalid EMULEBB_RELEASE_VERSION: {error}"),
    };
    assert!(
        !version.is_empty()
            && version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')),
        "the executable resource version must use ASCII SemVer characters"
    );
    let [major, minor, patch] = [
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH"),
    ]
    .map(|component| {
        component
            .parse::<u16>()
            .expect("Cargo version component exceeds the Windows version-resource range")
    });
    let fixed_version = format!("{major},{minor},{patch},0");
    let channel = env::var("EMULEBB_RELEASE_CHANNEL").unwrap_or_else(|_| "development".to_owned());
    assert!(
        matches!(
            channel.as_str(),
            "development" | "candidate" | "beta" | "nightly"
        ),
        "the executable resource channel must use a supported build channel"
    );
    let source_revision =
        env::var("EMULEBB_SOURCE_REVISION").unwrap_or_else(|_| "unknown".to_owned());
    assert!(
        source_revision == "unknown"
            || (source_revision.len() == 40
                && source_revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())),
        "the executable resource source must be unknown or a full lowercase commit"
    );
    let architecture_label = match architecture.as_str() {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo build output directory"));
    // Give RC a relative ASCII icon name regardless of the checkout path.
    fs::copy(ICON, out_dir.join("application.ico")).expect("copy approved application icon");

    let mut binaries = vec![("emulebb-rust", "eMuleBB", "eMuleBB Rust daemon")];
    if env::var_os("CARGO_FEATURE_PACKET_DIAGNOSTICS").is_some() {
        binaries.push((
            "emulebb-rust-diagnostics",
            "eMuleBB Diagnostics",
            "eMuleBB Rust diagnostics daemon",
        ));
    }
    for (binary, product, description) in binaries {
        let script = format!("{binary}.rc");
        let resource = format!("{binary}.res");
        let contents = format!(
            include_str!("resources/windows/version.rc.in"),
            fixed_version = fixed_version,
            version = version,
            binary = binary,
            product = product,
            description = description,
            channel = channel,
            architecture = architecture_label,
            source_revision = source_revision,
        );
        fs::write(out_dir.join(&script), contents).expect("write Windows resource script");
        let output = Command::new(&compiler)
            .current_dir(&out_dir)
            .args(["/nologo", "/fo", &resource, &script])
            .output()
            .expect("run Windows SDK resource compiler");
        assert!(
            output.status.success(),
            "Windows resource compilation failed for {binary} ({}):\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "cargo:rustc-link-arg-bin={binary}={}",
            out_dir.join(resource).display()
        );
    }
}
