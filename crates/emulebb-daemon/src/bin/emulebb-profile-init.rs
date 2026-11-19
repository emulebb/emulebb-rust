//! Package-private first-run provisioning; not a daemon CLI command.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use std::path::Path;
    emulebb_daemon::container_profile::initialize(
        Path::new("/config/emulebb-rust"),
        Path::new("/data/incoming"),
        Path::new("/data/temp"),
    )
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("The container profile initializer requires Linux.")
}
