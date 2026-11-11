//! Compile-time distribution identity shared by the daemon and REST views.

use std::sync::LazyLock;

pub const BUILD_VERSION: &str = match option_env!("EMULEBB_RELEASE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
pub const BUILD_CHANNEL: &str = match option_env!("EMULEBB_RELEASE_CHANNEL") {
    Some(channel) => channel,
    None => "development",
};
pub const BUILD_SOURCE_REVISION: &str = match option_env!("EMULEBB_SOURCE_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};
pub const BUILD_ARCHITECTURE: &str = if cfg!(target_arch = "aarch64") {
    "arm64"
} else if cfg!(target_arch = "x86_64") {
    "x64"
} else {
    std::env::consts::ARCH
};
pub const BUILD_FLAVOR: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// Describe the same immutable identity in both daemon CLI flavors.
pub fn build_version_description() -> &'static str {
    static DESCRIPTION: LazyLock<String> = LazyLock::new(|| {
        format!("{BUILD_VERSION} ({BUILD_CHANNEL}; {BUILD_ARCHITECTURE}; {BUILD_SOURCE_REVISION})")
    });
    DESCRIPTION.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_description_identifies_the_distribution_without_a_clock() {
        let description = build_version_description();
        assert!(description.starts_with(BUILD_VERSION));
        for identity in [BUILD_CHANNEL, BUILD_ARCHITECTURE, BUILD_SOURCE_REVISION] {
            assert!(description.contains(identity));
        }
        assert_eq!(description, build_version_description());
    }
}
