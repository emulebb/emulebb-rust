use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use emulebb_daemon::{
    BUILD_VERSION, DaemonProfile, apply_profile_import, build_version_description, logging, run,
};

#[derive(Debug, Parser)]
#[command(
    name = "emulebb-rust",
    version = BUILD_VERSION,
    long_version = build_version_description(),
    about = "Rust headless eMuleBB client"
)]
struct Cli {
    #[arg(
        long,
        help = "Profile directory; defaults to the executable directory. Relative paths use the caller's working directory."
    )]
    profile: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    #[command(about = "Read or prepare one saved application setting while the daemon is stopped")]
    Settings {
        #[command(subcommand)]
        operation: SettingsCommand,
    },
    #[command(about = "Import supported external profile data while the daemon is stopped")]
    Import {
        #[command(subcommand)]
        operation: ImportCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ImportCommand {
    #[command(about = "Import a portable MFC profile export (SQLite)")]
    Profile {
        #[arg(value_name = "EXPORT")]
        manifest: PathBuf,
        #[arg(
            long,
            help = "Import only portable hashes and retain the selected profile's roots"
        )]
        hashes_only: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SettingsCommand {
    Get { key: String },
    Set { key: String, value: String },
    Reset { key: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(CliCommand::Settings { operation }) = &cli.command {
        use emulebb_daemon::{OfflineSettingsOperation, run_offline_settings};
        let path = cli
            .profile
            .clone()
            .context("--profile is required for offline settings commands")?;
        let operation = match operation {
            SettingsCommand::Get { key } => OfflineSettingsOperation::Get { key: key.clone() },
            SettingsCommand::Set { key, value } => OfflineSettingsOperation::Set {
                key: key.clone(),
                value: value.clone(),
            },
            SettingsCommand::Reset { key } => OfflineSettingsOperation::Reset { key: key.clone() },
        };
        if let Some(value) = run_offline_settings(path, operation)? {
            println!("{value}");
        }
        return Ok(());
    }
    if let Some(CliCommand::Import {
        operation: ImportCommand::Profile {
            manifest,
            hashes_only,
        },
    }) = cli.command
    {
        let profile_dir = cli
            .profile
            .context("--profile is required for offline profile operations")?;
        let profile = DaemonProfile::load_for_import(profile_dir)?;
        let summary = apply_profile_import(&profile, &manifest, hashes_only)?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    let profile = DaemonProfile::load(cli.profile)?;
    // Keep profile ownership until the final diagnostic writer has drained too.
    let profile_lease = profile.profile_lease.clone();
    let logging_guard = logging::init(profile.profile_io_dir())?;
    let result = run(profile).await;
    if let Err(error) = result.as_ref() {
        tracing::error!(error = ?error, "daemon terminated with an error");
    }
    logging_guard.shutdown().await;
    drop(profile_lease);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn current_cli_shape_is_consistent_and_startup_has_one_profile_selector() {
        Cli::command().debug_assert();
        let cli = Cli::try_parse_from(["emulebb-rust", "--profile", "profile"]).unwrap();
        assert_eq!(cli.profile, Some(PathBuf::from("profile")));
        assert!(cli.command.is_none());
        assert!(
            Cli::try_parse_from(["emulebb-rust"])
                .unwrap()
                .profile
                .is_none()
        );
    }

    #[test]
    fn profile_import_uses_explicit_nested_resource_and_export_arguments() {
        let cli = Cli::try_parse_from([
            "emulebb-rust",
            "--profile",
            "profile",
            "import",
            "profile",
            "export.sqlite",
            "--hashes-only",
        ])
        .unwrap();
        assert!(
            matches!(cli.command,Some(CliCommand::Import {operation:ImportCommand::Profile {manifest,hashes_only:true}}) if manifest.as_os_str()=="export.sqlite")
        );
    }

    #[test]
    fn settings_commands_accept_one_key_and_one_plain_or_inline_list_value() {
        for value in ["Sample Client", r#"["pcp-natpmp","upnp"]"#] {
            let cli = Cli::try_parse_from([
                "emulebb-rust",
                "--profile",
                "profile",
                "settings",
                "set",
                "network.nickname",
                value,
            ])
            .unwrap();
            assert!(
                matches!(cli.command,Some(CliCommand::Settings {operation:SettingsCommand::Set {key,value:parsed}}) if key=="network.nickname" && parsed==value)
            );
        }
        for operation in ["get", "reset"] {
            let cli = Cli::try_parse_from([
                "emulebb-rust",
                "--profile",
                "profile",
                "settings",
                operation,
                "network.nickname",
            ])
            .unwrap();
            assert!(matches!(cli.command, Some(CliCommand::Settings { .. })));
        }
    }
}
