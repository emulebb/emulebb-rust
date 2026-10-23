use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use emulebb_daemon::{BUILD_VERSION, DaemonProfile, apply_profile_import, logging, run};

#[derive(Debug, Parser)]
#[command(
    name = "emulebb-rust",
    version = BUILD_VERSION,
    about = "Rust headless eMuleBB client"
)]
struct Cli {
    #[arg(short, long)]
    profile: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the REST listener for this run (for example, inside a container)"
    )]
    rest_bind_addr: Option<SocketAddr>,
    #[arg(long, help = "Override the finished-download directory for this run")]
    incoming_dir: Option<PathBuf>,
    #[arg(long, help = "Bind P2P traffic to this named interface for this run")]
    p2p_bind_interface: Option<String>,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    #[command(about = "Merge a portable stock-compatible eMule profile manifest and exit")]
    ImportEmuleProfile {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut profile = match cli.command.as_ref() {
        Some(CliCommand::ImportEmuleProfile { .. }) => {
            let profile_dir = cli
                .profile
                .clone()
                .context("--profile is required when importing an eMule profile")?;
            DaemonProfile::load_for_import(profile_dir)?
        }
        None => DaemonProfile::load(cli.profile)?,
    };
    if let Some(bind_addr) = cli.rest_bind_addr {
        profile.rest.bind_addr = Some(bind_addr);
    }
    if let Some(incoming_dir) = cli.incoming_dir {
        profile.incoming_dir = Some(incoming_dir);
    }
    if let Some(interface) = cli.p2p_bind_interface {
        profile.p2p_bind_interface = Some(interface);
    }
    if let Some(CliCommand::ImportEmuleProfile { manifest }) = cli.command {
        let summary = apply_profile_import(&profile, &manifest)?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    let logging_guard = logging::init(&profile.profile_dir)?;
    let result = run(profile).await;
    if let Err(error) = result.as_ref() {
        tracing::error!(error = ?error, "daemon terminated with an error");
    }
    logging_guard.shutdown().await;
    result
}
