use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use emulebb_daemon::{DaemonProfile, logging, run};

#[derive(Debug, Parser)]
#[command(name = "emulebb-rust", about = "Rust headless eMuleBB client")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut profile = DaemonProfile::load(cli.profile)?;
    if let Some(bind_addr) = cli.rest_bind_addr {
        profile.rest.bind_addr = Some(bind_addr);
    }
    if let Some(incoming_dir) = cli.incoming_dir {
        profile.incoming_dir = Some(incoming_dir);
    }
    if let Some(interface) = cli.p2p_bind_interface {
        profile.p2p_bind_interface = Some(interface);
    }
    let logging_guard = logging::init(&profile.profile_dir)?;
    let result = run(profile).await;
    if let Err(error) = result.as_ref() {
        tracing::error!(error = ?error, "daemon terminated with an error");
    }
    logging_guard.shutdown().await;
    result
}
