use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use emulebb_daemon::{DaemonConfig, run};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "emulebb-rust", about = "Rust headless eMuleBB client")]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    run(DaemonConfig::load(cli.config)?).await
}
