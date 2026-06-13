use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use emulebb_daemon::{DaemonConfig, LogBufferLayer, run};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Parser)]
#[command(name = "emulebb-rust", about = "Rust headless eMuleBB client")]
struct Cli {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Console output follows RUST_LOG; the REST log buffer captures INFO+ so
    // GET /api/v1/logs is populated regardless of the console filter.
    tracing_subscriber::registry()
        .with(fmt::layer().with_filter(EnvFilter::from_default_env()))
        .with(LogBufferLayer.with_filter(LevelFilter::INFO))
        .init();
    let cli = Cli::parse();
    run(DaemonConfig::load(cli.config)?).await
}
