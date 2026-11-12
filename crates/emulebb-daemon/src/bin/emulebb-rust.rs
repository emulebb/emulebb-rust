use std::net::SocketAddr;
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
    #[arg(short, long)]
    profile: Option<PathBuf>,
    #[arg(
        long,
        help = "Override the REST/WebUI listener for this run (for example, 127.0.0.1:20017); persist it as rest.bind_addr in the bootstrap TOML"
    )]
    rest_bind_addr: Option<SocketAddr>,
    #[arg(long, help = "Override the finished-download directory for this run")]
    incoming_dir: Option<PathBuf>,
    #[arg(
        long,
        help = "Bind P2P traffic to this named interface for this run; save the P2P bind interface in WebUI Settings > Network to persist it"
    )]
    p2p_bind_interface: Option<String>,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    #[command(
        about = "Reconcile imported/cached hashes with file metadata; never hash or start networking"
    )]
    ReconcileSharedFiles,
    #[command(
        about = "Merge a shared-directory text list, reuse live hashes, hash new or changed files offline, and exit"
    )]
    ImportSharedDirectories { file: PathBuf },
    #[command(about = "Merge a portable SQLite eMule profile export and exit")]
    ImportEmuleProfile {
        #[arg(value_name = "MANIFEST")]
        manifest: PathBuf,
        #[arg(
            long,
            help = "Import only portable hashes; keep the target's shared roots"
        )]
        hashes_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut profile = match cli.command.as_ref() {
        Some(_) => {
            let profile_dir = cli
                .profile
                .clone()
                .context("--profile is required for offline profile operations")?;
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
    if let Some(CliCommand::ImportEmuleProfile {
        manifest,
        hashes_only,
    }) = cli.command
    {
        let summary = apply_profile_import(&profile, &manifest, hashes_only)?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
    if matches!(
        cli.command,
        Some(CliCommand::ReconcileSharedFiles | CliCommand::ImportSharedDirectories { .. })
    ) {
        if let Some(CliCommand::ImportSharedDirectories { ref file }) = cli.command {
            let store = profile.open_metadata_store()?;
            emulebb_daemon::shared_directory_import::import_shared_directories(&store, file)?;
        }
        let core = emulebb_core::EmulebbCore::new(
            BUILD_VERSION,
            emulebb_index::FileIndex::from_metadata_store(profile.open_metadata_store()?),
            profile.transfer_root(),
        )?
        .with_profile_dir(profile.profile_io_dir().to_path_buf())
        .with_incoming_dir(profile.incoming_dir());
        if matches!(
            cli.command,
            Some(CliCommand::ImportSharedDirectories { .. })
        ) {
            let reload = core.reload_shared_directories();
            tokio::pin!(reload);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    result = &mut reload => { result?; break; }
                    _ = interval.tick() => {
                        // WHY: awaiting a root snapshot here can wait on the
                        // reload future that this select must keep driving.
                        let progress = core.shared_directory_reload_progress();
                        let remaining = progress.planned_hash_count.saturating_sub(progress.hashed_count + progress.failed_hash_count);
                        eprintln!("phase={}; hashed={}; remaining={}; reused={}",progress.phase,progress.hashed_count,remaining,progress.reused_count);
                    }
                }
            }
            let work = core.shared_directory_reload_progress();
            let reconciliation = core.reconcile_shared_files().await?;
            let metadata = profile.open_metadata_store()?;
            let missing_recovery =
                tokio::task::spawn_blocking(move || metadata.missing_live_aich_recovery_count())
                    .await??;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"hashing":work,"reconciliation":reconciliation,"missingAichRecoverySets":missing_recovery})
                )?
            );
            return Ok(());
        }
        let summary = core.reconcile_shared_files().await?;
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }
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
