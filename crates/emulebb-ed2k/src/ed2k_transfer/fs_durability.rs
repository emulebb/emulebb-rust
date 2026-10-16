use std::path::Path;

#[cfg(not(windows))]
use anyhow::Context;
use anyhow::Result;

#[cfg(not(windows))]
pub(super) async fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("path {} has no parent directory", path.display()))?
        .to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::File::open(parent)?.sync_all())
        .await
        .context("directory sync task failed")??;
    Ok(())
}

#[cfg(windows)]
pub(super) async fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}
