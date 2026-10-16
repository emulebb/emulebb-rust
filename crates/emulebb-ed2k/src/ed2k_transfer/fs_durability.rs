use std::path::Path;

#[cfg(not(windows))]
use anyhow::Context;
use anyhow::Result;

#[cfg(not(windows))]
pub(super) async fn sync_parent_directory(path: &Path) -> Result<()> {
    let mut parent = path
        .parent()
        .with_context(|| format!("path {} has no parent directory", path.display()))?
        .to_path_buf();
    let display_path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        loop {
            match parent.symlink_metadata() {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    match std::fs::File::open(&parent) {
                        Ok(directory) => {
                            directory.sync_all().with_context(|| {
                                format!("failed to sync directory {}", parent.display())
                            })?;
                            return Ok(());
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            anyhow::ensure!(
                parent.pop(),
                "no existing parent directory for {}",
                display_path.display()
            );
        }
    })
    .await
    .context("directory sync task failed")??;
    Ok(())
}

#[cfg(windows)]
pub(super) async fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn syncs_nearest_existing_ancestor_when_parent_is_missing() {
        let root = tempfile::tempdir().unwrap();
        let missing_path = root.path().join("removed-parent").join("payload.bin");

        sync_parent_directory(&missing_path).await.unwrap();
    }
}
