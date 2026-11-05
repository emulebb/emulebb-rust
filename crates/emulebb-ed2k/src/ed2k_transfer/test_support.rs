use std::path::Path;

use emulebb_metadata::MetadataSharedDirectoryRoot;

use super::Ed2kTransferRuntime;

/// Admit a fully hashed fixture through a real root and refresh its live offer.
pub(crate) async fn admit_local_share(runtime: &Ed2kTransferRuntime, root: &Path, path: &Path) {
    let mut metadata = runtime.metadata.clone();
    metadata
        .replace_shared_directory_roots(&[MetadataSharedDirectoryRoot {
            path: root.to_string_lossy().into_owned(),
            monitor_owned: false,
            shareable: true,
            accessible: true,
        }])
        .unwrap();
    let path = crate::long_path::long_path(path);
    let fingerprint = metadata
        .local_file_instance(&path)
        .unwrap()
        .expect("fixture must be fully hashed before root admission")
        .verified_fingerprint;
    let relative = path
        .strip_prefix(crate::long_path::long_path(root))
        .unwrap();
    assert!(
        metadata
            .admit_local_path_to_root(root, &path, relative, &fingerprint)
            .unwrap()
    );
    runtime.refresh_complete_shared_catalog().await.unwrap();
}
