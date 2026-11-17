use emulebb_core::{
    CategoryCreate, DownloadCreate, DownloadCreateSource, EmulebbCore, NullableStringField,
};
use emulebb_index::FileIndex;
use std::time::{SystemTime, UNIX_EPOCH};

async fn category(core: &EmulebbCore, name: &str) -> emulebb_core::Category {
    core.create_category(CategoryCreate {
        name: name.into(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Missing,
        comment: None,
    })
    .await
    .unwrap()
}
async fn queue_download(core: &EmulebbCore, hash: &str, category: &str) -> emulebb_metadata::JobId {
    let (created, download) = core
        .create_download(DownloadCreate {
            source: DownloadCreateSource::Content {
                hash: hash.into(),
                name: "Sample.bin".into(),
                size_bytes: Some(4096),
            },
            category: Some(category.into()),
            intent: emulebb_metadata::DownloadIntent::Stopped,
            redownload: false,
        })
        .await
        .unwrap();
    assert!(created);
    assert_eq!(download.category.as_deref(), Some(category));
    download.id
}
#[tokio::test]
async fn download_category_and_public_identity_survive_restart() {
    let root = unique_runtime_dir("category-restart");
    let db = root.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let category = category(&core, "Queued-Samples").await;
    let id = queue_download(&core, "00112233445566778899aabbccddeeff", &category.name).await;
    drop(core);
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let page = core.download_page(Default::default()).await.unwrap();
    assert_eq!(page.downloads.len(), 1);
    assert_eq!(page.downloads[0].id, id);
    assert_eq!(
        page.downloads[0].category.as_deref(),
        Some("Queued-Samples")
    );
    assert_eq!(
        page.downloads[0].state,
        emulebb_core::DownloadState::Stopped
    );
}
#[tokio::test]
async fn deleting_a_category_preserves_other_download_categories_and_names() {
    let root = unique_runtime_dir("category-delete");
    let db = root.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let first = category(&core, "First-Samples").await;
    let deleted = category(&core, "Deleted-Samples").await;
    let surviving = category(&core, "Surviving-Samples").await;
    let first_id = queue_download(&core, "00112233445566778899aabbccddeeff", &first.name).await;
    let deleted_id = queue_download(&core, "102132435465768798a9babbdcddedef", &deleted.name).await;
    let surviving_id =
        queue_download(&core, "ffeeddccbbaa99887766554433221100", &surviving.name).await;
    assert_eq!(
        core.delete_category(deleted.id)
            .await
            .unwrap()
            .unwrap()
            .name,
        deleted.name
    );
    let page = core.download_page(Default::default()).await.unwrap();
    for (id, expected) in [
        (first_id, Some(first.name.as_str())),
        (deleted_id, None),
        (surviving_id, Some(surviving.name.as_str())),
    ] {
        assert_eq!(
            page.downloads
                .iter()
                .find(|download| download.id == id)
                .unwrap()
                .category
                .as_deref(),
            expected
        );
    }
    drop(page);
    let categories = core.categories().await.unwrap();
    assert!(
        categories
            .iter()
            .all(|category| category.name != deleted.name)
    );
    assert!(
        categories
            .iter()
            .any(|category| category.id == surviving.id && category.name == surviving.name)
    );
    drop(core);
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&db).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    let page = core.download_page(Default::default()).await.unwrap();
    assert_eq!(
        page.downloads
            .iter()
            .find(|download| download.id == deleted_id)
            .unwrap()
            .category,
        None
    );
    assert_eq!(
        page.downloads
            .iter()
            .find(|download| download.id == surviving_id)
            .unwrap()
            .category
            .as_deref(),
        Some(surviving.name.as_str())
    );
}

fn unique_runtime_dir(name: &str) -> std::path::PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let path = rust_test_tmp_root().join(format!(
        "emulebb-rust-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create runtime dir");
    path
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
