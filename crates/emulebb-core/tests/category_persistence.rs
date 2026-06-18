use std::time::{SystemTime, UNIX_EPOCH};

use emulebb_core::{
    CategoryCreate, EmulebbCore, NullableStringField, NullableU32Field, TransferCreate,
};
use emulebb_index::FileIndex;

#[tokio::test]
async fn transfer_category_survives_restart() {
    let runtime_dir = unique_runtime_dir("emulebb-core-transfer-category-restart");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let category = core
        .create_category(CategoryCreate {
            name: "Queued Samples".to_string(),
            path: NullableStringField::Missing,
            comment: None,
            color: NullableU32Field::Missing,
            priority: None,
        })
        .await
        .unwrap();

    let transfer = core
        .create_transfer(TransferCreate {
            link: Some(
                "ed2k://|file|Category.Restart.bin|4096|00112233445566778899aabbccddeeff|/"
                    .to_string(),
            ),
            links: None,
            category_id: Some(category.id),
            category_name: None,
            paused: Some(true),
        })
        .await
        .unwrap();
    assert_eq!(transfer.category_id, category.id);
    assert_eq!(transfer.category_name, category.name);

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let reloaded_transfer = reloaded
        .transfer("00112233445566778899aabbccddeeff")
        .await
        .unwrap();

    assert_eq!(reloaded_transfer.category_id, category.id);
    assert_eq!(reloaded_transfer.category_name, category.name);
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
