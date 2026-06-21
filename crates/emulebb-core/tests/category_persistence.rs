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

#[tokio::test]
async fn deleting_category_reindexes_later_transfer_categories() {
    let runtime_dir = unique_runtime_dir("emulebb-core-category-delete-reindex");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let first = create_category(&core, "First Samples").await;
    let deleted = create_category(&core, "Deleted Samples").await;
    let shifted = create_category(&core, "Shifted Samples").await;
    let first_hash = "00112233445566778899aabbccddeeff";
    let deleted_hash = "102132435465768798a9babbdcddedef";
    let shifted_hash = "ffeeddccbbaa99887766554433221100";

    create_transfer(&core, first_hash, "First.Category.bin", first.id).await;
    create_transfer(&core, deleted_hash, "Deleted.Category.bin", deleted.id).await;
    create_transfer(&core, shifted_hash, "Shifted.Category.bin", shifted.id).await;

    let removed = core.delete_category(deleted.id).await.unwrap().unwrap();
    assert_eq!(removed.name, deleted.name);

    assert_eq!(
        core.transfer(first_hash).await.unwrap().category_id,
        first.id,
        "categories before the deleted index stay unchanged"
    );
    let deleted_transfer = core.transfer(deleted_hash).await.unwrap();
    assert_eq!(deleted_transfer.category_id, 0);
    // A transfer reset to uncategorized has its category name cleared (consistent
    // with profile_persistence::delete_category_resets_referencing_transfers_to_uncategorized).
    assert_eq!(deleted_transfer.category_name, "");
    let shifted_transfer = core.transfer(shifted_hash).await.unwrap();
    assert_eq!(shifted_transfer.category_id, deleted.id);
    assert_eq!(shifted_transfer.category_name, shifted.name);

    let categories = core.categories().await;
    assert!(
        categories
            .iter()
            .all(|category| category.name != deleted.name)
    );
    assert!(
        categories
            .iter()
            .any(|category| category.id == deleted.id && category.name == shifted.name)
    );

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert_eq!(
        reloaded.transfer(deleted_hash).await.unwrap().category_id,
        0
    );
    let reloaded_shifted = reloaded.transfer(shifted_hash).await.unwrap();
    assert_eq!(reloaded_shifted.category_id, deleted.id);
    assert_eq!(reloaded_shifted.category_name, shifted.name);
}

async fn create_category(core: &EmulebbCore, name: &str) -> emulebb_core::Category {
    core.create_category(CategoryCreate {
        name: name.to_string(),
        path: NullableStringField::Missing,
        comment: None,
        color: NullableU32Field::Missing,
        priority: None,
    })
    .await
    .unwrap()
}

async fn create_transfer(core: &EmulebbCore, hash: &str, name: &str, category_id: u32) {
    core.create_transfer(TransferCreate {
        link: Some(format!("ed2k://|file|{name}|4096|{hash}|/")),
        links: None,
        category_id: Some(category_id),
        category_name: None,
        paused: Some(true),
    })
    .await
    .unwrap();
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
