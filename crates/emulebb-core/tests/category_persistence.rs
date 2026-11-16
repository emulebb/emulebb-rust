use std::time::{SystemTime, UNIX_EPOCH};

use emulebb_core::{CategoryCreate, EmulebbCore, NullableStringField, TransferCreate};
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
            name: "Queued-Samples".to_string(),
            temp_dir: NullableStringField::Missing,
            destination_dir: NullableStringField::Missing,
            comment: None,
        })
        .await
        .unwrap();

    let transfer = core
        .create_transfer(TransferCreate {
            known_file_policy: Default::default(),
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
    assert_eq!(transfer.category_id, Some(category.id));
    assert_eq!(
        transfer.category_name.as_deref(),
        Some(category.name.as_str())
    );

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let reloaded_transfer = reloaded
        .transfer("00112233445566778899aabbccddeeff")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(reloaded_transfer.category_id, Some(category.id));
    assert_eq!(
        reloaded_transfer.category_name.as_deref(),
        Some(category.name.as_str())
    );
}

#[tokio::test]
async fn deleting_category_preserves_other_transfer_categories() {
    let runtime_dir = unique_runtime_dir("emulebb-core-category-delete-stable");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let first = create_category(&core, "First-Samples").await;
    let deleted = create_category(&core, "Deleted-Samples").await;
    let surviving = create_category(&core, "Surviving-Samples").await;
    let first_hash = "00112233445566778899aabbccddeeff";
    let deleted_hash = "102132435465768798a9babbdcddedef";
    let surviving_hash = "ffeeddccbbaa99887766554433221100";

    create_transfer(&core, first_hash, "First.Category.bin", first.id).await;
    create_transfer(&core, deleted_hash, "Deleted.Category.bin", deleted.id).await;
    create_transfer(
        &core,
        surviving_hash,
        "Surviving.Category.bin",
        surviving.id,
    )
    .await;

    let removed = core.delete_category(deleted.id).await.unwrap().unwrap();
    assert_eq!(removed.name, deleted.name);

    assert_eq!(
        core.transfer(first_hash)
            .await
            .unwrap()
            .unwrap()
            .category_id,
        Some(first.id),
        "other category assignments stay unchanged"
    );
    let deleted_transfer = core.transfer(deleted_hash).await.unwrap().unwrap();
    assert_eq!(deleted_transfer.category_id, None);
    // A transfer reset to uncategorized has its category name cleared (consistent
    // with profile_persistence::delete_category_resets_referencing_transfers_to_uncategorized).
    assert_eq!(deleted_transfer.category_name, None);
    let surviving_transfer = core.transfer(surviving_hash).await.unwrap().unwrap();
    assert_eq!(surviving_transfer.category_id, Some(surviving.id));
    assert_eq!(
        surviving_transfer.category_name.as_deref(),
        Some(surviving.name.as_str())
    );

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

    let reloaded = EmulebbCore::new(
        "test",
        FileIndex::open(&metadata_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert_eq!(
        reloaded
            .transfer(deleted_hash)
            .await
            .unwrap()
            .unwrap()
            .category_id,
        None
    );
    let reloaded_surviving = reloaded.transfer(surviving_hash).await.unwrap().unwrap();
    assert_eq!(reloaded_surviving.category_id, Some(surviving.id));
    assert_eq!(
        reloaded_surviving.category_name.as_deref(),
        Some(surviving.name.as_str())
    );
}

async fn create_category(core: &EmulebbCore, name: &str) -> emulebb_core::Category {
    core.create_category(CategoryCreate {
        name: name.to_string(),
        temp_dir: NullableStringField::Missing,
        destination_dir: NullableStringField::Missing,
        comment: None,
    })
    .await
    .unwrap()
}

async fn create_transfer(core: &EmulebbCore, hash: &str, name: &str, category_id: i64) {
    core.create_transfer(TransferCreate {
        known_file_policy: Default::default(),
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
