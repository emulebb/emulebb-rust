use std::collections::BTreeMap;

use super::*;

#[tokio::test]
async fn category_deletion_remaps_first_middle_last_and_empty_categories_after_restart() {
    for case in [
        DeleteCase {
            name: "first",
            deleted_id: 1,
            transfer_categories: &[1, 2, 3],
            expected_categories: &[(0, "All"), (1, "Two"), (2, "Three")],
            expected_transfer_categories: &[0, 1, 2],
        },
        DeleteCase {
            name: "middle",
            deleted_id: 2,
            transfer_categories: &[1, 2, 3],
            expected_categories: &[(0, "All"), (1, "One"), (2, "Three")],
            expected_transfer_categories: &[1, 0, 2],
        },
        DeleteCase {
            name: "last",
            deleted_id: 3,
            transfer_categories: &[1, 2, 3],
            expected_categories: &[(0, "All"), (1, "One"), (2, "Two")],
            expected_transfer_categories: &[1, 2, 0],
        },
        DeleteCase {
            name: "empty",
            deleted_id: 2,
            transfer_categories: &[1, 3],
            expected_categories: &[(0, "All"), (1, "One"), (2, "Three")],
            expected_transfer_categories: &[1, 2],
        },
    ] {
        assert_delete_case(case).await;
    }
}

#[tokio::test]
async fn failed_category_delete_keeps_memory_and_restart_snapshot_unchanged() {
    let runtime_dir = unique_runtime_dir("category-delete-injected-failure");
    let database_path = runtime_dir.join("metadata.sqlite");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    create_named_categories(&core).await;
    let transfer = create_paused_transfer(&core, 0x41, 2).await;
    let before_categories = category_snapshot(&core).await;
    let before_transfers = transfer_category_snapshot(&core).await;

    let error = category_runtime::delete_category_with_persist(&core.state, 2, |_| async {
        anyhow::bail!("injected category transaction failure")
    })
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "injected category transaction failure");
    assert_eq!(category_snapshot(&core).await, before_categories);
    assert_eq!(transfer_category_snapshot(&core).await, before_transfers);
    assert_eq!(core.transfer(&transfer.hash).await.unwrap().category_id, 2);
    drop(core);

    let restarted = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert_eq!(category_snapshot(&restarted).await, before_categories);
    assert_eq!(
        transfer_category_snapshot(&restarted).await,
        before_transfers
    );
    drop(restarted);
    std::fs::remove_dir_all(runtime_dir).unwrap();
}

#[tokio::test]
async fn transfer_category_update_serializes_before_category_remap() {
    let runtime_dir = unique_runtime_dir("category-delete-concurrent-transfer-update");
    let database_path = runtime_dir.join("metadata.sqlite");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    create_named_categories(&core).await;
    let transfer = create_paused_transfer(&core, 0x51, 1).await;

    let category_guard = core.category_mutation_gate.lock().await;
    let update_core = core.clone();
    let update_hash = transfer.hash.clone();
    let update = tokio::spawn(async move {
        update_core
            .update_transfer(
                &update_hash,
                TransferUpdate {
                    category_id: Some(3),
                    ..TransferUpdate::default()
                },
            )
            .await
    });
    tokio::task::yield_now().await;
    assert!(!update.is_finished());
    let delete_core = core.clone();
    let delete = tokio::spawn(async move { delete_core.delete_category(2).await });
    tokio::task::yield_now().await;
    assert!(!delete.is_finished());
    drop(category_guard);

    update.await.unwrap().unwrap().unwrap();
    delete.await.unwrap().unwrap().unwrap();
    let current = core.transfer(&transfer.hash).await.unwrap();
    assert_eq!(
        (current.category_id, current.category_name.as_str()),
        (2, "Three")
    );
    assert_eq!(
        core.ed2k_transfers
            .manifest(&transfer.hash)
            .await
            .unwrap()
            .category_id,
        2
    );
    drop(core);

    let restarted = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    let restarted_transfer = restarted.transfer(&transfer.hash).await.unwrap();
    assert_eq!(
        (
            restarted_transfer.category_id,
            restarted_transfer.category_name.as_str()
        ),
        (2, "Three")
    );
    drop(restarted);
    std::fs::remove_dir_all(runtime_dir).unwrap();
}

struct DeleteCase {
    name: &'static str,
    deleted_id: u32,
    transfer_categories: &'static [u32],
    expected_categories: &'static [(u32, &'static str)],
    expected_transfer_categories: &'static [u32],
}

async fn assert_delete_case(case: DeleteCase) {
    let runtime_dir = unique_runtime_dir(&format!("category-delete-{}", case.name));
    let database_path = runtime_dir.join("metadata.sqlite");
    let transfer_root = runtime_dir.join("transfers");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    create_named_categories(&core).await;
    for (index, category_id) in case.transfer_categories.iter().copied().enumerate() {
        create_paused_transfer(&core, 0x60 + index as u8, category_id).await;
    }

    core.delete_category(case.deleted_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        category_snapshot(&core).await,
        expected_category_snapshot(case.expected_categories)
    );
    assert_eq!(
        transfer_category_snapshot(&core).await,
        case.expected_transfer_categories
    );
    drop(core);

    let restarted = EmulebbCore::new(
        "test",
        FileIndex::open(&database_path).unwrap(),
        &transfer_root,
    )
    .unwrap();
    assert_eq!(
        category_snapshot(&restarted).await,
        expected_category_snapshot(case.expected_categories)
    );
    assert_eq!(
        transfer_category_snapshot(&restarted).await,
        case.expected_transfer_categories
    );
    drop(restarted);
    std::fs::remove_dir_all(runtime_dir).unwrap();
}

async fn create_named_categories(core: &EmulebbCore) {
    for name in ["One", "Two", "Three"] {
        core.create_category(CategoryCreate {
            name: name.to_string(),
            path: NullableStringField::Missing,
            comment: None,
            color: NullableU32Field::Missing,
            priority: None,
        })
        .await
        .unwrap();
    }
}

async fn create_paused_transfer(core: &EmulebbCore, byte: u8, category_id: u32) -> Transfer {
    let hash = format!("{byte:02x}").repeat(16);
    core.create_transfer(TransferCreate {
        link: Some(format!("ed2k://|file|{byte:02x}.bin|10|{hash}|/")),
        links: None,
        category_id: Some(category_id),
        category_name: None,
        paused: Some(true),
        known_file_policy: Default::default(),
    })
    .await
    .unwrap()
}

async fn category_snapshot(core: &EmulebbCore) -> Vec<(u32, String)> {
    core.categories()
        .await
        .into_iter()
        .map(|category| (category.id, category.name))
        .collect()
}

fn expected_category_snapshot(categories: &[(u32, &str)]) -> Vec<(u32, String)> {
    categories
        .iter()
        .map(|(id, name)| (*id, (*name).to_string()))
        .collect()
}

async fn transfer_category_snapshot(core: &EmulebbCore) -> Vec<u32> {
    core.transfers()
        .await
        .into_iter()
        .map(|transfer| (transfer.hash, transfer.category_id))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}
