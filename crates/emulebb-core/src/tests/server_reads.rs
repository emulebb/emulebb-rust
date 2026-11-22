use super::*;
use emulebb_metadata::{MetadataServerQuery, MetadataServerReadError, SERVER_READ_MAX_BYTES};

fn server_core(label: &str) -> (EmulebbCore, std::path::PathBuf) {
    let root = unique_runtime_dir(label);
    let database = root.join("metadata.sqlite");
    let core = EmulebbCore::new(
        "test",
        FileIndex::open(&database).unwrap(),
        root.join("transfers"),
    )
    .unwrap();
    (core, database)
}

async fn add(core: &EmulebbCore, address: &str, name: &str) {
    let definition = emulebb_metadata::MetadataServerCreate {
        address: address.into(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    };
    core.create_server_resource(&definition).await.unwrap();
    core.import_server_resource(&emulebb_metadata::MetadataServerImport {
        address: definition.address,
        port: definition.port,
        name: Some(name.into()),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_catalog_reads_use_persisted_ids_and_retain_owned_conversion() {
    let (core, _) = server_core("server-admitted-catalog");
    add(&core, "192.0.2.1", "Sample Server").await;
    add(&core, "192.0.2.2", "Second Server").await;
    core.state.lock().await.servers.clear();
    let resident = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    let page = core
        .server_page(MetadataServerQuery {
            limit: 1,
            count_total: true,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(page.servers.len(), 1);
    assert_eq!(page.total, Some(2));
    assert!(page.has_more);
    let id = page.servers[0].id;
    assert_eq!(page.next_after_id, Some(id));
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        SERVER_READ_MAX_BYTES
    );
    let exact = core.server_by_id(id).await.unwrap().unwrap();
    assert_eq!(exact.id, id);
    assert_eq!(exact.server, page.servers[0].server);
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        2 * SERVER_READ_MAX_BYTES
    );
    drop(exact);
    let output = page
        .try_project(16 * 1024, |page| {
            Ok(page
                .servers
                .into_iter()
                .map(|row| row.server.name)
                .collect::<Vec<_>>())
        })
        .unwrap()
        .serialize_json()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(output.as_ref()).unwrap(),
        vec!["Sample Server"]
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        output.len()
    );
    drop(output);
    let next = core
        .server_page(MetadataServerQuery {
            after_id: Some(id),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(next.servers[0].server.name, "Second Server");
    assert!(!next.has_more);
    assert!(next.total.is_none());
    drop(next);
    assert!(core.server_by_id(i64::MAX).await.unwrap().is_none());
    assert!(core.state.lock().await.servers.is_empty());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        resident
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}

#[tokio::test]
async fn server_reads_preserve_validation_and_oversized_row_errors() {
    let (core, database) = server_core("server-admitted-row-errors");
    add(&core, "192.0.2.1", "Sample Server").await;
    let page = core.server_page(Default::default()).await.unwrap();
    let id = page.servers[0].id;
    drop(page);
    let invalid = core.server_by_id(0).await.err().unwrap();
    assert_eq!(
        invalid.downcast_ref::<MetadataServerReadError>(),
        Some(&MetadataServerReadError::InvalidQuery)
    );
    let invalid = core
        .server_page(MetadataServerQuery {
            limit: 201,
            ..Default::default()
        })
        .await
        .err()
        .unwrap();
    assert_eq!(
        invalid.downcast_ref::<MetadataServerReadError>(),
        Some(&MetadataServerReadError::InvalidQuery)
    );
    // Inject a stored-row fault outside the admitted mutation boundary.
    rusqlite::Connection::open(database)
        .unwrap()
        .execute(
            "UPDATE servers SET name=?1 WHERE id=?2",
            rusqlite::params!["x".repeat(SERVER_READ_MAX_BYTES), id],
        )
        .unwrap();
    let error = core.server_by_id(id).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::TooLarge)
    ));
    let error = core.server_page(Default::default()).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::TooLarge)
    ));
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}

#[tokio::test]
async fn server_sql_failures_remain_storage_errors_instead_of_empty_pages() {
    let (core, database) = server_core("server-admitted-storage-error");
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute("DROP INDEX servers_live_id_idx", [])
        .unwrap();
    let error = core.server_page(Default::default()).await.err().unwrap();
    assert!(matches!(
        error.downcast_ref::<PersistenceError>(),
        Some(PersistenceError::Storage(_))
    ));
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}
