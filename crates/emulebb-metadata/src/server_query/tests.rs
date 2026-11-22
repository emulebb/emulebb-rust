use super::*;
use crate::{
    MetadataServerCreate, MetadataServerImport, MetadataServerUpdate, ServerEndpointConflict,
};

#[test]
fn server_summary_counts_live_rows_and_reads_only_the_selected_endpoint() {
    let store = MetadataStore::in_memory().unwrap();
    let first = store
        .create_server_resource(creation("seed.example"))
        .unwrap();
    let second = store
        .create_server_resource(creation("other.example"))
        .unwrap();
    store
        .update_server_resource(
            first.id,
            &MetadataServerUpdate {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    // An unrelated oversized row must not turn a count/current read into a list read.
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE servers SET name=?1 WHERE id=?2",
            params!["x".repeat(SERVER_READ_MAX_BYTES), second.id],
        )
        .unwrap();
    let summary = store.server_summary(Some(("SEED.EXAMPLE", 4661))).unwrap();
    assert_eq!(summary.total, 2);
    let current = summary.current.unwrap();
    assert_eq!(current.id, first.id);
    assert!(!current.server.enabled);
    assert_eq!(store.server_summary(None).unwrap().total, 2);
    assert!(
        store
            .server_summary(Some(("missing.example", 4661)))
            .unwrap()
            .current
            .is_none()
    );
    assert!(store.server_summary(Some(("other.example", 4661))).is_err());
    store.delete_server_resource(first.id).unwrap();
    let summary = store.server_summary(Some(("seed.example", 4661))).unwrap();
    assert_eq!(summary.total, 1);
    assert!(summary.current.is_none());
}

#[test]
fn explicit_server_creation_conflict_preserves_disabled_resource_and_observations() {
    let store = MetadataStore::in_memory().unwrap();
    let mut original = server("seed.example");
    original.enabled = false;
    original.failed_count = 3;
    let id = store.upsert_server(&original).unwrap();
    let before = store.server_by_id(id).unwrap().unwrap().server;
    let mut duplicate = creation("SEED.EXAMPLE");
    duplicate.priority = "high".into();
    let error = store.create_server_resource(duplicate.clone()).unwrap_err();
    assert!(error.is::<ServerEndpointConflict>());
    assert_eq!(store.server_by_id(id).unwrap().unwrap().server, before);
    assert!(store.delete_server_resource(id).unwrap());
    let created = store.create_server_resource(duplicate).unwrap().id;
    assert!(created > id);
    assert_eq!(
        store.server_page(Default::default()).unwrap().servers.len(),
        1
    );
}

#[test]
fn concurrent_server_creators_have_one_winner_and_one_endpoint_conflict() {
    let store = MetadataStore::in_memory().unwrap();
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let create = |address| {
            barrier.wait();
            store.create_server_resource(creation(address))
        };
        let first = scope.spawn(move || create("seed.example"));
        let second = scope.spawn(move || create("SEED.EXAMPLE"));
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(
        outcomes
            .into_iter()
            .find_map(Result::err)
            .unwrap()
            .is::<ServerEndpointConflict>()
    );
    assert_eq!(
        store.server_page(Default::default()).unwrap().servers.len(),
        1
    );
}

#[test]
fn failed_discovery_initialization_rolls_back_explicit_server_creation() {
    let store = MetadataStore::in_memory().unwrap();
    store.connection().unwrap().execute_batch(
        "CREATE TRIGGER block_server_initialization BEFORE UPDATE ON discovery_initialization
         WHEN NEW.domain='servers' BEGIN SELECT RAISE(ABORT,'injected initialization failure'); END;"
    ).unwrap();
    assert!(
        store
            .create_server_resource(creation("seed.example"))
            .is_err()
    );
    assert!(
        store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    let status: String = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT status FROM discovery_initialization WHERE domain='servers'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "pending");
}

#[test]
fn operator_server_edits_preserve_endpoint_and_network_observations() {
    let store = MetadataStore::in_memory().unwrap();
    let mut entry = server("seed.example");
    entry.failed_count = 7;
    entry.users = 83;
    entry.ping_ms = Some(42);
    let id = store.upsert_server(&entry).unwrap();
    let mut expected = store.server_by_id(id).unwrap().unwrap().server;
    let edit = MetadataServerUpdate {
        priority: Some("high".into()),
        static_server: Some(true),
        enabled: Some(false),
    };
    assert!(store.update_server_resource(id, &edit).unwrap());
    expected.server_priority = "high".into();
    expected.static_server = true;
    expected.enabled = false;
    assert_eq!(store.server_by_id(id).unwrap().unwrap().server, expected);
    assert!(store.update_server_resource(id, &edit).unwrap());
    assert!(
        store
            .update_server_resource(
                id,
                &MetadataServerUpdate {
                    enabled: Some(true),
                    ..Default::default()
                }
            )
            .unwrap()
    );
    assert!(store.server_by_id(id).unwrap().unwrap().server.enabled);
    assert_eq!(
        store.server_page(Default::default()).unwrap().servers.len(),
        1
    );
}

#[test]
fn server_mutation_failure_leaves_saved_resource_unchanged() {
    let store = MetadataStore::in_memory().unwrap();
    let id = store.upsert_server(&server("seed.example")).unwrap();
    let before = store.server_by_id(id).unwrap().unwrap().server;
    assert!(
        store
            .update_server_resource(
                id,
                &MetadataServerUpdate {
                    priority: Some("invalid-priority".into()),
                    ..Default::default()
                }
            )
            .is_err()
    );
    assert_eq!(store.server_by_id(id).unwrap().unwrap().server, before);
    store.connection().unwrap().execute_batch(
        "CREATE TRIGGER block_server_delete BEFORE UPDATE OF deleted_at_s ON servers
         WHEN NEW.deleted_at_s IS NOT NULL BEGIN SELECT RAISE(ABORT,'injected delete failure'); END;"
    ).unwrap();
    assert!(store.delete_server_resource(id).is_err());
    assert_eq!(store.server_by_id(id).unwrap().unwrap().server, before);
}

#[test]
fn server_edits_and_repeated_deletion_do_not_create_resources() {
    let store = MetadataStore::in_memory().unwrap();
    let edit = MetadataServerUpdate {
        enabled: Some(true),
        ..Default::default()
    };
    assert!(!store.update_server_resource(1, &edit).unwrap());
    assert!(!store.delete_server_resource(1).unwrap());
    let id = store.upsert_server(&server("seed.example")).unwrap();
    assert!(store.delete_server_resource(id).unwrap());
    assert!(!store.delete_server_resource(id).unwrap());
    assert!(!store.update_server_resource(id, &edit).unwrap());
    assert!(
        store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    assert!(store.update_server_resource(0, &edit).is_err());
    assert!(store.delete_server_resource(0).is_err());
    assert!(
        store
            .update_server_resource(id, &MetadataServerUpdate::default())
            .is_err()
    );
}

#[test]
fn imported_names_preserve_live_identity_controls_and_health() {
    let store = MetadataStore::in_memory().unwrap();
    let mut original = server("seed.example");
    original.server_priority = "high".into();
    original.static_server = true;
    original.enabled = false;
    original.failed_count = 7;
    original.users = 83;
    original.ping_ms = Some(42);
    let id = store.upsert_server(&original).unwrap();
    let mut original = store.server_by_id(id).unwrap().unwrap().server;
    let imported = MetadataServerImport {
        address: "SEED.EXAMPLE".into(),
        port: 4661,
        name: Some("Observed Server".into()),
    };
    let row = store.import_server_resource(&imported).unwrap();
    assert_eq!(row.id, id);
    original.name = "Observed Server".into();
    assert_eq!(row.server, original);
    assert_eq!(
        store
            .import_server_resource(&MetadataServerImport {
                name: None,
                ..imported.clone()
            })
            .unwrap()
            .server,
        original
    );
    assert!(store.delete_server_resource(id).unwrap());
    let replacement = store.import_server_resource(&imported).unwrap();
    assert!(replacement.id > id);
    assert!(replacement.server.enabled);
    assert!(!replacement.server.static_server);
    assert_eq!(replacement.server.server_priority, "normal");
    assert_eq!(replacement.server.failed_count, 0);
}

#[test]
fn failed_import_rolls_back_name_and_discovery_initialization() {
    let store = MetadataStore::in_memory().unwrap();
    let oversized = MetadataServerImport {
        address: "seed.example".into(),
        port: 4661,
        name: Some("x".repeat(SERVER_READ_MAX_BYTES / 4)),
    };
    assert!(
        store
            .import_server_resource(&oversized)
            .unwrap_err()
            .is::<MetadataServerReadError>()
    );
    assert!(
        store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    let status: String = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT status FROM discovery_initialization WHERE domain='servers'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "pending");
    let before = store
        .create_server_resource(creation("seed.example"))
        .unwrap();
    store.connection().unwrap().execute_batch(
        "CREATE TRIGGER block_server_import BEFORE UPDATE OF name ON servers BEGIN SELECT RAISE(ABORT,'injected import failure'); END;"
    ).unwrap();
    assert!(
        store
            .import_server_resource(&MetadataServerImport {
                name: Some("Uncommitted Name".into()),
                ..oversized
            })
            .is_err()
    );
    assert_eq!(
        store.server_by_id(before.id).unwrap().unwrap().server,
        before.server
    );
}

fn creation(address: &str) -> MetadataServerCreate {
    MetadataServerCreate {
        address: address.into(),
        port: 4661,
        priority: "normal".into(),
        static_server: false,
        enabled: true,
    }
}

#[test]
fn explicit_creation_starts_unobserved_and_import_preserves_its_id() {
    let store = MetadataStore::in_memory().unwrap();
    let created = store
        .create_server_resource(creation("seed.example"))
        .unwrap();
    assert!(created.server.name.is_empty());
    assert!(created.server.description.is_empty());
    assert_eq!(created.server.failed_count, 0);
    assert_eq!(created.server.ping_ms, None);
    assert_eq!(created.server.users, 0);
    assert_eq!(created.server.files, 0);
    assert_eq!(
        store.server_by_id(created.id).unwrap().unwrap().server,
        created.server
    );
    let mut observed = server("seed.example");
    observed.name = "Observed Server".into();
    observed.users = 83;
    assert_eq!(store.upsert_server(&observed).unwrap(), created.id);
    let saved = store.server_by_id(created.id).unwrap().unwrap().server;
    assert_eq!(saved.name, "Observed Server");
    assert_eq!(saved.users, 83);
}

fn server(address: &str) -> MetadataServer {
    MetadataServer {
        address: address.into(),
        port: 4661,
        name: "Sample Server".into(),
        description: String::new(),
        dynamic_host: String::new(),
        auxiliary_ports: vec![4662, 4663, 4662],
        server_priority: "normal".into(),
        static_server: false,
        enabled: true,
        failed_count: 0,
        ping_ms: None,
        users: 0,
        files: 0,
        max_users: 0,
        low_id_users: 0,
        soft_files: 0,
        hard_files: 0,
        version: String::new(),
        obfuscation_tcp_port: None,
        obfuscation_udp_port: None,
        udp_flags: None,
        udp_key: None,
        udp_key_ip: None,
    }
}

#[test]
fn server_calendar_times_use_seconds_and_updates_preserve_first_seen() {
    let store = MetadataStore::in_memory().unwrap();
    let mut entry = server("seed.example");
    entry.ping_ms = Some(1234);
    let before = crate::store::unix_s();
    assert!(
        store
            .initialize_servers_if_pending(&[entry.clone()])
            .unwrap()
    );
    let read_times = || {
        store
            .connection()
            .unwrap()
            .query_row(
                "SELECT first_seen_at_s,last_seen_at_s,deleted_at_s,ping_ms FROM servers",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .unwrap()
    };
    let initial = read_times();
    assert!((before..=crate::store::unix_s()).contains(&initial.0));
    assert_eq!(initial, (initial.0, initial.0, None, 1234));
    store
        .connection()
        .unwrap()
        .execute("UPDATE servers SET first_seen_at_s=1,last_seen_at_s=2", [])
        .unwrap();
    store.upsert_server(&entry).unwrap();
    let updated = read_times();
    assert_eq!(updated.0, 1);
    assert!((before..=crate::store::unix_s()).contains(&updated.1));
    assert_eq!((updated.2, updated.3), (None, 1234));
}

#[test]
fn identity_survives_upsert_bootstrap_and_reopen_without_reusing_removed_ids() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("metadata.sqlite");
    let store = MetadataStore::open(&path).unwrap();
    assert!(
        store
            .initialize_servers_if_pending(&[server("192.0.2.1")])
            .unwrap()
    );
    let first = store
        .server_page(Default::default())
        .unwrap()
        .servers
        .remove(0);
    assert!(first.id > 0);
    assert_eq!(first.server.auxiliary_ports, vec![4662, 4663]);
    let mut changed = first.server.clone();
    changed.name = "Updated Server".into();
    changed.enabled = false;
    store.upsert_server(&changed).unwrap();
    assert!(
        !store
            .initialize_servers_if_pending(&[server("192.0.2.2")])
            .unwrap()
    );
    assert_eq!(
        store.server_by_id(first.id).unwrap().unwrap().server,
        changed
    );
    drop(store);
    let store = MetadataStore::open(&path).unwrap();
    let row = store
        .server_page(Default::default())
        .unwrap()
        .servers
        .remove(0);
    assert_eq!(row.id, first.id);
    assert!(!row.server.enabled);
    store
        .connection()
        .unwrap()
        .execute("DELETE FROM servers WHERE id=?1", [row.id])
        .unwrap();
    store.upsert_server(&server("192.0.2.2")).unwrap();
    let next = store
        .server_page(Default::default())
        .unwrap()
        .servers
        .remove(0);
    assert!(next.id > row.id);
    assert!(store.server_by_id(row.id).unwrap().is_none());
}

#[test]
fn reimporting_a_retired_endpoint_allocates_a_new_identity() {
    let store = MetadataStore::in_memory().unwrap();
    let retired = store.upsert_server(&server("seed.example")).unwrap();
    let before = crate::store::unix_s();
    assert!(store.delete_server_resource(retired).unwrap());
    let imported = store.upsert_server(&server("SEED.EXAMPLE")).unwrap();
    let live = store.server_page(Default::default()).unwrap();
    assert_eq!(live.servers.len(), 1);
    assert!(live.servers[0].id > retired);
    assert_eq!(live.servers[0].id, imported);
    assert!(store.server_by_id(retired).unwrap().is_none());
    let historical: Option<i64> = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT deleted_at_s FROM servers WHERE id=?1",
            [retired],
            |row| row.get(0),
        )
        .unwrap();
    assert!((before..=crate::store::unix_s()).contains(&historical.unwrap()));
}

#[test]
fn hostname_case_variants_update_one_identity_while_ports_remain_distinct() {
    let store = MetadataStore::in_memory().unwrap();
    store.upsert_server(&server("seed.example")).unwrap();
    let first = store
        .server_page(Default::default())
        .unwrap()
        .servers
        .remove(0);
    let mut variant = server("SEED.EXAMPLE");
    variant.name = "Updated Server".into();
    assert_eq!(store.upsert_server(&variant).unwrap(), first.id);
    let page = store.server_page(Default::default()).unwrap();
    assert_eq!(page.servers.len(), 1);
    assert_eq!(page.servers[0].id, first.id);
    assert_eq!(page.servers[0].server.address, "seed.example");
    assert_eq!(page.servers[0].server.name, "Updated Server");
    variant.port = 4662;
    store.upsert_server(&variant).unwrap();
    let page = store.server_page(Default::default()).unwrap();
    assert_eq!(page.servers.len(), 2);
    assert!(page.servers[1].id > first.id);
}

#[test]
fn disabled_rows_remain_visible_and_deleted_boundaries_continue() {
    let store = MetadataStore::in_memory().unwrap();
    assert!(store.server_by_id(1).unwrap().is_none());
    for n in 1..=3 {
        let mut row = server(&format!("192.0.2.{n}"));
        row.enabled = n != 2;
        store.upsert_server(&row).unwrap();
    }
    let first = store
        .server_page(MetadataServerQuery {
            limit: 1,
            count_total: true,
            ..Default::default()
        })
        .unwrap();
    let id = first.next_after_id.unwrap();
    assert_eq!(first.total, Some(3));
    assert!(first.has_more);
    store
        .connection()
        .unwrap()
        .execute("UPDATE servers SET deleted_at_s=0 WHERE id=?1", [id])
        .unwrap();
    assert!(store.server_by_id(id).unwrap().is_none());
    let next = store
        .server_page(MetadataServerQuery {
            after_id: Some(id),
            limit: 2,
            count_total: true,
        })
        .unwrap();
    assert_eq!(next.servers.len(), 2);
    assert!(!next.servers[0].server.enabled);
    assert_eq!(next.total, Some(2));
    assert!(!next.has_more);
    assert!(next.next_after_id.is_none());
}

#[test]
fn byte_short_pages_keep_every_server_reachable_without_truncating_text() {
    let store = MetadataStore::in_memory().unwrap();
    for n in 1..=10 {
        let mut row = server(&format!("192.0.2.{n}"));
        row.name = "x".repeat(65_536);
        store.upsert_server(&row).unwrap();
    }
    let mut after = None;
    let mut ids = Vec::new();
    let mut pages = 0;
    loop {
        let page = store
            .server_page(MetadataServerQuery {
                after_id: after,
                count_total: pages == 0,
                ..Default::default()
            })
            .unwrap();
        if pages == 0 {
            assert_eq!(page.total, Some(10));
        } else {
            assert!(page.total.is_none());
        }
        assert!(!page.servers.is_empty());
        assert!(page.servers.len() < 10);
        for row in &page.servers {
            assert_eq!(row.server.name.len(), 65_536);
            assert_eq!(
                store.server_by_id(row.id).unwrap().unwrap().server,
                row.server
            );
            ids.push(row.id);
        }
        pages += 1;
        if !page.has_more {
            assert!(page.next_after_id.is_none());
            break;
        }
        assert_ne!(page.next_after_id, after);
        after = page.next_after_id;
    }
    assert!(pages > 1);
    assert_eq!(ids.len(), 10);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn oversized_row_is_reported_at_its_boundary() {
    let store = MetadataStore::in_memory().unwrap();
    store.upsert_server(&server("192.0.2.1")).unwrap();
    let mut large = server("192.0.2.2");
    large.description = "x".repeat(SERVER_READ_MAX_BYTES);
    store.upsert_server(&large).unwrap();
    let page = store.server_page(Default::default()).unwrap();
    assert_eq!(page.servers.len(), 1);
    assert!(page.has_more);
    let error = store
        .server_page(MetadataServerQuery {
            after_id: page.next_after_id,
            ..Default::default()
        })
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<MetadataServerReadError>(),
        Some(&MetadataServerReadError::RowTooLarge)
    );
    let error = store.server_by_id(page.servers[0].id + 1).unwrap_err();
    assert_eq!(
        error.downcast_ref::<MetadataServerReadError>(),
        Some(&MetadataServerReadError::RowTooLarge)
    );
}

#[test]
fn invalid_queries_are_rejected_and_empty_pages_keep_optional_totals() {
    let store = MetadataStore::in_memory().unwrap();
    for query in [
        MetadataServerQuery {
            limit: 0,
            ..Default::default()
        },
        MetadataServerQuery {
            limit: 201,
            ..Default::default()
        },
        MetadataServerQuery {
            after_id: Some(0),
            ..Default::default()
        },
        MetadataServerQuery {
            after_id: Some(-1),
            ..Default::default()
        },
    ] {
        assert_eq!(
            store
                .server_page(query)
                .unwrap_err()
                .downcast_ref::<MetadataServerReadError>(),
            Some(&MetadataServerReadError::InvalidQuery)
        );
    }
    for id in [0, -1] {
        assert_eq!(
            store
                .server_by_id(id)
                .unwrap_err()
                .downcast_ref::<MetadataServerReadError>(),
            Some(&MetadataServerReadError::InvalidQuery)
        );
    }
    let page = store
        .server_page(MetadataServerQuery {
            after_id: Some(i64::MAX),
            count_total: true,
            ..Default::default()
        })
        .unwrap();
    assert!(page.servers.is_empty());
    assert!(!page.has_more);
    assert!(page.next_after_id.is_none());
    assert_eq!(page.total, Some(0));
}

#[test]
fn late_page_uses_indexed_seek_with_a_large_deleted_cohort() {
    let store = MetadataStore::in_memory().unwrap();
    {
        let conn = store.connection().unwrap();
        conn.execute_batch(
            "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<100000)
            INSERT INTO servers(address,port,first_seen_at_s,last_seen_at_s,deleted_at_s)
            SELECT printf('server-%06d.example',x),4661,0,0,CASE WHEN x%2=0 THEN 0 END FROM n;",
        )
        .unwrap();
    }
    let page = store
        .server_page(MetadataServerQuery {
            after_id: Some(99_500),
            limit: 20,
            count_total: false,
        })
        .unwrap();
    assert_eq!(page.servers.len(), 20);
    assert_eq!(page.servers[0].id, 99_501);
    assert_eq!(page.next_after_id, Some(99_539));
    assert!(page.has_more);
    assert!(page.total.is_none());
    let conn = store.connection().unwrap();
    let sql = page_sql();
    let plan: Vec<String> = conn
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map(params![99_500, 21], |r| r.get(3))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(
        plan.iter().any(|line| line.contains("servers_live_id_idx")),
        "{plan:?}"
    );
    assert!(
        !plan.iter().any(|line| line.contains("TEMP B-TREE")),
        "{plan:?}"
    );
    let mut statement = conn.prepare(&sql).unwrap();
    let ids: Vec<i64> = statement
        .query_map(params![99_500, 21], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(ids.len(), 21);
    assert_eq!(statement.get_status(rusqlite::StatementStatus::Sort), 0);
    assert!(
        statement.get_status(rusqlite::StatementStatus::VmStep) < 10_000,
        "{plan:?}"
    );
}

#[test]
fn document_import_write_failure_rolls_back_the_accepted_set() {
    let store = MetadataStore::in_memory().unwrap();
    store.connection().unwrap().execute_batch(
        "CREATE TRIGGER fail_second_import BEFORE INSERT ON servers WHEN NEW.address='second.example' BEGIN SELECT RAISE(ABORT,'injected second-row failure'); END;"
    ).unwrap();
    let entries = ["first.example", "second.example"].map(|address| MetadataServerImport {
        address: address.into(),
        port: 4661,
        name: None,
    });
    assert!(store.import_server_resources(entries).is_err());
    assert!(
        store
            .server_page(Default::default())
            .unwrap()
            .servers
            .is_empty()
    );
    let status: String = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT status FROM discovery_initialization WHERE domain='servers'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(status, "pending");
}
