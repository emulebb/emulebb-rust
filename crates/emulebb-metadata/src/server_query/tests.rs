use super::*;

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
    store.upsert_server(&server("seed.example")).unwrap();
    let retired = store
        .server_page(Default::default())
        .unwrap()
        .servers
        .remove(0)
        .id;
    store
        .connection()
        .unwrap()
        .execute("UPDATE servers SET deleted_at_ms=0 WHERE id=?1", [retired])
        .unwrap();
    store.upsert_server(&server("SEED.EXAMPLE")).unwrap();
    let live = store.server_page(Default::default()).unwrap();
    assert_eq!(live.servers.len(), 1);
    assert!(live.servers[0].id > retired);
    assert!(store.server_by_id(retired).unwrap().is_none());
    let historical: Option<i64> = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT deleted_at_ms FROM servers WHERE id=?1",
            [retired],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(historical, Some(0));
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
    store.upsert_server(&variant).unwrap();
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
        .execute("UPDATE servers SET deleted_at_ms=0 WHERE id=?1", [id])
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
            INSERT INTO servers(address,port,first_seen_at_ms,last_seen_at_ms,deleted_at_ms)
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
