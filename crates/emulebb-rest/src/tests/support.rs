use std::sync::atomic::{AtomicU64, Ordering};
pub(crate) use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

pub(crate) use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
pub(crate) use emulebb_core::{Ed2kNetworkConfig, EmulebbCore, LocalShareCreate, VpnGuardConfig};
use emulebb_ed2k::{
    NatConfig, config::Ed2kRuntimeConfig, ed2k_tcp::Ed2kSecureIdent, ipfilter::IpFilter,
};
pub(crate) use emulebb_index::{
    FileIndex, IndexedFile, IndexedFileOrigin, KadLocalStoreConfig, SnoopQueueConfig,
};
pub(crate) use serde_json::{Value, json};
pub(crate) use tokio::sync::watch;
pub(crate) use tower::ServiceExt;

pub(crate) use crate::{RestServerSettings, router, router_with_shutdown};

pub(crate) fn test_router() -> Router {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    )
}

pub(crate) fn test_search_router() -> Router {
    router(
        test_search_core(&[]),
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: None,
        },
    )
}

pub(crate) fn test_search_core(files: &[IndexedFile]) -> Arc<EmulebbCore> {
    let runtime_dir = unique_test_dir("search-core");
    let mut index = FileIndex::open(runtime_dir.join("metadata.sqlite")).unwrap();
    for file in files {
        index
            .upsert_file(file, IndexedFileOrigin::PassiveCache)
            .unwrap();
    }
    Arc::new(
        EmulebbCore::new_with_network(
            "test",
            index,
            &runtime_dir,
            Some(test_network_config(&runtime_dir)),
        )
        .unwrap(),
    )
}

fn test_network_config(runtime_dir: &std::path::Path) -> Ed2kNetworkConfig {
    let bind_ip = Ipv4Addr::new(198, 51, 100, 10);
    Ed2kNetworkConfig {
        bind_ip,
        kad_bind_addr: SocketAddr::new(IpAddr::V4(bind_ip), 4665),
        listen_port: 4662,
        user_hash: [0x44; 16],
        secure_ident: Arc::new(
            Ed2kSecureIdent::load_or_create(&runtime_dir.join("secure-ident.der")).unwrap(),
        ),
        kad_local_store: KadLocalStoreConfig::default(),
        kad_snoop_queue: SnoopQueueConfig::default(),
        kad_passive_replay_enabled: true,
        kad_nodes_dat: None,
        kad_nodes_dat_path: None,
        kad_bootstrap_endpoints: Vec::new(),
        kad_bootstrap_min_routing_contacts: 10,
        kad_publish_shared_files: true,
        kad_republish_interval_secs: 1_800,
        kad_publish_contact_fanout: 4,
        kad_routing_maintenance_enabled: true,
        kad_udp_firewall_check_enabled: true,
        kad_udp_firewall_check_interval_secs: 600,
        kad_tcp_firewall_check_enabled: true,
        kad_tcp_firewall_check_interval_secs: 600,
        kad_buddy_enabled: true,
        nat_config: NatConfig::default(),
        ed2k: Ed2kRuntimeConfig::default(),
        p2p_bind_ip: Some(bind_ip),
        p2p_bind_interface: None,
        vpn_guard: VpnGuardConfig::default(),
        vpn_interface_bound: false,
        vpn_interface_bound_runtime: None,
        ip_filter: IpFilter::default(),
        ip_filter_path: None,
        ip_filter_level: emulebb_ed2k::ipfilter::DEFAULT_FILTER_LEVEL,
    }
}

pub(crate) fn test_router_with_webui(web_root_dir: std::path::PathBuf) -> Router {
    let core =
        Arc::new(EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap());
    router(
        core,
        RestServerSettings {
            api_key: "secret".to_string(),
            web_root_dir: Some(web_root_dir),
        },
    )
}

pub(crate) async fn assert_invalid_json_response(
    app: Router,
    method: &str,
    uri: &str,
    body: impl Into<Body>,
    expected_message: &str,
) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-API-Key", "secret")
                .header("Content-Type", "application/json")
                .body(body.into())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(value["error"]["message"], expected_message);
}

pub(crate) async fn assert_invalid_query_response(app: Router, method: &str, uri: &str) {
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("X-API-Key", "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "INVALID_ARGUMENT");
    assert_eq!(
        value["error"]["message"],
        "unknown query parameter: unsupportedQuery"
    );
}

pub(crate) fn unique_test_dir(name: &str) -> std::path::PathBuf {
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let root = rust_test_tmp_root();
    std::fs::create_dir_all(&root).expect("create test root");
    allocate_test_dir(&root, name, stamp, &NEXT_DIRECTORY)
}

fn allocate_test_dir(
    root: &std::path::Path,
    name: &str,
    stamp: u128,
    next: &AtomicU64,
) -> std::path::PathBuf {
    loop {
        let sequence = next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("test directory counter exhausted");
        let path = root.join(format!(
            "emulebb-rest-{name}-{}-{stamp}-{sequence}",
            std::process::id()
        ));
        // WHY: Windows clocks can return the same timestamp on parallel test
        // threads. Claim a new directory atomically; never reuse or delete an
        // existing fixture while another test may still have its database open.
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create test directory {}: {error}", path.display()),
        }
    }
}

#[test]
fn same_clock_directory_allocations_are_isolated_and_preserve_existing_fixtures() {
    let root = unique_test_dir("directory-allocation");
    let existing = root.join(format!(
        "emulebb-rest-same-clock-{}-7-0",
        std::process::id()
    ));
    std::fs::create_dir(&existing).unwrap();
    let sentinel = existing.join("active-fixture.txt");
    std::fs::write(&sentinel, b"still owned by another test").unwrap();
    let next = AtomicU64::new(0);
    let paths = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| allocate_test_dir(&root, "same-clock", 7, &next)))
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<std::collections::BTreeSet<_>>()
    });
    assert_eq!(paths.len(), 8);
    assert!(!paths.contains(&existing));
    for path in paths {
        assert_eq!(std::fs::read_dir(path).unwrap().count(), 0);
    }
    assert_eq!(
        std::fs::read(sentinel).unwrap(),
        b"still owned by another test"
    );
}

fn rust_test_tmp_root() -> std::path::PathBuf {
    std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("tmp").join("emulebb-rust-tests"))
        .unwrap_or_else(|| std::env::temp_dir().join("emulebb-rust-tests"))
}
