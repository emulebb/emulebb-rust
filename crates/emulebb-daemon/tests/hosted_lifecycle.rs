//! Public embedded-host lifecycle: readiness, authentication, teardown and cancellation.

use std::{fs, net::SocketAddr, time::Duration};

use emulebb_core::{EmulebbCore, ServerCreate};
use emulebb_daemon::{DaemonProfile, RestBootstrapSettings, ShutdownRequest, run_hosted};
use emulebb_index::FileIndex;
use emulebb_metadata::MetadataStore;
use tokio::sync::oneshot;

const FIXTURE_API_KEY: &str = "synthetic-hosted-lifecycle-fixture-key";
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn stop_before_start_creates_no_profile_or_listener() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = DaemonProfile {
        profile_dir: temporary.path().join("not-started"),
        ..DaemonProfile::default()
    };
    let path = profile.profile_dir.clone();
    let shutdown = ShutdownRequest::default();
    shutdown.request();
    let (ready, observer) = oneshot::channel();
    run_hosted(profile, shutdown.subscribe(), ready)
        .await
        .unwrap();
    assert!(observer.await.is_err());
    assert!(!path.exists());
}

#[tokio::test]
async fn missing_readiness_observer_rejects_start_before_profile_creation() {
    let temporary = tempfile::tempdir().unwrap();
    let profile = DaemonProfile {
        profile_dir: temporary.path().join("not-started"),
        ..DaemonProfile::default()
    };
    let path = profile.profile_dir.clone();
    let shutdown = ShutdownRequest::default();
    let (ready, observer) = oneshot::channel();
    drop(observer);
    let error = run_hosted(profile, shutdown.subscribe(), ready)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("readiness receiver closed"));
    assert!(!path.exists());
}

#[tokio::test]
async fn host_stop_releases_the_bound_listener_and_metadata_store() {
    assert_running_shutdown(Stop::Host).await;
}

#[tokio::test]
async fn rest_shutdown_uses_the_same_embedded_teardown() {
    assert_running_shutdown(Stop::Rest).await;
}

#[tokio::test]
async fn losing_the_host_stops_the_running_daemon() {
    assert_running_shutdown(Stop::LostHost).await;
}

enum Stop {
    Host,
    Rest,
    LostHost,
}

async fn assert_running_shutdown(stop: Stop) {
    let temporary = tempfile::tempdir().unwrap();
    let mut profile = DaemonProfile {
        profile_dir: temporary.path().to_owned(),
        initial_shared_directory_reload: false,
        rest: RestBootstrapSettings {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            api_key: FIXTURE_API_KEY.to_owned(),
            web_root_dir: None,
        },
        ..DaemonProfile::default()
    };
    profile.ed2k.listen_port = None;
    profile.kad.listen_port = None;
    // Preserve existing discovery state so this REST-only fixture never fetches
    // public bootstrap data. It does not start or qualify a Kad/P2P session.
    fs::write(
        profile.profile_dir.join("nodes.dat"),
        b"owned REST-only fixture",
    )
    .unwrap();
    let core = EmulebbCore::new(
        "fixture",
        FileIndex::open(profile.metadata_path()).unwrap(),
        profile.transfer_root(),
    )
    .unwrap();
    core.add_server(ServerCreate {
        address: "127.0.0.1".to_owned(),
        port: 9,
        name: Some("Local fixture".to_owned()),
        priority: None,
        static_server: None,
        connect: Some(false),
    })
    .await
    .unwrap();
    drop(core);
    let metadata_path = profile.metadata_path();
    let shutdown = ShutdownRequest::default();
    let (ready, observer) = oneshot::channel();
    let signal = shutdown.subscribe();
    let (finished, completion) = oneshot::channel();
    let worker = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(run_hosted(profile, signal, ready));
        // The host owns all background workers, including blocking work, until
        // runtime drain. Returning from the daemon future alone is insufficient.
        drop(runtime);
        let _ = finished.send(result);
    });
    let address: SocketAddr = tokio::time::timeout(TEST_TIMEOUT, observer)
        .await
        .unwrap()
        .unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    let client = reqwest::Client::builder()
        .timeout(TEST_TIMEOUT)
        .build()
        .unwrap();
    let base = format!("http://{address}/api/v1");
    assert_eq!(
        client
            .get(format!("{base}/app"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(
        client
            .get(format!("{base}/app"))
            .header("X-API-Key", FIXTURE_API_KEY)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    match stop {
        Stop::Host => shutdown.request(),
        Stop::Rest => {
            assert!(
                client
                    .post(format!("{base}/app/shutdown"))
                    .header("X-API-Key", FIXTURE_API_KEY)
                    .header("Content-Type", "application/json")
                    .body(r#"{"confirmShutdown":true}"#)
                    .send()
                    .await
                    .unwrap()
                    .status()
                    .is_success()
            );
        }
        Stop::LostHost => drop(shutdown),
    }
    drop(client);
    tokio::time::timeout(TEST_TIMEOUT, completion)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    let rebound = tokio::net::TcpListener::bind(address).await.unwrap();
    drop(rebound);
    let metadata = MetadataStore::open(&metadata_path).unwrap();
    assert_eq!(metadata.load_servers().unwrap().len(), 1);
    drop(metadata);
    // Windows rejects renaming a database still held by a detached worker.
    fs::rename(metadata_path, temporary.path().join("closed.db")).unwrap();
}
