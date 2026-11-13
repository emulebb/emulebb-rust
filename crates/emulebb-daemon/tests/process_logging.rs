//! Process-owned logging survives replacement of an application-owned Tokio runtime.

#[test]
fn process_logging_keeps_the_canonical_writer_across_runtime_restarts() {
    let root = tempfile::tempdir().unwrap();
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let guard =
        first.block_on(async { emulebb_daemon::logging::init_process(root.path()).unwrap() });
    drop(first);
    tracing::info!("first application runtime released");
    let second = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    second.block_on(async {
        tracing::info!("second application runtime active");
        guard.shutdown().await;
    });
    let mut retained = String::new();
    for entry in std::fs::read_dir(root.path().join("logs")).unwrap() {
        retained.push_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap());
    }
    assert!(retained.contains("first application runtime released"));
    assert!(retained.contains("second application runtime active"));
}
