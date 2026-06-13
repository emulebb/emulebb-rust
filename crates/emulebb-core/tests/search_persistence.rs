use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use emulebb_core::{EmulebbCore, LocalShareCreate, SearchCreate, SearchResultDownloadCreate};
use emulebb_index::{FileIndex, IndexedFile};

#[tokio::test]
async fn search_state_survives_core_restart_and_downloads_result() {
    let runtime_dir = unique_test_dir("search-state");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    let (search_id, file_hash) = {
        let core = open_core(&metadata_path, &transfer_root);
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Sample Search Payload.bin".to_string(),
            size_bytes: 1234,
            content_type: "archive".to_string(),
            availability_score: 7,
        })
        .await
        .unwrap();
        let search = core
            .create_search(SearchCreate {
                query: "sample payload".to_string(),
                method: "automatic".to_string(),
                r#type: "archive".to_string(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(search.results.len(), 1);
        (search.id, search.results[0].hash.clone())
    };

    let reloaded = open_core(&metadata_path, &transfer_root);
    let searches = reloaded.searches().await;
    assert_eq!(searches.len(), 1);
    assert_eq!(searches[0].id, search_id);
    assert_eq!(searches[0].results[0].name, "Sample Search Payload.bin");
    assert_eq!(searches[0].results[0].r#type, "archive");

    let search = reloaded.search(&search_id).await.unwrap();
    assert_eq!(search.results[0].hash, file_hash);

    let transfer = reloaded
        .download_search_result(
            &search_id,
            &file_hash,
            SearchResultDownloadCreate::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transfer.hash, file_hash);
}

#[tokio::test]
async fn search_delete_and_clear_survive_core_restart() {
    let runtime_dir = unique_test_dir("search-delete-clear");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");

    let deleted_search_id = {
        let core = open_core(&metadata_path, &transfer_root);
        core.index_file(IndexedFile {
            ed2k_hash: "00112233445566778899aabbccddeeff".to_string(),
            name: "Sample Alpha.bin".to_string(),
            size_bytes: 10,
            content_type: "archive".to_string(),
            availability_score: 1,
        })
        .await
        .unwrap();
        core.index_file(IndexedFile {
            ed2k_hash: "11223344556677889900aabbccddeeff".to_string(),
            name: "Sample Beta.bin".to_string(),
            size_bytes: 20,
            content_type: "archive".to_string(),
            availability_score: 1,
        })
        .await
        .unwrap();
        let first = core
            .create_search(SearchCreate {
                query: "alpha".to_string(),
                method: "automatic".to_string(),
                r#type: String::new(),
                ..Default::default()
            })
            .await
            .unwrap();
        core.create_search(SearchCreate {
            query: "beta".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(core.delete_search(&first.id).await.unwrap());
        first.id
    };

    let reloaded = open_core(&metadata_path, &transfer_root);
    assert!(reloaded.search(&deleted_search_id).await.is_none());
    assert_eq!(reloaded.searches().await.len(), 1);

    reloaded.clear_searches().await.unwrap();
    let reloaded_again = open_core(&metadata_path, &transfer_root);
    assert!(reloaded_again.searches().await.is_empty());
}

#[tokio::test]
async fn shared_local_file_is_searchable_after_core_restart() {
    let runtime_dir = unique_test_dir("shared-file-search-index");
    let transfer_root = runtime_dir.join("transfers");
    let metadata_path = runtime_dir.join("metadata.sqlite");
    let payload_path = runtime_dir.join("Local.Searchable.Payload.bin");
    fs::write(&payload_path, b"shared searchable payload").unwrap();

    let share_hash = {
        let core = open_core(&metadata_path, &transfer_root);
        let share = core
            .share_local_file(LocalShareCreate {
                path: payload_path.display().to_string(),
                name: Some("Local.Searchable.Payload.bin".to_string()),
            })
            .await
            .unwrap();
        let search = core
            .create_search(SearchCreate {
                query: "searchable payload".to_string(),
                method: "automatic".to_string(),
                r#type: String::new(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(search.results.len(), 1);
        assert_eq!(search.results[0].hash, share.hash);
        share.hash
    };

    let reloaded = open_core(&metadata_path, &transfer_root);
    let search = reloaded
        .create_search(SearchCreate {
            query: "searchable payload".to_string(),
            method: "automatic".to_string(),
            r#type: String::new(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(search.results.len(), 1);
    assert_eq!(search.results[0].hash, share_hash);
}

fn open_core(metadata_path: &Path, transfer_root: &Path) -> EmulebbCore {
    EmulebbCore::new(
        "test",
        FileIndex::open(metadata_path).unwrap(),
        transfer_root,
    )
    .unwrap()
}

fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let root = std::env::var_os("EMULEBB_WORKSPACE_OUTPUT_ROOT")
        .map(PathBuf::from)
        .map(|path| path.join("tmp"))
        .unwrap_or_else(std::env::temp_dir);
    let path = root.join(format!(
        "emulebb-core-{name}-{}-{stamp}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("create test dir");
    path
}
