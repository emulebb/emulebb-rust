use super::*;

#[tokio::test]
async fn copyless_location_page_retains_its_charge_through_json_without_execution_hydration() {
    let root = unique_runtime_dir("library-locations-owned-json");
    let index = FileIndex::in_memory().unwrap();
    let hash = "55".repeat(16);
    index
        .metadata_store()
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: hash.clone(),
            display_name: "Sample.bin".into(),
            expected_size_bytes: None,
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Stopped,
            piece_size: 1024,
        })
        .unwrap();
    let core = EmulebbCore::new("test", index, root).unwrap();
    let resident_before = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    let page = core
        .library_locations(&hash, 0, 100)
        .await
        .unwrap()
        .unwrap();
    assert!(page.locations.is_empty());
    assert!(page.next_after.is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        LIBRARY_LOCATION_PAGE_BYTES
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        resident_before
    );
    let encoded = page
        .try_project(LIBRARY_LOCATION_PAGE_BYTES + 4096, |page| {
            Ok(serde_json::json!({"data":page.locations}))
        })
        .unwrap()
        .serialize_json()
        .unwrap();
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        encoded.len()
    );
    drop(encoded);
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
    assert!(
        core.library_locations(&"ff".repeat(16), 0, 100)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}
