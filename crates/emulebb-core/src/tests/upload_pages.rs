use super::*;

#[tokio::test]
async fn empty_upload_page_keeps_its_charge_through_owned_json_without_hydration() {
    let root = unique_runtime_dir("upload-page-owned-json");
    let core = EmulebbCore::new("test", FileIndex::in_memory().unwrap(), root).unwrap();
    let resident_before = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    let page = core.upload_queue_page(None, 100, true).await.unwrap();
    assert!(page.uploads.is_empty());
    assert_eq!(page.total, Some(0));
    assert!(!page.has_more);
    assert!(page.next_after.is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        crate::UPLOAD_QUEUE_PAGE_BYTES
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .resident_bytes,
        resident_before
    );
    let encoded = page.try_project(crate::UPLOAD_QUEUE_PAGE_BYTES + 4096, |page| {
        Ok(serde_json::json!({"data":page.uploads,"meta":{"hasMore":page.has_more,"total":page.total}}))
    }).unwrap().serialize_json().unwrap();
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        encoded.len()
    );
    let value: serde_json::Value = serde_json::from_slice(encoded.as_ref()).unwrap();
    assert_eq!(value["meta"]["total"], 0);
    drop(encoded);
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}
