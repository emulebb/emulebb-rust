use super::*;
use crate::{LIBRARY_FILE_PAGE_BYTES, LibraryFileQuery, LibraryFileView};

fn core_with_copyless_library() -> (EmulebbCore, String) {
    let index = FileIndex::in_memory().unwrap();
    let hash = "61".repeat(16);
    index
        .metadata_store()
        .admit_download_job(&emulebb_metadata::DownloadJobRequest {
            file_hash: hash.clone(),
            display_name: "Sample.bin".into(),
            expected_size_bytes: Some(32),
            category_id: None,
            intent: emulebb_metadata::DownloadIntent::Stopped,
            piece_size: 1024,
        })
        .unwrap();
    index
        .metadata_store()
        .apply_credit_deltas(
            &[],
            &[emulebb_metadata::MetadataFileUploadDelta {
                file_hash: hash.clone(),
                uploaded_bytes: 17,
                upload_requests: 2,
                accepted_sessions: 1,
                last_requested_at_s: Some(0),
                last_uploaded_at_s: Some(1),
            }],
        )
        .unwrap();
    let core =
        EmulebbCore::new("test", index, unique_runtime_dir("library-file-contract")).unwrap();
    (core, hash)
}

#[tokio::test]
async fn copyless_summary_preserves_nullable_facts_and_owns_its_json_backing() {
    let (core, hash) = core_with_copyless_library();
    let resident = core
        .ed2k_transfers
        .download_resource_snapshot()
        .resident_bytes;
    let file = core.library_file(&hash).await.unwrap().unwrap();
    assert_eq!(file.hash, hash);
    assert_eq!(file.display_name, "Sample.bin");
    assert_eq!(
        file.size_bytes, None,
        "a provisional job size is not accepted content size"
    );
    assert!(!file.present);
    assert!(file.sharing_enabled);
    assert_eq!(file.session_uploaded_bytes, 0);
    assert_eq!(file.lifetime_uploaded_bytes, 17);
    assert_eq!(file.lifetime_upload_requests, 2);
    assert_eq!(file.lifetime_accepted_uploads, 1);
    assert_eq!(file.last_upload_requested_at, Some(0));
    assert_eq!(file.last_uploaded_at, Some(1));
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
        LIBRARY_FILE_PAGE_BYTES
    );
    let encoded = file
        .try_project(LIBRARY_FILE_PAGE_BYTES + 4096, |file| {
            Ok(serde_json::json!({"data":file}))
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
    let document: serde_json::Value = serde_json::from_slice(encoded.as_ref()).unwrap();
    assert_eq!(
        document["data"],
        serde_json::json!({
            "hash":hash,"displayName":"Sample.bin","sizeBytes":null,"present":false,"sharingEnabled":true,
            "sessionUploadedBytes":0,"sessionUploadRequests":0,"sessionAcceptedUploads":0,
            "lifetimeUploadedBytes":17,"lifetimeUploadRequests":2,"lifetimeAcceptedUploads":1,
            "lastUploadRequestedAt":0,"lastUploadedAt":1,
        })
    );
    drop(encoded);
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
    assert!(core.library_file(&"ff".repeat(16)).await.unwrap().is_none());
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}

#[tokio::test]
async fn collection_and_exact_summary_share_facts_and_named_filters_are_read_only() {
    let (core, hash) = core_with_copyless_library();
    let all = LibraryFileQuery {
        view: LibraryFileView::AllKnown,
        count_total: true,
        ..Default::default()
    };
    let page = core.library_file_page(all.clone()).await.unwrap();
    let file = core.library_file(&hash).await.unwrap().unwrap();
    assert_eq!(page.total, Some(1));
    assert!(page.next_after.is_none());
    assert_eq!(&page.files[0], &*file);
    drop(file);
    drop(page);
    assert!(
        core.library_file_page(LibraryFileQuery::default())
            .await
            .unwrap()
            .files
            .is_empty()
    );
    let filtered = core
        .library_file_page(LibraryFileQuery {
            tag: Some("Missing-1".into()),
            ..all.clone()
        })
        .await
        .unwrap();
    assert_eq!(filtered.total, Some(0));
    assert!(filtered.files.is_empty());
    drop(filtered);
    let error = core
        .library_file_page(LibraryFileQuery {
            after: Some([0xff; 16]),
            ..all
        })
        .await
        .err()
        .unwrap();
    assert!(
        error
            .downcast_ref::<crate::MetadataLibraryCursorExpired>()
            .is_some()
    );
    assert_eq!(
        core.ed2k_transfers
            .download_resource_snapshot()
            .transient_bytes,
        0
    );
}
