use super::*;
use crate::{DownloadCreate, DownloadCreateSource, EmulebbCore};

#[tokio::test]
async fn passive_notes_remain_remote_evidence_independent_of_local_metadata() {
    for local in [None, Some(("Operator note", 2))] {
        let core = EmulebbCore::new_in_memory("test", FileIndex::in_memory().unwrap()).unwrap();
        let hash = Ed2kHash::from_bytes([0x42; 16]);
        let (_, job) = core
            .create_download(DownloadCreate {
                source: DownloadCreateSource::Content {
                    hash: hash.to_string(),
                    name: "Sample.bin".into(),
                    size_bytes: Some(4096),
                },
                category: None,
                intent: emulebb_metadata::DownloadIntent::Stopped,
                redownload: false,
            })
            .await
            .unwrap();
        let id = job.id;
        drop(job);
        if let Some(note) = local {
            assert!(
                core.ed2k_transfers
                    .update_library_file_metadata(&hash.to_string(), None, Some(note))
                    .await
                    .unwrap()
            );
        }
        let owner = core
            .persistence_owner
            .owner(&core.metadata_store, &core.state)
            .unwrap();
        let note = KadNoteResult {
            file_hash: hash,
            source_id: Ed2kHash::from_bytes([0x53; 16]),
            comment: Some("Remote note".into()),
            rating: Some(4),
            source_tags: Vec::new(),
        };
        let mut other = note.clone();
        other.source_id = Ed2kHash::from_bytes([0x54; 16]);
        let mut unrelated = note.clone();
        unrelated.file_hash = Ed2kHash::from_bytes([0x55; 16]);
        observe_passive_note_results(&owner, &[note.clone(), other, unrelated.clone(), note])
            .await
            .unwrap();
        let stored = core
            .metadata_store
            .download_job_manifest(id)
            .unwrap()
            .unwrap();
        let expected = local.unwrap_or(("", 0));
        assert_eq!((stored.comment.as_str(), stored.rating), expected);
        assert!(
            core.library_file(&unrelated.file_hash.to_string())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(core.metadata_store.table_count("known_files").unwrap(), 1);
        assert_eq!(
            core.metadata_store.table_count("content_claims").unwrap(),
            2
        );
        let evidence = core
            .metadata_store
            .content_observations_page(1, 0, 100)
            .unwrap();
        assert_eq!(evidence.items.len(), 2);
        assert!(!evidence.has_more);
        for item in &evidence.items {
            assert_eq!(item.event.claim.hash, hash.0);
            assert_eq!(item.event.claim.size_bytes, None);
            assert_eq!(item.event.reporter_endpoint, None);
            assert_eq!(item.event.metadata.comment.as_deref(), Some("Remote note"));
            assert_eq!(item.event.metadata.rating, Some(4));
        }
        assert_eq!(
            evidence.items[0].event.metadata.publisher_id,
            Some([0x53; 16])
        );
        assert_eq!(evidence.items[0].receipt.observation_count, 2);
        assert_eq!(
            evidence.items[1].event.metadata.publisher_id,
            Some([0x54; 16])
        );
        assert_eq!(evidence.items[1].receipt.observation_count, 1);
        assert_eq!(
            core.metadata_store.table_count("search_sessions").unwrap(),
            0
        );
        assert_eq!(
            core.metadata_store.table_count("search_results").unwrap(),
            0
        );
        core.drain_persistence().await.unwrap();
    }
}
