use std::io::{Seek, SeekFrom, Write};

use emulebb_kad_proto::Ed2kHash;
use md4::{Digest, Md4};

use super::super::{
    ED2K_PART_SIZE, Ed2kDeliveryOutcome, Ed2kTransferRuntime, Ed2kTransferState, new_transfer_job,
};
use crate::paths::unique_test_dir;

fn md4(bytes: &[u8]) -> [u8; 16] {
    Md4::digest(bytes).into()
}

#[tokio::test]
async fn clean_completion_persists_pending_before_restart_finalizer_accepts() {
    let root = unique_test_dir("ed2k-final-rehash-clean-restart");
    let payload = b"completion barrier payload";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "clean.bin".to_string(), payload.len() as u64);

    {
        let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
        runtime.ensure_job(&job).await.unwrap();
        runtime
            .store_md4_hashset(&job.file_hash, Vec::new())
            .await
            .unwrap();
        runtime
            .store_piece_data_unfinalized(&job.file_hash, 0, payload)
            .await
            .unwrap();
        let pending = runtime.manifest(&job.file_hash).await.unwrap();
        assert!(!pending.completed);
        assert!(pending.final_rehash_pending);
        assert_eq!(
            runtime
                .materialize_completed_payload(&job.file_hash, &root.join("incoming"))
                .await
                .unwrap(),
            Ed2kDeliveryOutcome::NotCompleted
        );
    }

    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    assert!(
        runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    let completed = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(completed.completed);
    assert!(!completed.final_rehash_pending);
}

#[tokio::test]
async fn mutation_before_last_part_is_found_and_only_bad_part_is_demoted() {
    let root = unique_test_dir("ed2k-final-rehash-earlier-mutation");
    let first = vec![0x31; ED2K_PART_SIZE as usize];
    let second = vec![0x72; 257];
    let first_hash = md4(&first);
    let second_hash = md4(&second);
    let mut composite = Md4::new();
    composite.update(first_hash);
    composite.update(second_hash);
    let file_hash = Ed2kHash::from_bytes(composite.finalize().into());
    let job = new_transfer_job(
        file_hash,
        "mutated.bin".to_string(),
        first.len() as u64 + second.len() as u64,
    );
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, vec![first_hash, second_hash])
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, &first)
        .await
        .unwrap();

    let mut payload = std::fs::OpenOptions::new()
        .write(true)
        .open(runtime.payload_path(&job.file_hash))
        .unwrap();
    payload.seek(SeekFrom::Start(0)).unwrap();
    payload.write_all(&[0xff]).unwrap();
    payload.sync_all().unwrap();

    runtime
        .store_piece_data_unfinalized(&job.file_hash, 1, &second)
        .await
        .unwrap();
    assert!(
        !runtime
            .finalize_pending_transfer(&job.file_hash)
            .await
            .unwrap()
    );
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(!manifest.completed);
    assert!(!manifest.final_rehash_pending);
    assert_eq!(manifest.pieces[0].state, Ed2kTransferState::Missing);
    assert!(manifest.pieces[0].ich_corrupted);
    assert_eq!(manifest.pieces[1].state, Ed2kTransferState::Verified);
}

#[tokio::test]
async fn automatic_store_does_not_return_a_deliverable_file_before_final_rehash() {
    let root = unique_test_dir("ed2k-final-rehash-auto");
    let payload = b"automatic final rehash";
    let file_hash = Ed2kHash::from_bytes(md4(payload));
    let job = new_transfer_job(file_hash, "automatic.bin".to_string(), payload.len() as u64);
    let runtime = Ed2kTransferRuntime::load_or_create(&root).unwrap();
    runtime.ensure_job(&job).await.unwrap();
    runtime
        .store_md4_hashset(&job.file_hash, Vec::new())
        .await
        .unwrap();
    runtime
        .store_piece_data(&job.file_hash, 0, payload)
        .await
        .unwrap();
    let manifest = runtime.manifest(&job.file_hash).await.unwrap();
    assert!(manifest.completed);
    assert!(!manifest.final_rehash_pending);
}
