//! Checked conversions for unsigned Rust values stored as SQLite integers.

use rusqlite::{Error, Row};

pub(crate) fn unsigned<T: TryFrom<i64>>(row: &Row<'_>, column: usize) -> rusqlite::Result<T> {
    let value: i64 = row.get(column)?;
    T::try_from(value).map_err(|_| Error::IntegralValueOutOfRange(column, value))
}

pub(crate) fn optional_unsigned<T: TryFrom<i64>>(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<T>> {
    row.get::<_, Option<i64>>(column)?
        .map(|value| T::try_from(value).map_err(|_| Error::IntegralValueOutOfRange(column, value)))
        .transpose()
}

#[cfg(test)]
mod tests {
    #[test]
    fn file_counter_overflow_preserves_the_exact_committed_values() {
        let mut store = crate::MetadataStore::in_memory().unwrap();
        let hash = "11".repeat(16);
        store
            .upsert_indexed_file(
                &crate::MetadataIndexedFile {
                    ed2k_hash: hash.clone(),
                    name: "sample.bin".into(),
                    size_bytes: 1,
                    content_type: String::new(),
                    availability_score: 0,
                },
                crate::MetadataIndexedFileOrigin::LocalShare,
            )
            .unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE known_files SET all_time_uploaded_bytes = ?1,
             all_time_upload_requests = ?1, all_time_upload_accepts = ?1",
                [i64::MAX - 1],
            )
            .unwrap();
        assert!(store.add_file_all_time_uploaded(&hash, u64::MAX).is_err());
        assert!(store.add_file_all_time_uploaded(&hash, 2).is_err());
        for (bytes, requests, accepted) in [(u64::MAX, 0, 0), (2, 0, 0), (0, 2, 0), (0, 0, 2)] {
            assert!(
                store
                    .apply_credit_deltas(
                        &[("22".repeat(16), 1, 1)],
                        &[crate::MetadataFileUploadDelta {
                            file_hash: hash.clone(),
                            uploaded_bytes: bytes,
                            upload_requests: requests,
                            accepted_sessions: accepted,
                            ..Default::default()
                        }],
                    )
                    .is_err()
            );
        }
        let values: (i64, i64, i64) = store.connection().unwrap().query_row(
            "SELECT all_time_uploaded_bytes, all_time_upload_requests, all_time_upload_accepts FROM known_files",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).unwrap();
        assert_eq!(values, (i64::MAX - 1, i64::MAX - 1, i64::MAX - 1));
        assert!(
            store
                .peer_credit_by_hash(&"22".repeat(16))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .file_upload_statistics(&hash)
                .unwrap()
                .unwrap()
                .session_uploaded_bytes,
            0
        );
        store
            .apply_credit_deltas(
                &[],
                &[crate::MetadataFileUploadDelta {
                    file_hash: hash.clone(),
                    uploaded_bytes: 1,
                    upload_requests: 1,
                    accepted_sessions: 1,
                    ..Default::default()
                }],
            )
            .unwrap();
        let maximum = store.file_upload_statistics(&hash).unwrap().unwrap();
        assert_eq!(maximum.lifetime.uploaded_bytes, i64::MAX as u64);
        assert_eq!(maximum.lifetime.upload_requests, i64::MAX as u64);
        assert_eq!(maximum.lifetime.accepted_sessions, i64::MAX as u64);
        assert_eq!(maximum.session_uploaded_bytes, 1);
        assert_eq!(maximum.session_upload_requests, 1);
        assert_eq!(maximum.session_accepted_uploads, 1);
    }

    #[test]
    fn unsigned_reads_reject_negative_and_narrow_overflow() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        assert!(
            conn.query_row("SELECT -1", [], |r| super::unsigned::<u64>(r, 0))
                .is_err()
        );
        assert!(
            conn.query_row("SELECT 4294967296", [], |r| super::unsigned::<u32>(r, 0))
                .is_err()
        );
        assert_eq!(
            conn.query_row(
                "SELECT 9223372036854775807",
                [],
                |r| super::unsigned::<u64>(r, 0)
            )
            .unwrap(),
            i64::MAX as u64
        );
    }
}
