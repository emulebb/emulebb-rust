use super::*;

pub(crate) fn raw_file() -> Ed2kSearchFile {
    Ed2kSearchFile {
        file_hash: emulebb_kad_proto::Ed2kHash::from_bytes([0x42; 16]),
        client_id: 0,
        client_port: 0,
        file_name: Some("Sample.bin".into()),
        file_size: None,
        file_type: None,
        media_artist: None,
        media_album: None,
        media_title: None,
        media_length_seconds: None,
        media_bitrate_kbps: None,
        media_codec: None,
        source_count: None,
        complete_source_count: None,
        rating: None,
        aich_hash: Some(data_encoding::BASE32.encode(&[0x12; 20])),
        directory: None,
    }
}

#[test]
fn raw_evidence_retains_absence_and_decodes_the_wire_aich_representation() {
    let raw = raw_file();
    let request = SearchCreate::default();
    let reporter = "192.0.2.4:4661".parse().unwrap();
    let projected = crate::search_query::search_result_from_ed2k(
        "1",
        &request,
        "server",
        Some(reporter),
        raw.clone(),
    );
    let SearchLiveUpdate::Result { observations, .. } = ed2k(
        projected,
        MetadataObservationOrigin::Server,
        Some(reporter),
        &raw,
    ) else {
        panic!("expected result");
    };
    let event = &observations[0];
    assert_eq!(event.claim.size_bytes, None);
    assert_eq!(event.metadata.source_count, None);
    assert_eq!(event.metadata.complete, None);
    assert_eq!(event.metadata.source_client_id, None);
    assert_eq!(event.metadata.source_client_port, None);
    assert_eq!(event.metadata.aich_root, Some([0x12; 20]));
    assert_eq!(
        event.reporter_endpoint.unwrap().to_string(),
        reporter.to_string()
    );
}

#[tokio::test]
async fn settled_request_drains_all_750_occurrences_until_the_decoder_closes() {
    let (raw_tx, raw_rx) = tokio::sync::mpsc::channel(2);
    let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(2);
    let request = SearchCreate::default();
    let producer = tokio::spawn(async move {
        for index in 0u32..750 {
            let mut raw = raw_file();
            raw.file_hash.0[..4].copy_from_slice(&index.to_be_bytes());
            raw_tx
                .send(emulebb_ed2k::ed2k_server::Ed2kServerSearchObservation {
                    server_endpoint: "192.0.2.4:4661".parse().unwrap(),
                    file: raw,
                })
                .await
                .unwrap();
        }
    });
    let forward = forward_ed2k(
        "1",
        &request,
        MetadataObservationOrigin::Server,
        Some(&live_tx),
        raw_rx,
        std::future::ready(()),
    );
    let consume = async {
        for index in 0u32..750 {
            let update = live_rx.recv().await.unwrap();
            let SearchLiveUpdate::Result { observations, .. } = update else {
                panic!("expected result");
            };
            assert_eq!(&observations[0].claim.hash[..4], &index.to_be_bytes());
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(forward, consume);
    })
    .await
    .unwrap();
    producer.await.unwrap();
}
