use super::*;
use crate::persistence_owner::content_observations::tests::search_fixture;
use crate::persistence_owner::tests::usage;
use emulebb_metadata::MetadataSearchProjection;

#[tokio::test]
async fn selected_download_seed_is_byte_bounded_and_keeps_its_reply_charge() {
    let (store, state, owner, publication, mut observations) = search_fixture().await;
    let id: i64 = publication.search_id.parse().unwrap();
    let fields = crate::search_state::result_fields(&publication.result);
    let mut claim_id = 0;
    for index in 0..220 {
        observations[0].metadata.name = Some(format!("{index:03}{}", "x".repeat(5000)));
        claim_id = store
            .ingest_search_observations(
                &observations,
                &MetadataSearchProjection {
                    session_id: id,
                    fields: fields.clone(),
                    name_votes: vec![emulebb_metadata::MetadataSearchNameVote {
                        normalized_name: observations[0].metadata.name.clone().unwrap(),
                        reporter_endpoint: observations[0].reporter_endpoint,
                        origin: observations[0].origin,
                        quality: emulebb_metadata::MetadataSearchNameQuality {
                            useful: true,
                            sources: 3,
                            complete_sources: 0,
                            rating: 0,
                        },
                    }],
                },
            )
            .unwrap()
            .unwrap()
            .claim_id;
    }
    state.lock().await.searches.clear();
    let seed = owner.search_download_seed(id, claim_id).await.unwrap();
    assert_eq!(usage(&owner), (0, SEED_BYTES));
    let selected = seed.value().as_ref().unwrap();
    assert_eq!(selected.claim_id, claim_id);
    assert!(!selected.observations.is_empty());
    assert!(selected.observations.len() < 100);
    assert_eq!(
        store.table_count("search_result_observations").unwrap(),
        220
    );
    assert!(state.lock().await.searches.is_empty());
    drop(seed);
    assert_eq!(usage(&owner), (0, 0));
    let missing = owner.search_download_seed(id, claim_id + 1).await.unwrap();
    assert!(missing.value().is_none());
    drop(missing);
    assert_eq!(usage(&owner), (0, 0));
    owner.close_and_drain().await.unwrap();
}
