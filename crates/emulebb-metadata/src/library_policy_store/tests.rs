use super::*;
use crate::{MetadataIndexedFile, MetadataIndexedFileOrigin};

fn known(store: &mut MetadataStore, byte: u8) -> String {
    let hash = format!("{byte:02x}").repeat(16);
    store
        .upsert_indexed_file(
            &MetadataIndexedFile {
                ed2k_hash: hash.clone(),
                name: "Sample.bin".into(),
                size_bytes: 123,
                content_type: String::new(),
                availability_score: 0,
            },
            MetadataIndexedFileOrigin::PassiveCache,
        )
        .unwrap();
    hash
}

fn revision(store: &MetadataStore) -> i64 {
    store
        .connection()
        .unwrap()
        .query_row(
            "SELECT revision FROM library_catalog_revision WHERE id=1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn tag_identity_preserves_case_and_refuses_duplicates_and_renaming() {
    let store = MetadataStore::in_memory().unwrap();
    let tag = store.create_library_tag("Media-1").unwrap();
    assert!(tag.id > 0);
    assert_eq!(store.library_tag("MEDIA-1").unwrap(), Some(tag));
    let error = store.create_library_tag("media-1").unwrap_err();
    assert_eq!(
        error.downcast_ref::<LibraryTagError>(),
        Some(&LibraryTagError::AlreadyExists)
    );
    for replacement in ["Other", "media-1"] {
        assert!(
            store
                .connection()
                .unwrap()
                .execute("UPDATE library_tags SET name=?1", [replacement])
                .is_err()
        );
    }
    assert_eq!(
        store.library_tag("Media-1").unwrap().unwrap().name,
        "Media-1"
    );
}

#[test]
fn rust_and_sql_share_the_exact_ascii_tag_grammar() {
    let store = MetadataStore::in_memory().unwrap();
    for invalid in [
        "",
        " leading",
        "trailing ",
        "two words",
        "dot.name",
        "under_score",
        "-first",
        "line\n",
        "nul\0tail",
        "\u{e9}",
        &"a".repeat(65),
    ] {
        let error = store.create_library_tag(invalid).unwrap_err();
        assert_eq!(
            error.downcast_ref::<LibraryTagError>(),
            Some(&LibraryTagError::InvalidName),
            "{invalid:?}"
        );
        assert!(
            store
                .connection()
                .unwrap()
                .execute("INSERT INTO library_tags(name) VALUES(?1)", [invalid])
                .is_err(),
            "{invalid:?}"
        );
    }
    for valid in ["A", "0", "Sample-123", &"a".repeat(64)] {
        store.create_library_tag(valid).unwrap();
    }
}

#[test]
fn associations_are_explicit_idempotent_and_never_create_content_or_tags() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = known(&mut store, 1);
    store.create_library_tag("First").unwrap();
    assert!(store.set_library_file_tag(&hash, "FIRST", true).unwrap());
    let assigned_revision = revision(&store);
    assert!(!store.set_library_file_tag(&hash, "first", true).unwrap());
    assert_eq!(revision(&store), assigned_revision);
    let error = store
        .set_library_file_tag(&hash, "Unknown", true)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<LibraryTagError>(),
        Some(&LibraryTagError::NotFound)
    );
    let error = store
        .set_library_file_tag(&"ff".repeat(16), "First", true)
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<LibraryTagError>(),
        Some(&LibraryTagError::UnknownFile)
    );
    assert!(store.library_tag("Unknown").unwrap().is_none());
    assert!(
        store
            .library_sharing_enabled(&"ff".repeat(16))
            .unwrap()
            .is_none()
    );
    let page = store
        .library_file_tags_page(&hash, None, 200)
        .unwrap()
        .unwrap();
    assert_eq!(
        page.tags
            .iter()
            .map(|t| t.name.as_str())
            .collect::<Vec<_>>(),
        ["First"]
    );
    assert!(store.set_library_file_tag(&hash, "First", false).unwrap());
    let removed_revision = revision(&store);
    assert!(!store.set_library_file_tag(&hash, "First", false).unwrap());
    assert_eq!(revision(&store), removed_revision);
}

#[test]
fn tag_deletion_cascades_assignments_without_deleting_knowledge_or_policy() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hashes = [known(&mut store, 1), known(&mut store, 2)];
    store.create_library_tag("Rotate").unwrap();
    store.create_library_tag("Keep").unwrap();
    for hash in &hashes {
        store.set_library_file_tag(hash, "Rotate", true).unwrap();
    }
    store
        .set_library_file_tag(&hashes[0], "Keep", true)
        .unwrap();
    store
        .set_library_sharing_enabled(&hashes[0], false)
        .unwrap();
    assert!(store.delete_library_tag("ROTATE").unwrap());
    assert!(!store.delete_library_tag("Rotate").unwrap());
    assert_eq!(
        store.library_sharing_enabled(&hashes[0]).unwrap(),
        Some(false)
    );
    assert_eq!(
        store.library_sharing_enabled(&hashes[1]).unwrap(),
        Some(true)
    );
    assert_eq!(
        store
            .library_file_tags_page(&hashes[0], None, 10)
            .unwrap()
            .unwrap()
            .tags[0]
            .name,
        "Keep"
    );
    assert!(
        store
            .library_file_tags_page(&hashes[1], None, 10)
            .unwrap()
            .unwrap()
            .tags
            .is_empty()
    );
    assert!(
        store
            .connection()
            .unwrap()
            .prepare("PRAGMA foreign_key_check")
            .unwrap()
            .query([])
            .unwrap()
            .next()
            .unwrap()
            .is_none()
    );
}

#[test]
fn tag_pages_seek_names_and_bound_both_global_and_per_file_reads() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = known(&mut store, 1);
    for i in 0..205 {
        let name = format!("Tag-{i:03}");
        store.create_library_tag(&name).unwrap();
        store.set_library_file_tag(&hash, &name, true).unwrap();
    }
    let first = store.library_tags_page(None, 200).unwrap();
    assert_eq!(first.tags.len(), 200);
    assert!(first.has_more);
    assert_eq!(first.next_after.as_deref(), Some("Tag-199"));
    // A live cursor remains usable when its boundary row has been deleted.
    store.delete_library_tag("Tag-199").unwrap();
    let last = store.library_tags_page(Some("tag-199"), 200).unwrap();
    assert_eq!(last.tags.len(), 5);
    assert!(!last.has_more && last.next_after.is_none());
    let assigned = store
        .library_file_tags_page(&hash, Some("TAG-199"), 2)
        .unwrap()
        .unwrap();
    assert_eq!(
        assigned
            .tags
            .iter()
            .map(|tag| tag.name.as_str())
            .collect::<Vec<_>>(),
        ["Tag-200", "Tag-201"]
    );
    assert!(assigned.has_more);
    assert!(store.library_tags_page(None, 0).is_err());
    assert!(store.library_tags_page(None, 201).is_err());
}

#[test]
fn policy_and_tags_survive_reopen_and_reobserved_content_without_local_copies() {
    let path = std::env::temp_dir().join(format!(
        "emulebb-library-policy-{}.db",
        uuid::Uuid::new_v4()
    ));
    let hash;
    {
        let mut store = MetadataStore::open(&path).unwrap();
        hash = known(&mut store, 3);
        assert_eq!(store.library_sharing_enabled(&hash).unwrap(), Some(true));
        store.create_library_tag("Retained").unwrap();
        store.set_library_file_tag(&hash, "Retained", true).unwrap();
        assert_eq!(
            store.set_library_sharing_enabled(&hash, false).unwrap(),
            Some(true)
        );
        let changed_revision = revision(&store);
        assert_eq!(
            store.set_library_sharing_enabled(&hash, false).unwrap(),
            Some(false)
        );
        assert_eq!(revision(&store), changed_revision);
    }
    let mut store = MetadataStore::open(&path).unwrap();
    assert_eq!(known(&mut store, 3), hash);
    assert_eq!(store.library_sharing_enabled(&hash).unwrap(), Some(false));
    assert_eq!(
        store
            .library_file_tags_page(&hash, None, 10)
            .unwrap()
            .unwrap()
            .tags[0]
            .name,
        "Retained"
    );
    assert_eq!(
        store
            .set_library_sharing_enabled(&"ff".repeat(16), false)
            .unwrap(),
        None
    );
    assert!(
        store
            .library_file_tags_page(&"ff".repeat(16), None, 10)
            .unwrap()
            .is_none()
    );
    drop(store);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn failed_policy_or_assignment_write_rolls_back_the_catalog_revision() {
    let mut store = MetadataStore::in_memory().unwrap();
    let hash = known(&mut store, 4);
    store.create_library_tag("Atomic").unwrap();
    let before = revision(&store);
    store
        .connection()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER refuse_assignment BEFORE INSERT ON known_file_tags
         BEGIN SELECT RAISE(ABORT,'injected assignment fault'); END;
         CREATE TRIGGER refuse_policy AFTER UPDATE OF sharing_enabled ON known_files
         BEGIN SELECT RAISE(ABORT,'injected policy fault'); END;",
        )
        .unwrap();
    assert!(store.set_library_file_tag(&hash, "Atomic", true).is_err());
    assert!(store.set_library_sharing_enabled(&hash, false).is_err());
    assert_eq!(revision(&store), before);
    assert_eq!(store.library_sharing_enabled(&hash).unwrap(), Some(true));
    assert!(
        store
            .library_file_tags_page(&hash, None, 10)
            .unwrap()
            .unwrap()
            .tags
            .is_empty()
    );
}
