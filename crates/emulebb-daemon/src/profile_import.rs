use std::{
    collections::{BTreeMap, HashSet},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use emulebb_metadata::{
    MetadataImportedKnownFileEntry, MetadataProfileImport, MetadataProfileImportSummary,
    MetadataSharedDirectoryRoot, MetadataStore, NativePath,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::DaemonProfile;

const MANIFEST_SCHEMA: &str = "emulebb.profile-exchange.v1";
const ED2K_PART_SIZE: u64 = 9_728_000;
const UPLOAD_PRIORITIES: &[&str] = &[
    "auto",
    "not-published",
    "verylow",
    "low",
    "normal",
    "high",
    "release",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileImportManifest {
    schema: String,
    generated_at_utc: String,
    target_platform: String,
    source: Value,
    shared_roots: Vec<ProfileImportRoot>,
    known_files: Vec<ProfileImportKnownFile>,
    summary: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileImportRoot {
    path: String,
    origin: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileImportKnownFile {
    file_hash: String,
    display_name: String,
    file_size: u64,
    modified_s: i64,
    md4_hashset: Vec<String>,
    aich_root: Option<String>,
    aich_hashset: Vec<String>,
    upload_priority: String,
    auto_upload_priority: bool,
    all_time_uploaded_bytes: u64,
    all_time_upload_requests: u64,
    all_time_upload_accepts: u64,
    last_upload_request_ms: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileImportApplySummary {
    manifest: PathBuf,
    imported_known_files: usize,
    skipped_native_known_files: usize,
    merged_shared_roots: usize,
    imported_recovery_sets: usize,
    rejected_recovery_sets: usize,
    recovery_rejection_reasons: BTreeMap<String, usize>,
}

pub fn apply_profile_import(
    profile: &DaemonProfile,
    manifest_path: &Path,
    hashes_only: bool,
) -> Result<ProfileImportApplySummary> {
    use rusqlite::{Connection, OpenFlags};
    let source = Connection::open_with_flags(manifest_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.execute_batch("PRAGMA query_only=ON; PRAGMA cache_size=-8192; BEGIN")?;
    let header: String = source.query_row("SELECT value FROM header", [], |row| row.get(0))?;
    let mut header: Value = serde_json::from_str(&header)?;
    ensure!(
        header["schema"] == "emulebb.profile-exchange.v1",
        "unsupported profile exchange format"
    );
    if hashes_only {
        header["targetPlatform"] = Value::from(NativePath::platform());
        header["sharedRoots"] = serde_json::json!([]);
    }
    let metadata = MetadataStore::open(profile.metadata_path())?;
    let mut total = MetadataProfileImportSummary {
        imported_known_files: 0,
        skipped_native_known_files: 0,
        merged_shared_roots: 0,
    };
    let mut query = source.prepare("SELECT record,md4,aich FROM known_files ORDER BY id")?;
    let mut rows = query.query([])?;
    let mut batch = Vec::new();
    let mut batch_bytes = 0usize;
    let mut count = 0usize;
    while let Some(row) = rows.next()? {
        let record: String = row.get(0)?;
        let mut record_bytes = record.len();
        ensure!(record.len() <= 65536, "oversized known-file record");
        let mut record: Value = serde_json::from_str(&record)?;
        for (column, key, width) in [(1, "md4Hashset", 16), (2, "aichHashset", 20)] {
            let packed: Vec<u8> = row.get(column)?;
            record_bytes += packed.len();
            ensure!(
                packed.len() % width == 0 && packed.len() <= 1_000_000,
                "invalid packed hashset"
            );
            record[key] = serde_json::to_value(
                packed
                    .chunks_exact(width)
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
            )?;
        }
        if batch_bytes + record_bytes > 4 * 1024 * 1024 && !batch.is_empty() {
            merge_exchange_batch(&metadata, &mut header, &mut batch, &mut total)?;
            batch_bytes = 0;
        }
        batch.push(record);
        batch_bytes += record_bytes;
        count += 1;
        if batch.len() == 128 {
            merge_exchange_batch(&metadata, &mut header, &mut batch, &mut total)?;
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        merge_exchange_batch(&metadata, &mut header, &mut batch, &mut total)?;
    }
    ensure!(count > 0, "profile exchange contains no known files");
    let mut summary = apply_summary(manifest_path, total);
    let mut sets =
        source.prepare("SELECT root,size_bytes FROM recovery_sets ORDER BY root,size_bytes")?;
    let mut sets = sets.query([])?;
    let mut leaves_query=source.prepare("SELECT part_index,leaves FROM recovery_parts WHERE root=?1 AND size_bytes=?2 ORDER BY part_index")?;
    while let Some(row) = sets.next()? {
        let root: Vec<u8> = row.get(0)?;
        let size: i64 = row.get(1)?;
        let result = (|| -> Result<()> {
            ensure!(size > 0 && size <= 0x4000000000, "invalid recovery size");
            let master: [u8; 20] = root.as_slice().try_into()?;
            let mut leaves = leaves_query.query(rusqlite::params![root, size])?;
            let mut parts = Vec::new();
            while let Some(row) = leaves.next()? {
                let index: i64 = row.get(0)?;
                ensure!(
                    index == parts.len() as i64 && index < (size + 9_727_999) / 9_728_000,
                    "invalid recovery part index"
                );
                let packed: Vec<u8> = row.get(1)?;
                ensure!(packed.len() <= 1060, "oversized recovery part");
                parts.push(packed);
            }
            let roots = emulebb_ed2k::ed2k_transfer::validate_aich_recovery_set(
                size as u64,
                master,
                &parts,
            )?;
            metadata.store_aich_recovery_set(&hex::encode(master), size as u64, &parts, &roots)?;
            Ok(())
        })();
        match result {
            Ok(()) => summary.imported_recovery_sets += 1,
            Err(error) => {
                summary.rejected_recovery_sets += 1;
                let reason = if summary.recovery_rejection_reasons.len() < 16 {
                    error.to_string()
                } else {
                    "additional rejection reasons".to_string()
                };
                *summary
                    .recovery_rejection_reasons
                    .entry(reason)
                    .or_default() += 1;
                if summary.rejected_recovery_sets <= 8 {
                    tracing::warn!(%error,"AICH recovery set rejected; MD4 cache retained");
                }
            }
        }
    }
    Ok(summary)
}

fn merge_exchange_batch(
    metadata: &MetadataStore,
    header: &mut Value,
    batch: &mut Vec<Value>,
    total: &mut MetadataProfileImportSummary,
) -> Result<()> {
    let value = serde_json::json!({"schema":MANIFEST_SCHEMA,"generatedAtUtc":"exchange", "targetPlatform":header["targetPlatform"],"source":header["source"],"sharedRoots":header["sharedRoots"],"knownFiles":std::mem::take(batch),"summary":{}});
    let validated = validate_manifest(serde_json::from_value(value)?)?;
    let applied = metadata.merge_profile_import(&validated)?;
    total.imported_known_files += applied.imported_known_files;
    total.skipped_native_known_files += applied.skipped_native_known_files;
    total.merged_shared_roots += applied.merged_shared_roots;
    header["sharedRoots"] = serde_json::json!([]);
    Ok(())
}

fn validate_manifest(manifest: ProfileImportManifest) -> Result<MetadataProfileImport> {
    ensure!(
        manifest.schema == MANIFEST_SCHEMA,
        "unsupported profile import schema {:?}",
        manifest.schema
    );
    ensure!(
        manifest.target_platform == NativePath::platform(),
        "profile import targets platform {:?}, current platform is {:?}",
        manifest.target_platform,
        NativePath::platform()
    );
    ensure!(
        !manifest.generated_at_utc.trim().is_empty(),
        "profile import generatedAtUtc must not be empty"
    );
    ensure!(
        manifest.source.is_object(),
        "profile import source must be an object"
    );
    ensure!(
        manifest.summary.is_object(),
        "profile import summary must be an object"
    );
    ensure!(
        !manifest.known_files.is_empty(),
        "profile import must contain at least one known file"
    );

    let mut identities = HashSet::new();
    let mut known_files = Vec::with_capacity(manifest.known_files.len());
    for file in manifest.known_files {
        validate_known_file(&file)?;
        let identity = (
            file.file_hash.to_ascii_lowercase(),
            file.display_name.clone(),
            file.file_size,
            file.modified_s,
        );
        ensure!(
            identities.insert(identity),
            "profile import contains a duplicate known-file identity"
        );
        known_files.push(MetadataImportedKnownFileEntry {
            file_hash: file.file_hash,
            display_name: file.display_name,
            file_size: file.file_size,
            modified_s: file.modified_s,
            md4_hashset: file.md4_hashset,
            aich_root: file.aich_root,
            aich_hashset: file.aich_hashset,
            upload_priority: file.upload_priority,
            auto_upload_priority: file.auto_upload_priority,
            all_time_uploaded_bytes: file.all_time_uploaded_bytes,
            all_time_upload_requests: file.all_time_upload_requests,
            all_time_upload_accepts: file.all_time_upload_accepts,
            last_upload_request_ms: file.last_upload_request_ms,
        });
    }

    let mut root_paths = HashSet::new();
    let mut shared_roots = Vec::with_capacity(manifest.shared_roots.len());
    for root in manifest.shared_roots {
        ensure!(
            !root.origin.trim().is_empty(),
            "shared-root origin must not be empty"
        );
        let path = Path::new(&root.path);
        ensure!(
            path.is_absolute(),
            "shared root must be absolute: {:?}",
            root.path
        );
        ensure!(
            !path
                .components()
                .any(|component| component == Component::ParentDir),
            "shared root must not contain traversal: {:?}",
            root.path
        );
        let root_identity = if NativePath::platform() == "windows" {
            root.path.to_ascii_lowercase()
        } else {
            root.path.clone()
        };
        ensure!(
            root_paths.insert(root_identity),
            "duplicate shared root: {:?}",
            root.path
        );
        let accessible = path.is_dir();
        shared_roots.push(MetadataSharedDirectoryRoot {
            path: root.path,
            monitor_owned: false,
            shareable: accessible,
            accessible,
        });
    }

    Ok(MetadataProfileImport {
        known_files,
        shared_roots,
    })
}

fn validate_known_file(file: &ProfileImportKnownFile) -> Result<()> {
    validate_hex(&file.file_hash, 16, "ED2K hash")?;
    ensure!(
        !file.display_name.trim().is_empty(),
        "known-file name must not be empty"
    );
    ensure!(file.file_size > 0, "known-file size must be positive");
    i64::try_from(file.file_size).context("known-file size exceeds SQLite range")?;
    ensure!(file.modified_s > 0, "known-file mtime must be positive");
    ensure!(
        file.md4_hashset.len() == expected_md4_hash_count(file.file_size),
        "known-file MD4 hashset count does not match file size"
    );
    for hash in &file.md4_hashset {
        validate_hex(hash, 16, "MD4 part hash")?;
    }
    if let Some(aich_root) = file.aich_root.as_deref() {
        validate_hex(aich_root, 20, "AICH root")?;
        ensure!(
            file.aich_hashset.is_empty()
                || file.aich_hashset.len() == expected_aich_hash_count(file.file_size),
            "known-file AICH hashset count does not match file size"
        );
    } else {
        ensure!(
            file.aich_hashset.is_empty(),
            "AICH hashset requires an AICH root"
        );
    }
    for hash in &file.aich_hashset {
        validate_hex(hash, 20, "AICH part hash")?;
    }
    ensure!(
        UPLOAD_PRIORITIES.contains(&file.upload_priority.as_str()),
        "unsupported upload priority {:?}",
        file.upload_priority
    );
    i64::try_from(file.all_time_uploaded_bytes)
        .context("uploaded-byte total exceeds SQLite range")?;
    i64::try_from(file.all_time_upload_requests)
        .context("upload-request total exceeds SQLite range")?;
    i64::try_from(file.all_time_upload_accepts)
        .context("upload-accept total exceeds SQLite range")?;
    ensure!(
        file.last_upload_request_ms >= 0,
        "last upload request timestamp must not be negative"
    );
    Ok(())
}

fn validate_hex(value: &str, byte_len: usize, label: &str) -> Result<()> {
    ensure!(
        value.len() == byte_len * 2 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must be {} hex characters",
        byte_len * 2
    );
    Ok(())
}

fn expected_md4_hash_count(file_size: u64) -> usize {
    let whole_parts = file_size / ED2K_PART_SIZE;
    usize::try_from(whole_parts + u64::from(whole_parts > 0)).unwrap_or(usize::MAX)
}

fn expected_aich_hash_count(file_size: u64) -> usize {
    if file_size <= ED2K_PART_SIZE {
        return 0;
    }
    usize::try_from(file_size.div_ceil(ED2K_PART_SIZE)).unwrap_or(usize::MAX)
}

fn apply_summary(
    manifest_path: &Path,
    summary: MetadataProfileImportSummary,
) -> ProfileImportApplySummary {
    ProfileImportApplySummary {
        manifest: manifest_path.to_path_buf(),
        imported_known_files: summary.imported_known_files,
        skipped_native_known_files: summary.skipped_native_known_files,
        merged_shared_roots: summary.merged_shared_roots,
        imported_recovery_sets: 0,
        rejected_recovery_sets: 0,
        recovery_rejection_reasons: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_import_streams_100k_aliases_without_payload_paths() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("scale.sqlite");
        let mut source = rusqlite::Connection::open(&artifact).unwrap();
        source.execute_batch("CREATE TABLE header(value TEXT); CREATE TABLE known_files(id INTEGER PRIMARY KEY,record TEXT,md4 BLOB,aich BLOB); CREATE TABLE recovery_sets(root BLOB,size_bytes INTEGER); CREATE TABLE recovery_parts(root BLOB,size_bytes INTEGER,part_index INTEGER,leaves BLOB);").unwrap();
        source.execute("INSERT INTO header VALUES (?1)",[serde_json::json!({"schema":MANIFEST_SCHEMA,"targetPlatform":NativePath::platform(),"source":{},"sharedRoots":[]}).to_string()]).unwrap();
        let mut record = serde_json::json!({"fileHash":"11".repeat(16),"displayName":"Sample.bin","fileSize":1024,"modifiedS":1700000000i64,"aichRoot":null,"uploadPriority":"normal","autoUploadPriority":false,"allTimeUploadedBytes":0,"allTimeUploadRequests":0,"allTimeUploadAccepts":0,"lastUploadRequestMs":0});
        let tx = source.transaction().unwrap();
        {
            let mut insert = tx
                .prepare("INSERT INTO known_files(record,md4,aich) VALUES(?1,X'',X'')")
                .unwrap();
            for index in 0..100_001 {
                record["displayName"] = serde_json::Value::from(format!("Sample {index}.bin"));
                insert.execute([record.to_string()]).unwrap();
            }
        }
        tx.commit().unwrap();
        let profile = DaemonProfile::load_for_import(temp.path().join("target")).unwrap();
        let summary = apply_profile_import(&profile, &artifact, true).unwrap();
        assert_eq!(summary.imported_known_files, 100_001);
        assert_eq!(summary.imported_recovery_sets, 0);
        let target = rusqlite::Connection::open(profile.metadata_path()).unwrap();
        assert_eq!(
            target
                .query_row("SELECT count(*) FROM imported_known_files", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
            100_001
        );
    }

    #[test]
    fn sqlite_exchange_reimports_recovery_and_rejects_corruption_without_losing_md4() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("hashes.sqlite");
        let source = rusqlite::Connection::open(&artifact).unwrap();
        source.execute_batch("CREATE TABLE header(value TEXT); CREATE TABLE known_files(id INTEGER PRIMARY KEY,record TEXT,md4 BLOB,aich BLOB); CREATE TABLE recovery_sets(root BLOB,size_bytes INTEGER); CREATE TABLE recovery_parts(root BLOB,size_bytes INTEGER,part_index INTEGER,leaves BLOB,PRIMARY KEY(root,size_bytes,part_index));").unwrap();
        let master = hex::encode([7u8; 20]);
        let header = serde_json::json!({"schema":"emulebb.profile-exchange.v1","targetPlatform":"foreign-platform","sharedRoots":[],"source":{}});
        source
            .execute("INSERT INTO header VALUES (?1)", [header.to_string()])
            .unwrap();
        let record = serde_json::json!({"fileHash":"11".repeat(16),"displayName":"Sample.bin","fileSize":1024,"modifiedS":1700000000i64,"aichRoot":master,"uploadPriority":"normal","autoUploadPriority":false,"allTimeUploadedBytes":0,"allTimeUploadRequests":0,"allTimeUploadAccepts":0,"lastUploadRequestMs":0});
        source
            .execute(
                "INSERT INTO known_files VALUES(1,?1,X'',X'')",
                [record.to_string()],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO recovery_sets VALUES (?1,1024)",
                [[7u8; 20].as_slice()],
            )
            .unwrap();
        source
            .execute(
                "INSERT INTO recovery_parts VALUES(?1,1024,0,?1)",
                [[7u8; 20].as_slice()],
            )
            .unwrap();
        let profile = DaemonProfile::load_for_import(temp.path().join("target")).unwrap();
        assert!(apply_profile_import(&profile, &artifact, false).is_err());
        for _ in 0..2 {
            let summary = apply_profile_import(&profile, &artifact, true).unwrap();
            assert_eq!(summary.imported_recovery_sets, 1);
            assert_eq!(summary.rejected_recovery_sets, 0);
        }
        source
            .execute(
                "UPDATE recovery_parts SET leaves=?1",
                [[8u8; 20].as_slice()],
            )
            .unwrap();
        let summary = apply_profile_import(&profile, &artifact, true).unwrap();
        assert_eq!(summary.rejected_recovery_sets, 1);
        let native = MetadataStore::open(profile.metadata_path()).unwrap();
        assert_eq!(
            native.aich_recovery_part(&master, 1024, 0).unwrap(),
            Some(vec![7; 20])
        );
    }

    fn small_file() -> ProfileImportKnownFile {
        ProfileImportKnownFile {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "sample.bin".to_string(),
            file_size: 1024,
            modified_s: 1_700_000_000,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
        }
    }

    fn manifest_with_roots(paths: &[&str]) -> ProfileImportManifest {
        ProfileImportManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            generated_at_utc: "2026-10-23T00:00:00Z".to_string(),
            target_platform: NativePath::platform().to_string(),
            source: serde_json::json!({}),
            shared_roots: paths
                .iter()
                .map(|path| ProfileImportRoot {
                    path: (*path).to_string(),
                    origin: "test".to_string(),
                })
                .collect(),
            known_files: vec![small_file()],
            summary: serde_json::json!({}),
        }
    }

    #[test]
    fn small_file_without_part_hashes_is_valid() {
        let file = small_file();

        validate_known_file(&file).unwrap();
    }

    #[test]
    fn hash_only_manifest_needs_no_shared_roots() {
        let imported = validate_manifest(manifest_with_roots(&[])).unwrap();
        assert!(imported.shared_roots.is_empty());
        assert_eq!(imported.known_files.len(), 1);
    }

    #[test]
    fn aich_root_without_optional_part_hashes_preserves_ed2k_hashes() {
        let mut file = small_file();
        file.file_size = ED2K_PART_SIZE + 1;
        file.md4_hashset = vec!["11".repeat(16), "22".repeat(16)];
        file.aich_root = Some("33".repeat(20));
        validate_known_file(&file).unwrap();
    }

    #[test]
    fn mismatched_hashset_count_is_rejected() {
        let file = ProfileImportKnownFile {
            file_hash: "00112233445566778899aabbccddeeff".to_string(),
            display_name: "sample.bin".to_string(),
            file_size: ED2K_PART_SIZE + 1,
            modified_s: 1_700_000_000,
            md4_hashset: Vec::new(),
            aich_root: None,
            aich_hashset: Vec::new(),
            upload_priority: "normal".to_string(),
            auto_upload_priority: false,
            all_time_uploaded_bytes: 0,
            all_time_upload_requests: 0,
            all_time_upload_accepts: 0,
            last_upload_request_ms: 0,
        };

        assert!(validate_known_file(&file).is_err());
    }

    #[test]
    fn shared_root_traversal_is_rejected() {
        let root = if cfg!(windows) {
            r"C:\shared\..\escape"
        } else {
            "/shared/../escape"
        };

        let error = validate_manifest(manifest_with_roots(&[root]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("must not contain traversal"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_shared_roots_are_case_insensitive() {
        let error = validate_manifest(manifest_with_roots(&[r"C:\Shared", r"c:\shared"]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("duplicate shared root"));
    }
}
