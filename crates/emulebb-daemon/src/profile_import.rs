use std::{
    collections::HashSet,
    fs,
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

const MANIFEST_SCHEMA: &str = "emulebb-rust.profile-import.v1";
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
}

pub fn apply_profile_import(
    profile: &DaemonProfile,
    manifest_path: &Path,
) -> Result<ProfileImportApplySummary> {
    let text = fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read import manifest {}", manifest_path.display()))?;
    let manifest: ProfileImportManifest = serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse import manifest {}",
            manifest_path.display()
        )
    })?;
    let profile_import = validate_manifest(manifest)?;
    let metadata = MetadataStore::open(profile.metadata_path())?;
    let summary = metadata.merge_profile_import(&profile_import)?;
    Ok(apply_summary(manifest_path, summary))
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
    ensure!(
        !manifest.shared_roots.is_empty(),
        "profile import must contain at least one shared root"
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
            file.aich_hashset.len() == expected_aich_hash_count(file.file_size),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
