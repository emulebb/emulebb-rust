use std::{
    collections::HashSet,
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use crate::DIAG_EVENT_FILE_PREFIX;

const MAX_REPORTED_CONSTRAINTS: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetentionPolicy {
    pub(crate) retained_segments: usize,
    pub(crate) max_total_bytes: u64,
    pub(crate) max_retained_age: Duration,
    pub(crate) minimum_free_bytes: u64,
}

#[derive(Debug, Clone)]
struct SegmentArtifact {
    path: PathBuf,
    file_name: String,
    size_bytes: u64,
    modified: SystemTime,
}

#[derive(Debug)]
struct SegmentInventory {
    segments: Vec<SegmentArtifact>,
    total_bytes: u64,
    scan_errors: u64,
}

#[derive(Debug)]
struct RetentionPlan {
    delete_paths: Vec<PathBuf>,
    unresolved_constraints: Vec<&'static str>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RetentionOutcome {
    pub(crate) deleted: u64,
    pub(crate) delete_errors: u64,
    pub(crate) scan_errors: u64,
    pub(crate) free_space_probe_errors: u64,
    pub(crate) policy_failures: u64,
    pub(crate) retained_segment_count: usize,
    pub(crate) retained_bytes: u64,
    pub(crate) available_bytes: Option<u64>,
    pub(crate) unresolved_constraints: Vec<&'static str>,
}

impl RetentionOutcome {
    pub(crate) fn within_limits(&self) -> bool {
        self.scan_errors == 0
            && self.delete_errors == 0
            && self.free_space_probe_errors == 0
            && self.unresolved_constraints.is_empty()
    }
}

pub(crate) fn enforce(
    directory: &Path,
    active_path: &Path,
    policy: RetentionPolicy,
    reserved_bytes: u64,
    now: SystemTime,
    free_space_probe: &dyn Fn(&Path) -> io::Result<u64>,
) -> RetentionOutcome {
    let initial = inventory_segments(directory);
    let (initial_available_bytes, initial_probe_errors) =
        available_bytes(directory, policy.minimum_free_bytes, free_space_probe);
    let plan = plan_retention(
        &initial,
        active_path,
        policy,
        reserved_bytes,
        now,
        initial_available_bytes,
    );
    let mut outcome = RetentionOutcome {
        scan_errors: initial.scan_errors,
        free_space_probe_errors: initial_probe_errors,
        ..RetentionOutcome::default()
    };
    for path in plan.delete_paths {
        match fs::remove_file(path) {
            Ok(()) => outcome.deleted = outcome.deleted.saturating_add(1),
            Err(_) => outcome.delete_errors = outcome.delete_errors.saturating_add(1),
        }
    }

    let verification = inventory_segments(directory);
    let (verification_available_bytes, verification_probe_errors) =
        available_bytes(directory, policy.minimum_free_bytes, free_space_probe);
    let verification_plan = plan_retention(
        &verification,
        active_path,
        policy,
        reserved_bytes,
        now,
        verification_available_bytes,
    );
    outcome.scan_errors = outcome.scan_errors.saturating_add(verification.scan_errors);
    outcome.free_space_probe_errors = outcome
        .free_space_probe_errors
        .saturating_add(verification_probe_errors);
    outcome.retained_segment_count = verification.segments.len();
    outcome.retained_bytes = verification.total_bytes;
    outcome.available_bytes = verification_available_bytes;
    outcome.unresolved_constraints = verification_plan.unresolved_constraints;
    if !verification_plan.delete_paths.is_empty() {
        outcome.unresolved_constraints.push("pending_deletions");
    }
    outcome
        .unresolved_constraints
        .truncate(MAX_REPORTED_CONSTRAINTS);
    if !outcome.within_limits() {
        outcome.policy_failures = 1;
    }
    outcome
}

fn available_bytes(
    directory: &Path,
    minimum_free_bytes: u64,
    free_space_probe: &dyn Fn(&Path) -> io::Result<u64>,
) -> (Option<u64>, u64) {
    if minimum_free_bytes == 0 {
        return (None, 0);
    }
    match free_space_probe(directory) {
        Ok(available_bytes) => (Some(available_bytes), 0),
        Err(_) => (None, 1),
    }
}

fn inventory_segments(directory: &Path) -> SegmentInventory {
    let Ok(entries) = fs::read_dir(directory) else {
        return SegmentInventory {
            segments: Vec::new(),
            total_bytes: 0,
            scan_errors: 1,
        };
    };
    let mut segments = Vec::new();
    let mut total_bytes = 0_u64;
    let mut scan_errors = 0_u64;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                scan_errors = scan_errors.saturating_add(1);
                continue;
            }
        };
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.starts_with(DIAG_EVENT_FILE_PREFIX) || !file_name.ends_with(".jsonl") {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => continue,
            Err(_) => {
                scan_errors = scan_errors.saturating_add(1);
                continue;
            }
        };
        let size_bytes = metadata.len();
        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(_) => {
                scan_errors = scan_errors.saturating_add(1);
                SystemTime::UNIX_EPOCH
            }
        };
        total_bytes = total_bytes.saturating_add(size_bytes);
        segments.push(SegmentArtifact {
            path: entry.path(),
            file_name,
            size_bytes,
            modified,
        });
    }
    segments.sort_by(|left, right| {
        left.modified
            .cmp(&right.modified)
            .then_with(|| left.file_name.cmp(&right.file_name))
    });
    SegmentInventory {
        segments,
        total_bytes,
        scan_errors,
    }
}

fn plan_retention(
    inventory: &SegmentInventory,
    active_path: &Path,
    policy: RetentionPolicy,
    reserved_bytes: u64,
    now: SystemTime,
    available_bytes: Option<u64>,
) -> RetentionPlan {
    let mut selected = HashSet::new();
    let mut delete_paths = Vec::new();
    let mut projected_segment_count = inventory.segments.len();
    let mut projected_total_bytes = inventory.total_bytes.saturating_add(reserved_bytes);
    let mut projected_free_bytes =
        available_bytes.map(|available| available.saturating_sub(reserved_bytes));

    for artifact in &inventory.segments {
        if artifact.path != active_path
            && now
                .duration_since(artifact.modified)
                .is_ok_and(|age| age > policy.max_retained_age)
        {
            select_artifact(
                artifact,
                active_path,
                &mut selected,
                &mut delete_paths,
                &mut projected_segment_count,
                &mut projected_total_bytes,
                &mut projected_free_bytes,
            );
        }
    }
    for artifact in &inventory.segments {
        if projected_segment_count <= policy.retained_segments {
            break;
        }
        select_artifact(
            artifact,
            active_path,
            &mut selected,
            &mut delete_paths,
            &mut projected_segment_count,
            &mut projected_total_bytes,
            &mut projected_free_bytes,
        );
    }
    for artifact in &inventory.segments {
        if projected_total_bytes <= policy.max_total_bytes {
            break;
        }
        select_artifact(
            artifact,
            active_path,
            &mut selected,
            &mut delete_paths,
            &mut projected_segment_count,
            &mut projected_total_bytes,
            &mut projected_free_bytes,
        );
    }
    if projected_free_bytes.is_some() {
        for artifact in &inventory.segments {
            if projected_free_bytes.is_some_and(|projected| projected >= policy.minimum_free_bytes)
            {
                break;
            }
            select_artifact(
                artifact,
                active_path,
                &mut selected,
                &mut delete_paths,
                &mut projected_segment_count,
                &mut projected_total_bytes,
                &mut projected_free_bytes,
            );
        }
    }

    let mut unresolved_constraints = Vec::new();
    if projected_segment_count > policy.retained_segments {
        unresolved_constraints.push("retained_segments");
    }
    if projected_total_bytes > policy.max_total_bytes {
        unresolved_constraints.push("max_total_bytes");
    }
    if policy.minimum_free_bytes > 0
        && !projected_free_bytes.is_some_and(|projected| projected >= policy.minimum_free_bytes)
    {
        unresolved_constraints.push("minimum_free_bytes");
    }
    RetentionPlan {
        delete_paths,
        unresolved_constraints,
    }
}

fn select_artifact(
    artifact: &SegmentArtifact,
    active_path: &Path,
    selected: &mut HashSet<PathBuf>,
    delete_paths: &mut Vec<PathBuf>,
    projected_segment_count: &mut usize,
    projected_total_bytes: &mut u64,
    projected_free_bytes: &mut Option<u64>,
) {
    if artifact.path == active_path || !selected.insert(artifact.path.clone()) {
        return;
    }
    delete_paths.push(artifact.path.clone());
    *projected_segment_count = projected_segment_count.saturating_sub(1);
    *projected_total_bytes = projected_total_bytes.saturating_sub(artifact.size_bytes);
    if let Some(projected_free_bytes) = projected_free_bytes {
        *projected_free_bytes = projected_free_bytes.saturating_add(artifact.size_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(name: &str, size_bytes: u64, modified_seconds: u64) -> SegmentArtifact {
        SegmentArtifact {
            path: PathBuf::from(name),
            file_name: name.to_string(),
            size_bytes,
            modified: SystemTime::UNIX_EPOCH + Duration::from_secs(modified_seconds),
        }
    }

    fn policy() -> RetentionPolicy {
        RetentionPolicy {
            retained_segments: 3,
            max_total_bytes: 100,
            max_retained_age: Duration::from_secs(100),
            minimum_free_bytes: 0,
        }
    }

    #[test]
    fn plan_deletes_expired_then_oldest_for_count_and_bytes() {
        let inventory = SegmentInventory {
            segments: vec![
                artifact("expired.jsonl", 20, 1),
                artifact("old.jsonl", 40, 150),
                artifact("new.jsonl", 40, 160),
                artifact("active.jsonl", 10, 170),
            ],
            total_bytes: 110,
            scan_errors: 0,
        };

        let plan = plan_retention(
            &inventory,
            Path::new("active.jsonl"),
            policy(),
            50,
            SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            None,
        );

        assert_eq!(
            plan.delete_paths,
            vec![PathBuf::from("expired.jsonl"), PathBuf::from("old.jsonl")]
        );
        assert!(plan.unresolved_constraints.is_empty());
    }

    #[test]
    fn plan_never_deletes_active_segment_and_reports_unresolved_bytes() {
        let inventory = SegmentInventory {
            segments: vec![artifact("active.jsonl", 120, 1)],
            total_bytes: 120,
            scan_errors: 0,
        };

        let plan = plan_retention(
            &inventory,
            Path::new("active.jsonl"),
            policy(),
            0,
            SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            None,
        );

        assert!(plan.delete_paths.is_empty());
        assert_eq!(plan.unresolved_constraints, vec!["max_total_bytes"]);
    }

    #[test]
    fn plan_deletes_oldest_closed_segments_to_preserve_free_space() {
        let inventory = SegmentInventory {
            segments: vec![
                artifact("old.jsonl", 30, 150),
                artifact("new.jsonl", 30, 160),
                artifact("active.jsonl", 0, 170),
            ],
            total_bytes: 60,
            scan_errors: 0,
        };
        let policy = RetentionPolicy {
            retained_segments: 3,
            max_total_bytes: 1_000,
            max_retained_age: Duration::MAX,
            minimum_free_bytes: 100,
        };

        let plan = plan_retention(
            &inventory,
            Path::new("active.jsonl"),
            policy,
            20,
            SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            Some(90),
        );

        assert_eq!(plan.delete_paths, vec![PathBuf::from("old.jsonl")]);
        assert!(plan.unresolved_constraints.is_empty());
    }

    #[test]
    fn plan_does_not_delete_when_free_space_cannot_be_measured() {
        let inventory = SegmentInventory {
            segments: vec![
                artifact("closed.jsonl", 30, 150),
                artifact("active.jsonl", 0, 170),
            ],
            total_bytes: 30,
            scan_errors: 0,
        };
        let policy = RetentionPolicy {
            retained_segments: 3,
            max_total_bytes: 1_000,
            max_retained_age: Duration::MAX,
            minimum_free_bytes: 100,
        };

        let plan = plan_retention(
            &inventory,
            Path::new("active.jsonl"),
            policy,
            20,
            SystemTime::UNIX_EPOCH + Duration::from_secs(200),
            None,
        );

        assert!(plan.delete_paths.is_empty());
        assert_eq!(plan.unresolved_constraints, vec!["minimum_free_bytes"]);
    }
}
