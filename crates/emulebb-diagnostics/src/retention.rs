use std::{
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use crate::DIAG_EVENT_FILE_PREFIX;

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RetentionOutcome {
    pub(crate) deleted: u64,
    pub(crate) delete_errors: u64,
}

pub(crate) fn enforce_segment_count(
    directory: &Path,
    active_path: &Path,
    process_id: u32,
    run_id: &str,
    retained_segments: usize,
) -> RetentionOutcome {
    let run_prefix = format!("{DIAG_EVENT_FILE_PREFIX}{process_id}-{run_id}-");
    let Ok(entries) = fs::read_dir(directory) else {
        return RetentionOutcome {
            delete_errors: 1,
            ..RetentionOutcome::default()
        };
    };
    let mut prior_run_segments = Vec::new();
    let mut current_run_segments = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path == active_path {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.starts_with(DIAG_EVENT_FILE_PREFIX) || !file_name.ends_with(".jsonl") {
            continue;
        }
        if let Some(segment_id) = file_name
            .strip_prefix(&run_prefix)
            .and_then(|tail| tail.strip_suffix(".jsonl"))
            .and_then(|tail| tail.parse::<u64>().ok())
        {
            current_run_segments.push((segment_id, file_name, path));
        } else {
            let modified = entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            prior_run_segments.push((modified, file_name, path));
        }
    }
    prior_run_segments
        .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    current_run_segments
        .sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let total_segments = prior_run_segments.len() + current_run_segments.len() + 1;
    let delete_count = total_segments.saturating_sub(retained_segments);
    let delete_paths = prior_run_segments
        .into_iter()
        .map(|(_, _, path)| path)
        .chain(current_run_segments.into_iter().map(|(_, _, path)| path))
        .take(delete_count)
        .collect::<Vec<PathBuf>>();

    let mut outcome = RetentionOutcome::default();
    for path in delete_paths {
        match fs::remove_file(path) {
            Ok(()) => outcome.deleted = outcome.deleted.saturating_add(1),
            Err(_) => outcome.delete_errors = outcome.delete_errors.saturating_add(1),
        }
    }
    outcome
}
