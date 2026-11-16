//! Category name and profile-relative path preparation.

use crate::NullableStringField;
use anyhow::{Result, ensure};
use emulebb_ed2k::long_path::normal_path_display;
use std::path::{Path, PathBuf};

pub(crate) fn normalize_category_name(name: String) -> Result<String> {
    ensure!(
        emulebb_metadata::valid_category_name(&name),
        "name must be 1-64 ASCII letters, digits, or hyphens and start with a letter or digit"
    );
    Ok(name)
}

pub(crate) fn resolve_category_path(
    profile: &Path,
    value: NullableStringField,
    previous: Option<String>,
) -> Result<Option<String>> {
    match value {
        NullableStringField::Missing => Ok(previous),
        NullableStringField::Null(()) => Ok(None),
        NullableStringField::Value(value) => {
            ensure!(!value.trim().is_empty(), "path must not be empty");
            let path = PathBuf::from(value);
            let path = if path.is_absolute() {
                path
            } else {
                profile.join(path)
            };
            Ok(Some(normal_path_display(path.display().to_string())))
        }
    }
}
