//! Download-category model helpers.
//!
//! The default category set plus the create/update appliers, name/path/color
//! normalizers, and the priority parser. Moved verbatim out of `lib.rs` during
//! the maintainability restructuring; pure helpers over the `Category` REST
//! model with no behavior beyond what they had inline.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, ensure};
use emulebb_ed2k::long_path::long_path;

use crate::{
    Category, CategoryCreate, CategoryPriorityValue, CategoryUpdate, NullableStringField,
    NullableU32Field,
};

pub(crate) const PR_LOW: u32 = 0;
pub(crate) const PR_NORMAL: u32 = 1;
pub(crate) const PR_HIGH: u32 = 2;
pub(crate) const PR_VERYHIGH: u32 = 3;
pub(crate) const PR_VERYLOW: u32 = 4;

pub(crate) fn default_categories() -> BTreeMap<u32, Category> {
    BTreeMap::from([(
        0,
        Category {
            id: 0,
            name: "All".to_string(),
            path: None,
            comment: String::new(),
            priority: PR_NORMAL,
            color: None,
        },
    )])
}

pub(crate) fn apply_category_create(
    category: &mut Category,
    request: CategoryCreate,
) -> Result<()> {
    category.name = normalize_category_name(Some(request.name))?;
    apply_category_path(category, request.path)?;
    if let Some(comment) = request.comment {
        category.comment = comment;
    }
    apply_category_color(category, request.color)?;
    if let Some(priority) = request.priority {
        category.priority = parse_category_priority(priority)?;
    }
    Ok(())
}

pub(crate) fn apply_category_update(
    category: &mut Category,
    request: CategoryUpdate,
) -> Result<()> {
    if request.name.is_some() {
        category.name = normalize_category_name(request.name)?;
    }
    apply_category_path(category, request.path)?;
    if let Some(comment) = request.comment {
        category.comment = comment;
    }
    apply_category_color(category, request.color)?;
    if let Some(priority) = request.priority {
        category.priority = parse_category_priority(priority)?;
    }
    Ok(())
}

pub(crate) fn normalize_category_name(name: Option<String>) -> Result<String> {
    let name = name
        .ok_or_else(|| anyhow::anyhow!("name must be a non-empty string"))?
        .trim()
        .to_string();
    ensure!(!name.is_empty(), "name must not be empty");
    Ok(name)
}

fn apply_category_path(category: &mut Category, path: NullableStringField) -> Result<()> {
    category.path = match path {
        NullableStringField::Missing => return Ok(()),
        NullableStringField::Value(path) => {
            let path = path.trim();
            ensure!(!path.is_empty(), "path must not be empty");
            // Operator-facing category-path boundary: a per-category
            // download/incoming directory is an operator content path, so it is
            // resolved/opened through the long-path helper. The current model
            // stores+validates the category path here but does not yet open a
            // download file under it (completed payloads live in the internal
            // short-path piece store), so this is where a category path is
            // consumed today and the boundary is ready for when category-rooted
            // output lands. (Operator-rule scope: category paths -- see
            // long_path.rs.)
            let long = long_path(Path::new(path));
            let canonical =
                fs::canonicalize(&long).with_context(|| format!("failed to resolve {path}"))?;
            ensure!(canonical.is_dir(), "path is not a directory");
            Some(canonical.display().to_string())
        }
        NullableStringField::Null(()) => None,
    };
    Ok(())
}

fn apply_category_color(category: &mut Category, color: NullableU32Field) -> Result<()> {
    match color {
        NullableU32Field::Missing => {}
        NullableU32Field::Value(color) => {
            ensure!(color <= 0x00ff_ffff, "color must be null or an RGB integer");
            category.color = Some(color);
        }
        NullableU32Field::Null(()) => {
            category.color = None;
        }
    }
    Ok(())
}

fn parse_category_priority(priority: CategoryPriorityValue) -> Result<u32> {
    match priority {
        CategoryPriorityValue::Number(value) => Ok(value),
        CategoryPriorityValue::Name(value) => match value.trim().to_ascii_lowercase().as_str() {
            "verylow" => Ok(PR_VERYLOW),
            "low" => Ok(PR_LOW),
            "normal" => Ok(PR_NORMAL),
            "high" => Ok(PR_HIGH),
            "veryhigh" => Ok(PR_VERYHIGH),
            _ => anyhow::bail!("priority must be one of verylow, low, normal, high, veryhigh"),
        },
    }
}
