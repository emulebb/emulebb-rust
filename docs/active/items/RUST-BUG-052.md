---
id: RUST-BUG-052
title: Persist transfer category assignments across restart
status: done
priority: Major
category: bug
workflow: github
---

# RUST-BUG-052: Persist transfer category assignments across restart

## Problem

Rust kept a transfer's `categoryId` / `categoryName` only in the in-memory REST
view. After daemon restart, transfers rebuilt from persisted ED2K manifests fell
back to the default category. eMuleBB MFC persists the download category in the
part-file metadata (`FT_CATEGORY`), so transfer category assignment survives
restart.

## Acceptance

- [x] The ED2K resume manifest carries the transfer category id.
- [x] The metadata store saves and reloads `transfers.category_id`.
- [x] REST transfer views resolve the persisted category id back to the current
      category name after restart.
- [x] Missing or removed category ids degrade to the default category instead
      of surfacing a dangling id.

## Implementation Notes

- Added `category_id` to the ED2K resume manifest and metadata transfer model.
- Wired `transfers.category_id` into transfer manifest upsert/load queries.
- Persisted category changes when transfers are created or patched through the
  public transfer category selector.
- Added core restart coverage for category persistence.

## Evidence

- `cargo test -p emulebb-core transfer_category_survives_restart --locked`
- `cargo test -p emulebb-metadata transfer_manifest_roundtrips_sql_tables --locked`
