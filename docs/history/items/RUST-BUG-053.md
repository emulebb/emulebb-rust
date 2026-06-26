---
id: RUST-BUG-053
title: Reindex transfer categories after category deletion
status: done
priority: Major
category: bug
workflow: github
---

# RUST-BUG-053: Reindex transfer categories after category deletion

## Problem

Rust treated category ids as stable identifiers when a category was deleted.
eMuleBB MFC stores categories as array indexes: deleting category `N` resets
downloads in `N` to the default category and shifts downloads in later
categories down by one. Rust therefore diverged from MFC category semantics and
could leave transfer category assignments pointing at the wrong logical slot.

## Acceptance

- [x] Deleting a non-default category removes it from the configured category
      list.
- [x] Transfers in the deleted category move to the default category.
- [x] Transfers in later categories shift down by one category id.
- [x] Shifted category ids and transfer assignments survive daemon restart.
- [x] The category controller logic is moved out of `lib.rs` to keep the source
      size gate healthy.

## Implementation Notes

- Added `category_runtime.rs` for category controller operations.
- Reindexed configured categories above the deleted id and persisted the shifted
  category rows.
- Updated affected transfer views and persisted their ED2K manifest category id.
- Added restart coverage for delete/reindex semantics.

## Evidence

- `cargo test -p emulebb-core category_persistence --locked`
- `python tools\rust_quality_gate.py quick`
