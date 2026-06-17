---
id: RUST-BUG-039
status: done
type: bug
area: rest
---

# RUST-BUG-039: Align categoryName selector validation with MFC

## Problem

MFC validates download category selectors in order: `categoryId` takes
precedence, otherwise `categoryName` must be a string and must resolve to a
configured category. Rust let malformed `categoryName` values fall through to
serde and used a separate non-MFC message for empty names.

## Resolution

- Added route metadata validation for `categoryName` when it is the active
  category selector.
- Kept MFC precedence by allowing malformed `categoryName` to be ignored during
  DTO deserialization when `categoryId` is also present.
- Changed empty `categoryName` handling to use the MFC unresolved-category
  message.
- Added REST body validation coverage across transfer create, transfer patch,
  and search-result download bodies.
- Split category-selector body validation tests into a focused module so the
  existing route body validation file stays under the Rust client size budget.

## Evidence

- `cargo fmt --all`
- `cargo test -p emulebb-rest route_body_category_validation --locked`
- `cargo test -p emulebb-core category_id_selector_ignores_malformed_category_name_like_master --locked`
- `cargo test -p emulebb-rest --locked`
- `python tools\rust_quality_gate.py quick`
- `python tools\rust_quality_gate.py ci-test`
