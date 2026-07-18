from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).resolve().parents[1] / "check_rust_client_policy.py"
SPEC = importlib.util.spec_from_file_location("check_rust_client_policy", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class TestMaintainabilityAdvisories(unittest.TestCase):
    def test_toolchain_version_matches_workspace_minor(self) -> None:
        self.assertTrue(CHECKER.toolchain_versions_match("1.97.0", "1.97"))
        self.assertFalse(CHECKER.toolchain_versions_match("stable", "1.97"))
        self.assertFalse(CHECKER.toolchain_versions_match("1.96.1", "1.97"))

    def test_test_path_classification_covers_supported_layouts(self) -> None:
        self.assertTrue(CHECKER.is_test_path("crates/example/tests/scenario.rs"))
        self.assertTrue(CHECKER.is_test_path("crates/example/src/tests.rs"))
        self.assertTrue(CHECKER.is_test_path("crates/example/src/codec_tests.rs"))
        self.assertFalse(CHECKER.is_test_path("crates/example/src/codec.rs"))

    def test_inline_test_module_counts_only_braced_inline_modules(self) -> None:
        text = """\
fn production() {}

#[cfg(test)]
mod external_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn works() {
        assert!(true);
    }
}
"""
        self.assertEqual(CHECKER.inline_test_module_line_counts(text), [7])

    def test_ranked_advisories_are_non_mutating_and_limited(self) -> None:
        files = [(f"src/file_{index}.rs", index) for index in range(10)]
        advisories = CHECKER.ranked_file_advisories("production", files)
        self.assertEqual(len(advisories), CHECKER.LARGEST_FILES_REPORTED_PER_KIND)
        self.assertIn("src/file_9.rs (9 lines)", advisories[0])

    def test_changed_files_are_prioritized_and_limited(self) -> None:
        files = [(f"src/file_{index}.rs", index) for index in range(25)]
        changed = {path for path, _ in files}
        advisories = CHECKER.changed_file_advisories("production", files, changed)
        self.assertEqual(len(advisories), CHECKER.CHANGED_FILES_REPORTED)
        self.assertIn("changed production file: src/file_24.rs", advisories[0])


class TestLintSuppressions(unittest.TestCase):
    def test_rejects_direct_and_conditional_broad_allows(self) -> None:
        self.assertTrue(CHECKER.contains_permanent_lint_allow("#[allow(dead_code)]"))
        self.assertTrue(
            CHECKER.contains_permanent_lint_allow(
                '#![cfg_attr(not(feature = "trace"), allow(dead_code, unused_imports))]'
            )
        )

    def test_accepts_reasoned_expectations_and_unrelated_allows(self) -> None:
        self.assertFalse(
            CHECKER.contains_permanent_lint_allow(
                '#[expect(dead_code, reason = "feature-disabled seam")]'
            )
        )
        self.assertFalse(CHECKER.contains_permanent_lint_allow("#[allow(non_snake_case)]"))


class TestCurrentOnlyMetadataSchema(unittest.TestCase):
    def test_rejects_rust_side_schema_repair_patterns(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/store.rs": """
fn reset_schema(&mut self) {}
fn open() {
    self.reset_schema()?;
    tx.execute_batch("DROP TABLE old");
    tx.execute_batch("ALTER TABLE files ADD COLUMN old INTEGER");
}
""",
            }
        )

        self.assertGreaterEqual(len(errors), 4)
        self.assertTrue(any("reset helper" in error for error in errors))
        self.assertTrue(any("ALTER TABLE" in error for error in errors))

    def test_rejects_retired_recursive_schema_field(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/schema.sql": """
CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    recursive INTEGER NOT NULL DEFAULT 0
);
""",
            }
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("shared_directory_roots.recursive", errors[0])

    def test_accepts_current_schema_open_path(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/store.rs": """
fn ensure_schema(&mut self) -> Result<()> {
    ensure!(stored_version == SCHEMA_VERSION, "not current");
    Ok(())
}
""",
                "crates/emulebb-metadata/src/schema.sql": """
CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL
);
""",
            }
        )

        self.assertEqual(errors, [])


class TestActionPins(unittest.TestCase):
    def test_accepts_only_full_lowercase_commit_ids(self) -> None:
        self.assertTrue(CHECKER.action_ref_is_immutable("a" * 40))
        self.assertFalse(CHECKER.action_ref_is_immutable("v4"))
        self.assertFalse(CHECKER.action_ref_is_immutable("A" * 40))
        self.assertFalse(CHECKER.action_ref_is_immutable("a" * 39))


class TestOmissionRegistry(unittest.TestCase):
    def test_active_registry_rejects_fixed_entries(self) -> None:
        policy = {"protocol": {"omission_registry": "policy/rust-client-omissions.toml"}}
        omissions = {
            "omissions": [
                {
                    "id": "already-fixed",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "done",
                    "compatibility": "compatible",
                    "disposition": "fixed",
                    "owner": "core-protocol",
                    "target": "implemented",
                    "beta_blocker": False,
                }
            ]
        }

        errors = CHECKER.check_omission_registry(policy, omissions)

        self.assertTrue(any("unsupported disposition: fixed" in error for error in errors))

    def test_active_registry_rejects_contradictory_review_disposition(self) -> None:
        policy = {"protocol": {"omission_registry": "policy/rust-client-omissions.toml"}}
        omissions = {
            "omissions": [
                {
                    "id": "preview",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "drop",
                    "compatibility": "compatible",
                    "disposition": "protocol_drop_approved",
                    "review_disposition": "defer",
                    "owner": "operator",
                    "target": "beta",
                    "beta_blocker": False,
                }
            ]
        }

        errors = CHECKER.check_omission_registry(policy, omissions)

        self.assertTrue(any("contradicts disposition" in error for error in errors))

    def test_resolved_history_rejects_active_overlap(self) -> None:
        omissions = {
            "omissions": [
                {
                    "id": "same-id",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "defer",
                    "compatibility": "compatible",
                    "disposition": "protocol_defer",
                    "owner": "core-protocol",
                    "target": "post-beta",
                    "beta_blocker": False,
                }
            ]
        }
        history = {
            "resolved_omissions": [
                {
                    "id": "same-id",
                    "disposition": "fixed",
                }
            ]
        }

        errors = CHECKER.check_omission_history(omissions, history)

        self.assertTrue(any("also appears in active registry" in error for error in errors))


class TestReleaseOutputPaths(unittest.TestCase):
    def test_accepts_external_release_paths(self) -> None:
        workflow = """
EMULEBB_WORKSPACE_ROOT: ${{ github.workspace }}
EMULEBB_WORKSPACE_OUTPUT_ROOT: ${{ runner.temp }}/emulebb-rust-out
CARGO_TARGET_DIR: ${{ runner.temp }}/emulebb-rust-out/builds/rust/target
RELEASE_OUT_DIR: ${{ runner.temp }}/emulebb-rust-dist
--target-dir "$CARGO_TARGET_DIR/release"
--webui-dir "$EMULEBB_WORKSPACE_OUTPUT_ROOT/tools/emulebb-rust/bin/webui"
--out "$RELEASE_OUT_DIR"
"""
        self.assertEqual(CHECKER.check_release_output_paths(workflow), [])

    def test_reports_in_checkout_release_paths(self) -> None:
        errors = CHECKER.check_release_output_paths(
            "python tools/package_release_zip.py --target-dir target/release --out dist"
        )
        self.assertEqual(len(errors), 6)


if __name__ == "__main__":
    unittest.main()
