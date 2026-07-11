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


class TestReleaseOutputPaths(unittest.TestCase):
    def test_accepts_external_release_paths(self) -> None:
        workflow = """
CARGO_TARGET_DIR: ${{ runner.temp }}/emulebb-rust-target
RELEASE_OUT_DIR: ${{ runner.temp }}/emulebb-rust-dist
--target-dir "$CARGO_TARGET_DIR/release"
--out "$RELEASE_OUT_DIR"
"""
        self.assertEqual(CHECKER.check_release_output_paths(workflow), [])

    def test_reports_in_checkout_release_paths(self) -> None:
        errors = CHECKER.check_release_output_paths(
            "python tools/package_release_zip.py --target-dir target/release --out dist"
        )
        self.assertEqual(len(errors), 4)


if __name__ == "__main__":
    unittest.main()
