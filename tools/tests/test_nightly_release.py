from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "nightly_release.py"
SPEC = importlib.util.spec_from_file_location("nightly_release", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
NIGHTLY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = NIGHTLY
SPEC.loader.exec_module(NIGHTLY)


class TestNightlyMetadata(unittest.TestCase):
    def test_metadata_schema_version_requires_one_exact_declaration(self) -> None:
        self.assertEqual(
            NIGHTLY.metadata_schema_version("pub const SCHEMA_VERSION: i64 = 25;\n"),
            25,
        )
        with self.assertRaisesRegex(RuntimeError, "exactly one"):
            NIGHTLY.metadata_schema_version("const SCHEMA_VERSION: u32 = 25;\n")

    def test_version_is_derived_from_promoted_beta(self) -> None:
        self.assertEqual(
            NIGHTLY.nightly_version("0.1.0-beta.2", "20261003", "9E43EA5E"),
            "0.1.0-beta.2.nightly.20261003.g9e43ea5e",
        )

    def test_version_rejects_unprefixed_or_short_hash(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid source commit"):
            NIGHTLY.nightly_version("0.1.0-beta.2", "20261003", "123")

    def test_latest_tag_is_scoped_to_beta_and_uses_newest_first_order(self) -> None:
        tags = [
            "rust-v0.1.0-beta.2.nightly.20261003.g2222222",
            "rust-v0.1.0-beta.1.nightly.20261005.gbbbbbbb",
            "rust-v0.1.0-beta.2.nightly.20261002.g1111111",
            "rust-v0.1.0-beta.2.nightly.20261003.g9999999",
            "rust-v0.1.0-beta.2",
            "rust-v0.1.0-beta.2.nightly.bad.g3333333",
        ]
        self.assertEqual(
            NIGHTLY.latest_nightly_tag("0.1.0-beta.2", tags),
            "rust-v0.1.0-beta.2.nightly.20261003.g2222222",
        )

    def test_github_output_contains_only_scalars(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "github-output"
            NIGHTLY.write_github_output(output, {"version": "0.1.0", "should_build": "true"})
            self.assertEqual(output.read_text(encoding="utf-8"), "version=0.1.0\nshould_build=true\n")

    def test_successful_ci_shas_accept_only_completed_main_pushes(self) -> None:
        valid_sha = "1" * 40
        payload = {
            "workflow_runs": [
                {
                    "head_sha": valid_sha,
                    "head_branch": "main",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                },
                {
                    "head_sha": "2" * 40,
                    "head_branch": "main",
                    "event": "push",
                    "status": "in_progress",
                    "conclusion": None,
                },
                {
                    "head_sha": "3" * 40,
                    "head_branch": "topic",
                    "event": "push",
                    "status": "completed",
                    "conclusion": "success",
                },
            ]
        }
        self.assertEqual(NIGHTLY.successful_ci_shas(payload, "main"), [valid_sha])

    def test_latest_green_main_skips_newer_commit_outside_checkout_lineage(self) -> None:
        newer_sha = "1" * 40
        selected_sha = "2" * 40
        response = mock.Mock(
            stdout=(
                '{"workflow_runs":['
                f'{{"head_sha":"{newer_sha}","head_branch":"main","event":"push",'
                '"status":"completed","conclusion":"success"},'
                f'{{"head_sha":"{selected_sha}","head_branch":"main","event":"push",'
                '"status":"completed","conclusion":"success"}'
                "]}"
            )
        )
        with (
            mock.patch.object(NIGHTLY, "run", return_value=response),
            mock.patch.object(NIGHTLY, "is_ancestor", side_effect=[False, True]),
        ):
            self.assertEqual(NIGHTLY.latest_green_main_sha("emulebb/emulebb-rust"), selected_sha)

    def test_published_nightly_is_scoped_to_beta_and_date(self) -> None:
        releases = [
            {
                "tagName": "rust-v0.1.0-beta.2.nightly.20261005.g1111111",
                "publishedAt": "2026-10-05T09:00:00Z",
                "isPrerelease": True,
                "isDraft": False,
            },
            {
                "tagName": "rust-v0.1.0-beta.1.nightly.20261006.g2222222",
                "publishedAt": "2026-10-06T09:00:00Z",
                "isPrerelease": True,
                "isDraft": False,
            },
            {
                "tagName": "rust-v0.1.0-beta.2.nightly.20261006.g3333333",
                "publishedAt": "2026-10-06T09:00:00Z",
                "isPrerelease": True,
                "isDraft": True,
            },
        ]
        self.assertTrue(
            NIGHTLY.published_nightly_for_date("0.1.0-beta.2", "20261005", releases)
        )
        self.assertFalse(
            NIGHTLY.published_nightly_for_date("0.1.0-beta.2", "20261006", releases)
        )

    def test_scheduled_retry_stops_after_one_published_nightly_per_date(self) -> None:
        self.assertFalse(
            NIGHTLY.should_build_nightly(
                force=False,
                publish=True,
                scheduled=True,
                tag_exists=False,
                published_for_date=True,
                source_changed=True,
                version="0.1.0-beta.2.nightly.20261006.g1111111",
            )
        )

    def test_manual_force_can_rebuild_candidate_but_not_republish_version(self) -> None:
        arguments = {
            "force": True,
            "scheduled": False,
            "tag_exists": True,
            "published_for_date": True,
            "source_changed": False,
            "version": "0.1.0-beta.2.nightly.20261006.g1111111",
        }
        self.assertTrue(NIGHTLY.should_build_nightly(publish=False, **arguments))
        with self.assertRaisesRegex(RuntimeError, "refusing to republish"):
            NIGHTLY.should_build_nightly(publish=True, **arguments)


class TestNightlyNotes(unittest.TestCase):
    def test_commit_subjects_are_grouped_and_linked(self) -> None:
        log = "\n".join(
            (
                "1" * 40 + "\tRUST-FEAT-037 feat: add PCP-first NAT traversal",
                "2" * 40 + "\tRUST-BUG-101 fix: preserve delayed Kad results",
                "3" * 40 + "\tINBOX: coalesce shared-directory watcher updates",
                "4" * 40 + "\tci: retain nightly packages",
            )
        )
        changes = NIGHTLY.changes_from_log(log)
        rendered = NIGHTLY.render_notes(
            version="0.1.0-beta.2.nightly.20261003.g9e43ea5e",
            previous_ref="rust-v0.1.0-beta.2",
            source_sha="9" * 40,
            schema_version=25,
            previous_schema_version=24,
            changes=changes,
        )
        self.assertIn("## Added", rendered)
        self.assertIn("RUST-FEAT-037: Add PCP-first NAT traversal.", rendered)
        self.assertIn("## Fixed", rendered)
        self.assertIn("## Changed", rendered)
        self.assertIn("## Engineering", rendered)
        self.assertIn("Metadata schema: `25` (changed from `24`", rendered)
        self.assertIn("Profile schema status: incompatible", rendered)
        self.assertIn("does not migrate, repair, or reset", rendered)
        self.assertIn("compare/rust-v0.1.0-beta.2...", rendered)

    def test_unchanged_schema_is_explicit(self) -> None:
        rendered = NIGHTLY.render_notes(
            version="0.1.0-beta.2.nightly.20261003.g9e43ea5e",
            previous_ref="rust-v0.1.0-beta.2",
            source_sha="9" * 40,
            schema_version=25,
            previous_schema_version=25,
            changes=(),
        )

        self.assertIn("Metadata schema: `25` (unchanged", rendered)
        self.assertIn("Profile schema status: unchanged", rendered)
        self.assertNotIn("incompatible with the previous build", rendered)


class TestNightlyGatesAndRetention(unittest.TestCase):
    def test_required_checks_include_workflow_lint(self) -> None:
        self.assertIn("GitHub Actions workflow lint", NIGHTLY.REQUIRED_CI_CHECKS)

    def test_required_linux_check_uses_pinned_runner_name(self) -> None:
        self.assertIn("build+test (ubuntu-24.04)", NIGHTLY.REQUIRED_CI_CHECKS)
        self.assertNotIn("build+test (ubuntu-latest)", NIGHTLY.REQUIRED_CI_CHECKS)

    def test_required_checks_accept_one_success_per_name(self) -> None:
        check_runs = [
            {"name": name, "status": "completed", "conclusion": "success"}
            for name in NIGHTLY.REQUIRED_CI_CHECKS
        ]
        check_runs.append({"name": NIGHTLY.REQUIRED_CI_CHECKS[0], "status": "completed", "conclusion": "skipped"})
        self.assertEqual(NIGHTLY.successful_required_checks({"check_runs": check_runs}), ())

    def test_required_checks_report_missing_or_failed_names(self) -> None:
        payload = {
            "check_runs": [
                {"name": NIGHTLY.REQUIRED_CI_CHECKS[0], "status": "completed", "conclusion": "failure"}
            ]
        }
        self.assertEqual(NIGHTLY.successful_required_checks(payload), NIGHTLY.REQUIRED_CI_CHECKS)

    def test_pruning_never_selects_formal_or_non_prerelease_tags(self) -> None:
        releases = [
            {
                "tagName": f"rust-v0.1.0-beta.2.nightly.202610{day:02d}.g{day:07x}",
                "createdAt": f"2026-10-{day:02d}T02:17:00Z",
                "isPrerelease": True,
            }
            for day in range(1, 5)
        ]
        releases.extend(
            (
                {"tagName": "rust-v0.1.0-beta.2", "createdAt": "2026-10-05T00:00:00Z", "isPrerelease": True},
                {
                    "tagName": "rust-v0.1.0-beta.2.nightly.20261006.gabcdef0",
                    "createdAt": "2026-10-06T00:00:00Z",
                    "isPrerelease": False,
                },
            )
        )
        self.assertEqual(
            NIGHTLY.nightly_tags_to_prune(releases, keep=2),
            [
                "rust-v0.1.0-beta.2.nightly.20261002.g0000002",
                "rust-v0.1.0-beta.2.nightly.20261001.g0000001",
            ],
        )


if __name__ == "__main__":
    unittest.main()
