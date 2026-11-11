from __future__ import annotations

import importlib.util
import json
import subprocess
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


class TestScheduledWorkflowSource(unittest.TestCase):
    def metadata(self, *, scheduled=True, qualification_error=None, force=False, publish=True, tags="", releases=()):
        source, previous = "a" * 40, "b" * 40

        def git(*arguments, **_kwargs):
            if arguments == ("rev-parse", "HEAD"):
                return source
            if arguments[0] == "tag":
                return tags
            if arguments == ("rev-parse", "rust-v0.1.0-beta.2^{commit}"):
                return previous
            self.fail(f"Unexpected metadata Git read: {arguments}")

        with (
            mock.patch.object(NIGHTLY, "git_output", side_effect=git),
            mock.patch.object(NIGHTLY, "workspace_version_at_ref", return_value="0.1.0-beta.2") as version,
            mock.patch.object(NIGHTLY, "github_releases", return_value=list(releases)),
            mock.patch.object(NIGHTLY, "metadata_schema_version_at_ref", return_value=25),
            mock.patch.object(NIGHTLY, "run", return_value=subprocess.CompletedProcess([], 0, "")),
            mock.patch.object(NIGHTLY, "verify_source_checks", side_effect=qualification_error) as verify,
        ):
            values = NIGHTLY.metadata(date="20261109", scheduled=scheduled, force=force, publish=publish)
        return values, verify, version

    def test_scheduled_nightly_qualifies_its_own_checkout(self):
        values, verify, version = self.metadata()
        self.assertEqual(values["sha"], "a" * 40)
        self.assertEqual(values["should_build"], "true")
        self.assertEqual(values["skip_reason"], "")
        verify.assert_called_once_with(
            "emulebb/emulebb-rust", "a" * 40, platform_profile="full", deadline=mock.ANY,
        )
        version.assert_called_once_with("a" * 40)

    def test_unqualified_checkout_skips_without_selecting_an_older_source(self):
        reason = "Required CI latest workflow attempt must complete successfully"
        values, verify, version = self.metadata(qualification_error=NIGHTLY.SourceChecksNotReady(reason))
        self.assertEqual(values["sha"], "a" * 40)
        self.assertEqual(values["should_build"], "false")
        self.assertEqual(values["skip_reason"], reason)
        verify.assert_called_once_with(
            "emulebb/emulebb-rust", "a" * 40, platform_profile="full", deadline=mock.ANY,
        )
        version.assert_called_once_with("a" * 40)

    def test_source_inventory_and_transport_errors_are_not_normal_skips(self):
        for error in (RuntimeError("Invalid Required CI workflow identity"),
                      json.JSONDecodeError("invalid inventory", "", 0),
                      subprocess.CalledProcessError(1, ["gh", "api"])):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    self.metadata(qualification_error=error)

    def test_manual_nonpublishing_force_does_not_require_ready_source_metadata(self):
        values, verify, _ = self.metadata(
            scheduled=False, force=True, publish=False,
            qualification_error=AssertionError("manual metadata must not query source qualification"),
        )
        self.assertEqual(values["sha"], "a" * 40)
        self.assertEqual(values["should_build"], "true")
        verify.assert_not_called()

    def test_manual_publication_cannot_republish_an_existing_tag(self):
        with self.assertRaisesRegex(RuntimeError, "refusing to republish existing nightly version"):
            self.metadata(scheduled=False, force=True, tags="rust-v0.1.0-beta.2.nightly.20261109.gaaaaaaaa")


class TestNightlyNotes(unittest.TestCase):
    def test_git_reads_use_the_selected_source_directory(self) -> None:
        candidate = Path("candidate-history")
        with mock.patch.object(NIGHTLY, "run") as run:
            run.return_value.stdout = "  source-value\n"
            self.assertEqual(NIGHTLY.git_output("rev-parse", "HEAD", root=candidate), "source-value")
        run.assert_called_once_with(("git", "rev-parse", "HEAD"), cwd=candidate)

    def test_notes_command_reads_all_history_and_schemas_from_candidate(self) -> None:
        candidate = Path("candidate-history")
        output = Path("notes-output.md")
        source_sha = "a" * 40
        responses = (
            source_sha,
            "b" * 40 + "\tfix: preserve verified data",
            "pub const SCHEMA_VERSION: i64 = 25;",
            "pub const SCHEMA_VERSION: i64 = 24;",
        )
        with (
            mock.patch.object(NIGHTLY, "git_output", side_effect=responses) as git,
            mock.patch.object(Path, "mkdir"),
            mock.patch.object(Path, "write_text") as write,
        ):
            self.assertEqual(NIGHTLY.main([
                "notes", "--version", "0.1.0-beta.2.nightly.20261108.gaaaaaaaa",
                "--previous-ref", "rust-v0.1.0-beta.2", "--source-root", str(candidate),
                "--output", str(output),
            ]), 0)
        self.assertEqual(git.call_args_list, [
            mock.call("rev-parse", "HEAD", root=candidate),
            mock.call("log", "--reverse", "--format=%H%x09%s", f"rust-v0.1.0-beta.2..{source_sha}", root=candidate),
            mock.call("show", f"{source_sha}:{NIGHTLY.METADATA_SCHEMA_PATH}", root=candidate),
            mock.call("show", f"rust-v0.1.0-beta.2:{NIGHTLY.METADATA_SCHEMA_PATH}", root=candidate),
        ])
        rendered = write.call_args.args[0]
        self.assertIn("changed from `24`", rendered)
        self.assertIn(source_sha, rendered)
        self.assertIn("Preserve verified data", rendered)

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
        self.assertIn("Automated nightly beta from `main`", rendered)
        self.assertIn("not a formal beta release", rendered)
        self.assertIn("Metadata schema: `25` (changed from `24`", rendered)
        self.assertIn("Profile schema status: incompatible", rendered)
        self.assertIn("does not migrate, repair, or reset", rendered)
        self.assertIn("compare/rust-v0.1.0-beta.2...", rendered)
        self.assertNotIn("experimental profile", rendered)

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
        self.assertIn("testing this nightly beta", rendered)
        self.assertNotIn("incompatible with the previous build", rendered)
        self.assertNotIn("experimental profile", rendered)

    def test_android_compile_only_developer_scope_is_explicit_only_for_nightly(self) -> None:
        for channel in ("nightly", "candidate", "beta"):
            version = "0.1.0-beta.2" + (".nightly.20261003.g9e43ea5e" if channel == "nightly" else "")
            with self.subTest(channel=channel):
                rendered = NIGHTLY.render_notes(
                    version=version, channel=channel, previous_ref="rust-v0.1.0-beta.1",
                    source_sha="9" * 40, schema_version=25, previous_schema_version=25,
                    changes=(),
                )
                if channel == "nightly":
                    for fragment in ("## Android developer archives", "`arm64-v8a` and `x86_64`",
                                     "experimental CLI developer builds, not APKs",
                                     "Compilation and ELF checks do not qualify Android device runtime, transfers or VPN behavior",
                                     "Completed-file delivery and route discovery have known Android limitations",
                                     "`emulebb-rust/README.txt`"):
                        self.assertIn(fragment, rendered)
                else:
                    self.assertNotIn("Android developer archives", rendered)
                    self.assertNotIn("experimental CLI", rendered)


class TestReleaseDocuments(unittest.TestCase):
    def test_default_baseline_ignores_nightlies_and_resolves_a_tag_only_once(self):
        source, baseline = "a" * 40, "b" * 40
        root = Path("candidate-history")
        responses = ["rust-v0.1.0-beta.9.nightly.20261108.gaaaaaaaa\nrust-v0.1.0-beta.2\nrust-v0.1.0-beta.1",
                     source, baseline, ""]
        with mock.patch.object(NIGHTLY, "git_output", side_effect=responses) as git:
            self.assertEqual(NIGHTLY.release_notes_baseline(source, "", root=root),
                             ("rust-v0.1.0-beta.1", baseline))
        resolves = [call for call in git.call_args_list if call.args[:2] == ("rev-parse", "--verify")]
        self.assertEqual(len(resolves), 2)
        self.assertEqual(git.call_args_list[-1], mock.call("merge-base", "--is-ancestor", baseline, source, root=root))

    def test_no_formal_ancestor_fails_instead_of_inventing_release_notes(self):
        with mock.patch.object(NIGHTLY, "git_output", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "earlier promoted beta ancestor"):
                NIGHTLY.release_notes_baseline("a" * 40, "", root=Path("candidate"))

    def test_non_ancestor_baseline_is_rejected(self):
        failure = subprocess.CalledProcessError(1, ["git", "merge-base"])
        with mock.patch.object(NIGHTLY, "git_output", side_effect=["b" * 40, failure]):
            with self.assertRaisesRegex(RuntimeError, "must be an ancestor"):
                NIGHTLY.release_notes_baseline("a" * 40, "rust-v0.1.0-beta.2", root=Path("candidate"))

    def test_source_mismatch_fails_before_creating_any_documents(self):
        with mock.patch.object(NIGHTLY, "git_output", return_value="b" * 40), mock.patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                NIGHTLY.write_release_documents(version="0.1.0-beta.2", channel="candidate", source_sha="a" * 40,
                                                source_root=Path("candidate"), previous_ref="", output_dir=Path("documents"))
            mkdir.assert_not_called()

    def test_each_channel_has_truthful_documents_from_immutable_candidate_objects(self):
        source, baseline = "a" * 40, "b" * 40
        candidate = Path("candidate-history")
        for channel in ("candidate", "beta", "nightly"):
            with self.subTest(channel=channel), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "documents"
                version = "0.1.0-beta.2" + (".nightly.20261109.gaaaaaaaa" if channel == "nightly" else "")
                responses = [source, "c" * 40 + "\tfix: preserve verified data",
                             "pub const SCHEMA_VERSION: i64 = 25;", "pub const SCHEMA_VERSION: i64 = 24;"]
                with (mock.patch.object(NIGHTLY, "release_notes_baseline", return_value=("rust-v0.1.0-beta.1", baseline)),
                      mock.patch.object(NIGHTLY, "git_output", side_effect=responses) as git):
                    NIGHTLY.write_release_documents(version=version, channel=channel, source_sha=source,
                                                    source_root=candidate, previous_ref="rust-v0.1.0-beta.1", output_dir=output)
                notes = (output / f"RELEASE-{version}-NOTES.md").read_text()
                self.assertIn("Preserve verified data", notes)
                self.assertIn(f"compare/{baseline}...{source}", notes)
                self.assertIn("does not migrate, repair, or reset", notes)
                self.assertEqual(len(list(output.iterdir())), 1 if channel == "nightly" else 2)
                if channel == "candidate":
                    self.assertIn("Validation candidate", notes)
                    self.assertNotIn("from `main`", notes)
                self.assertTrue(all(call.kwargs.get("root") == candidate for call in git.call_args_list))
                self.assertEqual(git.call_args_list[1].args[-1], f"{baseline}..{source}")
                self.assertEqual(git.call_args_list[-1].args[-1], f"{baseline}:{NIGHTLY.METADATA_SCHEMA_PATH}")

    def test_nightly_cannot_silently_pick_a_different_baseline(self):
        with mock.patch.object(NIGHTLY, "git_output", return_value="a" * 40):
            with self.assertRaisesRegex(RuntimeError, "selected previous release ref"):
                NIGHTLY.write_release_documents(version="0.1.0-beta.2.nightly.20261109.gaaaaaaaa", channel="nightly",
                                                source_sha="a" * 40, source_root=Path("candidate"), previous_ref="",
                                                output_dir=Path("documents"))


class TestNightlyGatesAndRetention(unittest.TestCase):
    def test_required_checks_use_stable_aggregate_names(self) -> None:
        self.assertEqual(
            NIGHTLY.REQUIRED_SOURCE_CHECKS,
            ("Required CI", "Required CodeQL"),
        )

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


class TestSourceWorkflowEligibility(unittest.TestCase):
    def setUp(self) -> None:
        self.sha = "a" * 40
        self.ci = {"id": 20, "run_number": 8, "run_attempt": 2, "head_sha": self.sha, "path": ".github/workflows/ci.yml",
                   "status": "completed", "conclusion": "success"}
        self.codeql = {**self.ci, "id": 30, "run_number": 15, "run_attempt": 1, "path": ".github/workflows/codeql.yml"}
        self.optional = {**self.ci, "id": 40, "run_number": 4, "run_attempt": 1, "path": ".github/workflows/optional-platforms.yml"}
        self.runs = {"ci.yml": [{**self.ci, "id": 10, "run_number": 7, "conclusion": "failure"}, self.ci],
                     "codeql.yml": [self.codeql], "optional-platforms.yml": [self.optional]}
        self.jobs = {"ci.yml": [{"id": 200, "run_id": 20, "run_attempt": 2, "head_sha": self.sha,
                                 "name": "Required CI", "status": "completed", "conclusion": "success"}],
                     "codeql.yml": [{"id": 300, "run_id": 30, "run_attempt": 1, "head_sha": self.sha,
                                     "name": "Required CodeQL", "status": "completed", "conclusion": "success"}],
                     "optional-platforms.yml": [{"id": 400, "run_id": 40, "run_attempt": 1, "head_sha": self.sha,
                                                 "name": "Optional Platform CI", "status": "completed", "conclusion": "success"}]}
        self.calls = []
        patcher = mock.patch.object(NIGHTLY, "run", side_effect=self.respond)
        patcher.start()
        self.addCleanup(patcher.stop)

    def respond(self, command, **_kwargs):
        self.calls.append(command)
        self.assertEqual(command[:4], ("gh", "api", "--paginate", "--slurp"))
        endpoint = command[-1]
        for workflow, run_id, attempt in (("ci.yml", 20, 2), ("codeql.yml", 30, 1), ("optional-platforms.yml", 40, 1)):
            if f"/workflows/{workflow}/runs?" in endpoint:
                self.assertIn(f"head_sha={self.sha}", endpoint)
                pages = [{"workflow_runs": self.runs[workflow][:1]}, {"workflow_runs": self.runs[workflow][1:]}]
                break
            if f"/runs/{run_id}/attempts/{attempt}/jobs?" in endpoint:
                pages = [{"jobs": []}, {"jobs": self.jobs[workflow]}]
                break
        else:
            self.fail(f"Unexpected eligibility request: {endpoint}")
        return subprocess.CompletedProcess(command, 0, json.dumps(pages))

    def verify(self):
        return NIGHTLY.verify_source_checks("example/project", self.sha)

    def test_latest_success_and_exact_attempt_aggregate_are_required_across_all_pages(self) -> None:
        self.runs["ci.yml"].reverse()
        self.assertEqual(self.verify(), {
            "Required CI": {"runId": 20, "runNumber": 8, "runAttempt": 2, "jobId": 200},
            "Required CodeQL": {"runId": 30, "runNumber": 15, "runAttempt": 1, "jobId": 300},
            "Optional Platform CI": {"runId": 40, "runNumber": 4, "runAttempt": 1, "jobId": 400},
        })
        self.assertEqual(len(self.calls), 6)

    def test_optional_platform_failure_blocks_full_but_not_explicit_scoped_qualification(self):
        self.runs["optional-platforms.yml"] = [{**self.optional, "conclusion": "failure"}]
        with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "Optional Platform CI latest"):
            self.verify()
        self.calls.clear()
        evidence = NIGHTLY.verify_source_checks("example/project", self.sha, platform_profile="windows-linux")
        self.assertEqual(set(evidence), {"Required CI", "Required CodeQL"})
        self.assertFalse(any("optional-platforms" in call[-1] for call in self.calls))

    def test_scoped_qualification_cannot_ignore_shared_ci_or_codeql_failure(self):
        for workflow in ("ci.yml", "codeql.yml"):
            original = self.runs[workflow]
            self.runs[workflow] = [{**original[-1], "conclusion": "failure"}]
            with self.assertRaises(NIGHTLY.SourceChecksNotReady):
                NIGHTLY.verify_source_checks("example/project", self.sha, platform_profile="windows-linux")
            self.runs[workflow] = original

    def test_full_requires_optional_aggregate_in_exact_latest_attempt(self):
        self.jobs["optional-platforms.yml"][0]["run_attempt"] = 2
        with self.assertRaisesRegex(RuntimeError, "exact latest"):
            self.verify()

    def test_optional_older_success_cannot_mask_new_pending_or_failed_invocation(self):
        for status, conclusion in (("in_progress", None), ("completed", "failure")):
            with self.subTest(status=status):
                self.runs["optional-platforms.yml"] = [self.optional,
                    {**self.optional, "id": 41, "run_number": 5, "status": status, "conclusion": conclusion}]
                with self.assertRaises(NIGHTLY.SourceChecksNotReady):
                    self.verify()

    def test_old_success_never_masks_new_pending_failed_cancelled_or_skipped_workflow(self) -> None:
        for status, conclusion in (("queued", None), ("in_progress", None), ("completed", "failure"),
                                   ("completed", "cancelled"), ("completed", "skipped")):
            with self.subTest(status=status, conclusion=conclusion):
                self.runs["ci.yml"] = [{**self.ci, "id": 10, "run_number": 7, "conclusion": "success"},
                                       {**self.ci, "status": status, "conclusion": conclusion}]
                with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "latest workflow attempt"):
                    self.verify()

    def test_missing_source_workflow_is_not_ready(self) -> None:
        self.runs["ci.yml"] = []
        with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "No Required CI workflow invocation"):
            self.verify()

    def test_invalid_workflow_state_is_an_error_instead_of_a_normal_skip(self) -> None:
        for change in ({"status": None}, {"status": "unknown"}, {"status": []},
                       {"conclusion": None}, {"conclusion": True}, {"conclusion": {}},
                       {"status": "queued", "conclusion": "success"}):
            with self.subTest(change=change):
                self.runs["ci.yml"] = [{**self.ci, **change}]
                with self.assertRaisesRegex(RuntimeError, "Invalid Required CI latest workflow state") as caught:
                    self.verify()
                self.assertNotIsInstance(caught.exception, NIGHTLY.SourceChecksNotReady)

    def test_rerunning_old_invocation_does_not_supersede_newer_failed_invocation(self) -> None:
        self.runs["ci.yml"] = [{**self.ci, "id": 999, "run_number": 7, "run_attempt": 99}, {**self.ci, "conclusion": "failure"}]
        with self.assertRaisesRegex(RuntimeError, "latest workflow attempt"):
            self.verify()

    def test_new_attempt_of_same_workflow_blocks_older_success_before_aggregate_starts(self) -> None:
        self.runs["ci.yml"] = [self.ci, {**self.ci, "run_attempt": 3, "status": "queued", "conclusion": None}]
        with self.assertRaisesRegex(RuntimeError, "latest workflow attempt"):
            self.verify()

    def test_inconsistent_latest_snapshot_fails_closed(self) -> None:
        self.runs["ci.yml"] = [self.ci, {**self.ci, "status": "in_progress", "conclusion": None}]
        with self.assertRaisesRegex(RuntimeError, "inconsistent"):
            self.verify()

    def test_codeql_is_required_even_when_ci_passed(self) -> None:
        self.runs["codeql.yml"] = [{**self.codeql, "conclusion": "failure"}]
        with self.assertRaisesRegex(RuntimeError, "Required CodeQL latest"):
            self.verify()

    def test_other_source_or_workflow_cannot_satisfy_gate(self) -> None:
        invalid_rows = (
            {},
            {key: value for key, value in self.ci.items() if key != "head_sha"},
            {**self.ci, "head_sha": "b" * 40},
            {**self.ci, "path": ".github/workflows/branch-check.yml"},
        )
        for row in invalid_rows:
            for inventory in ([row], [self.ci, row]):
                with self.subTest(inventory=inventory):
                    self.runs["ci.yml"] = inventory
                    with self.assertRaisesRegex(RuntimeError, "Invalid Required CI workflow identity") as caught:
                        self.verify()
                    self.assertNotIsInstance(caught.exception, NIGHTLY.SourceChecksNotReady)

    def test_invalid_source_inventory_propagates_through_scheduled_metadata(self) -> None:
        def metadata_command(command, **kwargs):
            if command[:3] == ("git", "merge-base", "--is-ancestor"):
                return subprocess.CompletedProcess(command, 0, "")
            return self.respond(command, **kwargs)

        for row in ({}, {key: value for key, value in self.ci.items() if key != "head_sha"},
                    {**self.ci, "head_sha": "b" * 40}):
            with self.subTest(row=row):
                self.runs["ci.yml"] = [row]
                with (
                    mock.patch.object(NIGHTLY, "git_output", side_effect=[self.sha, "", "b" * 40]),
                    mock.patch.object(NIGHTLY, "workspace_version_at_ref", return_value="0.1.0-beta.2"),
                    mock.patch.object(NIGHTLY, "github_releases", return_value=[]),
                    mock.patch.object(NIGHTLY, "metadata_schema_version_at_ref", return_value=25),
                    mock.patch.object(NIGHTLY, "run", side_effect=metadata_command),
                ):
                    with self.assertRaisesRegex(RuntimeError, "Invalid Required CI workflow identity") as caught:
                        NIGHTLY.metadata(date="20261109", scheduled=True, publish=True)
                    self.assertNotIsInstance(caught.exception, NIGHTLY.SourceChecksNotReady)

    def test_missing_duplicate_or_unrelated_aggregate_cannot_satisfy_gate(self) -> None:
        good = self.jobs["ci.yml"][0]
        for jobs in ([], [good, good], [{**good, "name": "another workflow aggregate"}]):
            with self.subTest(jobs=jobs):
                self.jobs["ci.yml"] = jobs
                with self.assertRaisesRegex(RuntimeError, "exactly one"):
                    self.verify()

    def test_aggregate_must_match_source_attempt_and_success(self) -> None:
        good = self.jobs["ci.yml"][0]
        for change in ({"run_id": 10}, {"run_attempt": 1}, {"run_attempt": True}, {"head_sha": "b" * 40},
                       {"id": True}, {"status": "queued"}, {"conclusion": "skipped"}, {"conclusion": "failure"}):
            with self.subTest(change=change):
                self.jobs["ci.yml"] = [{**good, **change}]
                with self.assertRaisesRegex(RuntimeError, "exact latest source workflow attempt"):
                    self.verify()

    def test_malformed_identity_cannot_fall_back_to_old_green(self) -> None:
        for change in ({"id": True}, {"id": 0}, {"run_number": True}, {"run_number": 0},
                       {"run_attempt": "2"}, {"run_attempt": 0}):
            with self.subTest(change=change):
                self.runs["ci.yml"] = [self.ci, {**self.ci, **change}]
                with self.assertRaisesRegex(RuntimeError, "identity"):
                    self.verify()

    def test_malformed_or_missing_pages_fail_closed(self) -> None:
        for pages in ({"workflow_runs": []}, [], [{"jobs": []}], [{"workflow_runs": [None]}]):
            with self.subTest(pages=pages), mock.patch.object(NIGHTLY, "run", return_value=
                    subprocess.CompletedProcess([], 0, json.dumps(pages))):
                with self.assertRaises(RuntimeError):
                    self.verify()

    def test_mutable_source_ref_is_rejected_before_api_calls(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "full lowercase source SHA"):
            NIGHTLY.verify_source_checks("example/project", "main")
        self.assertFalse(self.calls)


class TestSourceQualificationWait(unittest.TestCase):
    def test_pending_then_success_rechecks_the_same_source_without_real_sleep(self):
        expected = {"Required CI": {"runId": 20}}
        with mock.patch.object(NIGHTLY, "verify_source_checks", side_effect=[
            NIGHTLY.SourceChecksPending("Optional Platform CI pending"), expected,
        ]) as verify, mock.patch.object(NIGHTLY.time, "monotonic", side_effect=[0, 1, 2]), \
                mock.patch.object(NIGHTLY.time, "sleep") as sleep:
            self.assertEqual(NIGHTLY.wait_for_source_checks("example/project", "a" * 40), expected)
        self.assertEqual(verify.call_args_list, [mock.call(
            "example/project", "a" * 40, platform_profile="full", deadline=480,
        )] * 2)
        sleep.assert_called_once_with(30)

    def test_pending_then_terminal_failure_does_not_wait_or_choose_an_older_success(self):
        with mock.patch.object(NIGHTLY, "verify_source_checks", side_effect=[
            NIGHTLY.SourceChecksPending("pending"), NIGHTLY.SourceChecksNotReady("new attempt failed"),
        ]), mock.patch.object(NIGHTLY.time, "monotonic", side_effect=[0, 1]), \
                mock.patch.object(NIGHTLY.time, "sleep") as sleep:
            with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "new attempt failed"):
                NIGHTLY.wait_for_source_checks("example/project", "a" * 40)
        sleep.assert_called_once_with(30)

    def test_pending_timeout_is_bounded_and_explicit(self):
        with mock.patch.object(NIGHTLY, "verify_source_checks", side_effect=NIGHTLY.SourceChecksPending("pending")), \
                mock.patch.object(NIGHTLY.time, "monotonic", side_effect=[0, 481]), \
                mock.patch.object(NIGHTLY.time, "sleep") as sleep:
            with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "timed out"):
                NIGHTLY.wait_for_source_checks("example/project", "a" * 40)
        sleep.assert_not_called()

    def test_inventory_errors_do_not_become_pending_retries(self):
        with mock.patch.object(NIGHTLY, "verify_source_checks", side_effect=RuntimeError("invalid inventory")), \
                mock.patch.object(NIGHTLY.time, "sleep") as sleep:
            with self.assertRaisesRegex(RuntimeError, "invalid inventory"):
                NIGHTLY.wait_for_source_checks("example/project", "a" * 40)
        sleep.assert_not_called()

    def test_actions_request_uses_only_the_remaining_budget(self):
        response = subprocess.CompletedProcess([], 0, stdout='[{"workflow_runs": []}]')
        with mock.patch.object(NIGHTLY.time, "monotonic", return_value=8), \
                mock.patch.object(NIGHTLY, "run", return_value=response) as run:
            self.assertEqual(NIGHTLY._action_rows("synthetic", "workflow_runs", deadline=10), [])
        self.assertEqual(run.call_args.kwargs["timeout"], 2)

    def test_actions_timeout_is_terminal_for_this_qualification(self):
        with mock.patch.object(NIGHTLY, "run", side_effect=subprocess.TimeoutExpired("gh", 120)):
            with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "Actions request timed out"):
                NIGHTLY._action_rows("synthetic", "workflow_runs")

    def test_success_after_the_deadline_cannot_qualify_source(self):
        with mock.patch.object(NIGHTLY, "verify_source_checks", return_value={}), \
                mock.patch.object(NIGHTLY.time, "monotonic", side_effect=[0, 481]):
            with self.assertRaisesRegex(NIGHTLY.SourceChecksNotReady, "timed out after"):
                NIGHTLY.wait_for_source_checks("example/project", "a" * 40)


if __name__ == "__main__":
    unittest.main()
