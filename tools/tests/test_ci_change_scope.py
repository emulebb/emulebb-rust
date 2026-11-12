"""Exercise trusted classification against real immutable Git objects and events."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tools/ci_change_scope.py"
SPEC = importlib.util.spec_from_file_location("ci_change_scope", SOURCE)
SCOPE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCOPE)
REPOSITORY = "example/project"


class TestChangeScope(unittest.TestCase):
    def setUp(self):
        output = Path(os.environ["EMULEBB_WORKSPACE_OUTPUT_ROOT"]) / "cache" / "tmp"
        output.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="ci-scope-test-", dir=output)
        self.addCleanup(self.temporary.cleanup)
        self.control = Path(self.temporary.name)
        self.repo = self.control / "repo"
        self.repo.mkdir()
        self.git("init", "-b", "main")
        self.git("config", "user.name", "CI Test")
        self.git("config", "user.email", "ci-test@example.invalid")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "core.filemode", "true")
        self.git("remote", "add", "origin", "https://github.com/example/project.git")
        self.write("tools/ci_change_scope.py", SOURCE.read_bytes())
        self.write("README.md", b"# Example\n")
        self.policy = '[product]\nphase_gate = "Client first"\nnumber = 1\nflag = true\n'
        self.write("policy/rust-client.toml", self.policy)
        self.base = self.commit()
        self.trusted = self.control / "trusted.py"
        self.trusted.write_bytes(SOURCE.read_bytes())

    def git(self, *arguments):
        return subprocess.run(["git", "-c", "core.hooksPath=", "-C", str(self.repo), *arguments],
                              check=True, capture_output=True, timeout=15).stdout.decode().strip()

    def write(self, path, content):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode() if isinstance(content, str) else content)

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--allow-empty", "-m", "Synthetic scope fixture")
        return self.git("rev-parse", "HEAD")

    def event(self, head=None):
        return {"repository": {"full_name": REPOSITORY}, "before": self.base,
                "after": head or self.git("rev-parse", "HEAD"), "ref": "refs/heads/main"}

    def classify(self, event=None, name="push", base=None, tested=None, trusted=None):
        return SCOPE.classify(self.repo, event or self.event(), name, REPOSITORY,
                              tested or self.git("rev-parse", "HEAD"), base or self.base,
                              trusted or self.trusted)

    def test_readme_change_has_bound_docs_receipt(self):
        self.write("README.md", "# Updated example\n")
        tested = self.commit()
        result = self.classify()
        self.assertEqual((result["scope"], result["docsValidated"]), ("docs", True))
        self.assertEqual(result["baseSha"], self.base)
        self.assertEqual(result["testedSha"], tested)
        self.assertEqual(result["classifierBlob"], self.git("rev-parse", self.base + ":tools/ci_change_scope.py"))

    def test_full_push_range_catches_earlier_code_before_last_docs_commit(self):
        self.write("Cargo.toml", "[workspace]\n")
        self.write("src/example.rs", "fn example() {}\n")
        self.commit()
        self.write("README.md", "# Last commit is documentation\n")
        self.commit()
        receipt = self.classify()
        self.assertEqual(receipt["scope"], "full")
        self.assertEqual([change["path"] for change in receipt["changes"]],
                         ["Cargo.toml", "README.md", "src/example.rs"])

    def test_semantic_phase_gate_preserves_all_other_types_and_keys(self):
        self.assertTrue(SCOPE.phase_gate_only(self.policy, self.policy.replace("Client first", "Client then Indexer")))
        for changed in (self.policy.replace("number = 1", "number = true"),
                        self.policy.replace("number = 1", "number = 1.0"),
                        self.policy.replace("flag = true", "flag = 1"),
                        self.policy.replace("number = 1", "number = 2"),
                        self.policy + "extra = 1\n", self.policy.replace("flag = true\n", ""),
                        self.policy.replace('phase_gate = "Client first"', 'phase_gate = ""'),
                        self.policy.replace('phase_gate = "Client first"', "phase_gate = 1"),
                        self.policy.replace('phase_gate = "Client first"\n', "")):
            with self.subTest(changed=changed):
                self.assertFalse(SCOPE.phase_gate_only(self.policy, changed))
        self.assertFalse(SCOPE.exact_equal({"nested": [1]}, {"nested": [True]}))
        self.assertFalse(SCOPE.exact_equal({"nested": [1]}, {"nested": [1.0]}))

    def test_multiline_phase_gate_and_formatting_are_semantic(self):
        changed = self.policy.replace('"Client first"', "'''Client\nthen Indexer'''")
        self.write("policy/rust-client.toml", changed)
        self.commit()
        self.assertEqual(self.classify()["scope"], "docs")

    def test_malformed_toml_is_full(self):
        self.write("policy/rust-client.toml", self.policy + "flag = false\n")
        self.commit()
        self.assertEqual(self.classify()["scope"], "full")

    def test_unknown_packaged_assets_and_templates_are_full(self):
        for path in ("docs/README.md", "packaging/example.md", ".github/ISSUE_TEMPLATE/example.md",
                     ".github/workflows/example.yml", "tools/ci_change_scope.py", "Cargo.lock"):
            with self.subTest(path=path):
                self.git("reset", "--hard", self.base)
                self.write(path, "Changed fixture\n")
                self.commit()
                self.assertEqual(self.classify()["scope"], "full")

    def test_readme_binary_invalid_utf8_and_control_text_are_full(self):
        for value in (b"binary\0payload", b"invalid\xff\n", b"bad\x01\n", b"CRLF\r\n"):
            with self.subTest(value=value):
                self.git("reset", "--hard", self.base)
                self.write("README.md", value)
                self.commit()
                self.assertEqual(self.classify()["scope"], "full")

    def test_readme_rename_deletion_and_modes_are_full(self):
        self.git("mv", "README.md", "OTHER.md")
        self.commit()
        self.assertEqual(self.classify()["scope"], "full")
        self.git("reset", "--hard", self.base)
        self.git("rm", "README.md")
        self.commit()
        self.assertEqual(self.classify()["scope"], "full")
        for mode in ("100755", "120000", "160000"):
            with self.subTest(mode=mode):
                self.git("reset", "--hard", self.base)
                oid = self.base if mode == "160000" else self.git("rev-parse", "HEAD:README.md")
                self.git("update-index", "--cacheinfo", f"{mode},{oid},README.md")
                self.git("commit", "-m", "Synthetic mode fixture")
                self.assertEqual(self.classify()["scope"], "full")

    def test_push_event_source_origin_and_checkout_mismatches_are_full(self):
        self.write("README.md", "# Updated\n")
        head = self.commit()
        for key, value in (("before", "0" * 40), ("after", self.base), ("ref", "refs/heads/other"),
                           ("repository", {"full_name": "other/project"}), ("deleted", True)):
            event = self.event(head)
            event[key] = value
            with self.subTest(key=key):
                self.assertEqual(self.classify(event)["scope"], "full")
        self.assertEqual(self.classify(tested=self.base)["scope"], "full")
        self.assertEqual(self.classify(base="0" * 40)["scope"], "full")
        self.assertEqual(self.classify(base="f" * 40)["scope"], "full")
        self.git("remote", "set-url", "origin", "https://github.com/other/project.git")
        self.assertEqual(self.classify()["scope"], "full")

    def test_nonancestor_push_is_full(self):
        self.write("README.md", "# One tip\n")
        before = self.commit()
        self.git("reset", "--hard", self.base)
        self.write("README.md", "# Other tip\n")
        self.commit()
        event = self.event()
        event["before"] = before
        self.assertEqual(self.classify(event, base=before)["reason"], "nonancestor-push-base")

    def test_pull_request_requires_actual_ordered_two_parent_merge(self):
        self.git("checkout", "-b", "worker")
        self.write("README.md", "# PR docs\n")
        head = self.commit()
        self.git("checkout", "main")
        self.git("merge", "--no-ff", "worker", "-m", "Synthetic tested merge")
        event = {"repository": {"full_name": REPOSITORY}, "pull_request": {
            "base": {"sha": self.base, "ref": "main", "repo": {"full_name": REPOSITORY}},
            "head": {"sha": head}}}
        self.assertEqual(self.classify(event, "pull_request")["scope"], "docs")
        self.assertEqual(self.classify(event, "pull_request")["headSha"], head)
        for path, value in (("sha", head), ("ref", "other"), ("repo", {"full_name": "other/project"})):
            changed = json.loads(json.dumps(event))
            changed["pull_request"]["base"][path] = value
            self.assertEqual(self.classify(changed, "pull_request")["scope"], "full")
        changed = json.loads(json.dumps(event))
        changed["pull_request"]["head"]["sha"] = self.base
        self.assertEqual(self.classify(changed, "pull_request")["scope"], "full")
        self.git("reset", "--hard", head)
        self.assertEqual(self.classify(event, "pull_request")["reason"], "pull-request-merge-parent-mismatch")

    def test_manual_schedule_and_empty_range_are_full(self):
        for name in ("workflow_dispatch", "schedule", "merge_group", "unknown"):
            self.assertEqual(self.classify(name=name)["scope"], "full")
        self.assertEqual(self.classify()["reason"], "empty-change-range")

    def test_executing_untrusted_classifier_bytes_is_an_error(self):
        self.write("README.md", "# Updated\n")
        self.commit()
        self.trusted.write_text("untrusted replacement\n")
        with self.assertRaisesRegex(RuntimeError, "immutable base blob"):
            self.classify()

    def test_unknown_git_path_encoding_is_full_with_a_receipt(self):
        self.write("README.md", "# Changed\n")
        self.commit()
        original = SCOPE.git
        def read(repo, *arguments, **kwargs):
            if "--raw" in arguments:
                return b":100644 100644 " + b"a" * 40 + b" " + b"b" * 40 + b" M\0invalid-\xff\0"
            return original(repo, *arguments, **kwargs)
        with mock.patch.object(SCOPE, "git", side_effect=read):
            self.assertEqual(self.classify()["reason"], "invalid-change-record-encoding")

    def bootstrap(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())["jobs"]
        script = next(step["run"] for step in jobs["change-scope"]["steps"] if step.get("id") == "classify")
        lines = script.splitlines()
        self.assertEqual(lines[0], "python -I -B - <<'PY'")
        self.assertEqual(lines[-1], "PY")
        event_path, output = self.control / "event.json", self.control / "outputs"
        event_path.write_text(json.dumps(self.event()))
        environment = {**os.environ, "GITHUB_WORKSPACE": str(self.repo), "GITHUB_EVENT_PATH": str(event_path),
                       "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": REPOSITORY,
                       "GITHUB_SHA": self.git("rev-parse", "HEAD"), "RUNNER_TEMP": str(self.control),
                       "GITHUB_OUTPUT": str(output)}
        subprocess.run([sys.executable, "-I", "-B", "-"], input="\n".join(lines[1:-1]),
                       text=True, env=environment, check=True, capture_output=True, timeout=30)
        return dict(line.split("=", 1) for line in output.read_text().splitlines())

    def test_bootstrap_extracts_base_and_ignores_malicious_head_classifier(self):
        self.write("tools/ci_change_scope.py", "raise RuntimeError('HEAD MUST NOT EXECUTE')\n")
        self.write("README.md", "# Proposed docs\n")
        self.commit()
        result = self.bootstrap()
        self.assertEqual(result["scope"], "full")
        self.assertEqual(result["classifier_blob"], self.git("rev-parse", self.base + ":tools/ci_change_scope.py"))

    def test_bootstrap_without_base_helper_is_full_without_running_head(self):
        self.git("rm", "tools/ci_change_scope.py")
        self.base = self.commit()
        self.write("tools/ci_change_scope.py", "raise RuntimeError('HEAD MUST NOT EXECUTE')\n")
        self.commit()
        result = self.bootstrap()
        self.assertEqual((result["scope"], result["docs_validated"], result["classifier_blob"]), ("full", "false", ""))

    def test_actual_bootstrap_docs_cli_writes_bound_outputs_and_receipt(self):
        self.write("README.md", "# Real documentation change\n")
        head = self.commit()
        result = self.bootstrap()
        self.assertEqual((result["scope"], result["docs_validated"], result["tested_sha"]), ("docs", "true", head))
        receipt = json.loads((self.control / "emulebb-ci-scope/classification.json").read_text())
        self.assertEqual(receipt["headSha"], head)
        self.assertEqual(receipt["classifierBlob"], result["classifier_blob"])

    def test_all_workflows_share_identical_read_only_base_bootstrap(self):
        commands = []
        for name in ("ci.yml", "codeql.yml", "optional-platforms.yml"):
            jobs = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())["jobs"]
            job = jobs["change-scope"]
            self.assertEqual(job["permissions"], {"contents": "read"})
            self.assertNotIn("if", job)
            commands.append(next(step["run"] for step in job["steps"] if step.get("id") == "classify"))
        self.assertEqual(len(set(commands)), 1)


if __name__ == "__main__":
    unittest.main()
