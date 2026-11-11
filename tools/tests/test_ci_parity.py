"""Verify workflow dispatch covers exactly the locally required Rust checks."""
import importlib.util
from pathlib import Path
import shlex
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("quality_parity", ROOT / "tools/rust_quality_gate.py")
QUALITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY)


class CiParityTests(unittest.TestCase):
    def assert_workflow_parity(self, jobs):
        covered = set()
        for job, gate in QUALITY.CI_JOBS.items():
            steps = jobs[job]["steps"]
            dispatched = [shlex.split(step["run"]) for step in steps if "rust_quality_gate.py" in step.get("run", "")]
            self.assertTrue(any(command[-1] == gate for command in dispatched), f"{job} must dispatch {gate}")
            covered.update(QUALITY.GATES[gate])
        self.assertEqual(covered, set(QUALITY.GATES["pre-push"]))

    def test_required_workflow_and_local_gate_cover_the_same_checks(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        self.assert_workflow_parity(jobs)

    def test_omitted_dispatch_is_rejected(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        jobs["quality"]["steps"] = []
        with self.assertRaises(AssertionError):
            self.assert_workflow_parity(jobs)

    def test_required_and_optional_matrices_cover_six_native_targets_and_both_musl_cpus(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        optional = yaml.safe_load((ROOT / ".github/workflows/optional-platforms.yml").read_text(encoding="utf-8"))["jobs"]
        native = {jobs["build-linux"]["runs-on"], *jobs["build-test"]["strategy"]["matrix"]["runner"]}
        self.assertEqual(native, {"ubuntu-24.04", "ubuntu-24.04-arm", "windows-latest", "windows-11-arm"})
        self.assertEqual(set(optional["build-macos"]["strategy"]["matrix"]["runner"]), {"macos-15-intel", "macos-15"})
        self.assertEqual(set(optional["build-android"]["strategy"]["matrix"]["abi"]), {"arm64-v8a", "x86_64"})
        self.assertNotIn("build-android", jobs["required-ci"]["needs"])
        musl = jobs["build-musl"]
        self.assertEqual({(row["architecture"], row["runner"]) for row in musl["strategy"]["matrix"]["include"]},
                         {("amd64", "ubuntu-24.04"), ("arm64", "ubuntu-24.04-arm")})
        package = next(step for step in musl["steps"]
                       if "package-emulebb-rust-linux-ci" in step.get("run", ""))
        self.assertIn("--test-scope full --smoke", package["run"])
        self.assertIn('mkdir -p "$CARGO_TARGET_DIR"', package["run"])
        self.assertLess(package["run"].index('mkdir -p "$CARGO_TARGET_DIR"'),
                        package["run"].index("python -B -m emule_workspace"))
        self.assertIn("build-musl", jobs["required-ci"]["needs"])
        aggregate = jobs["required-ci"]["steps"][0]
        self.assertEqual(aggregate["env"]["BUILD_MUSL_RESULT"], "${{ needs.build-musl.result }}")
        self.assertIn('"$BUILD_MUSL_RESULT"', aggregate["run"])

    def test_ci_checkout_credentials_do_not_survive_into_builds(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        for name, job in jobs.items():
            for step in job.get("steps", []):
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertIs(step.get("with", {}).get("persist-credentials"), False, name)

    def test_branch_workflow_dispatches_the_shared_light_gate(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/branch-check.yml").read_text(encoding="utf-8"))["jobs"]
        self.assertTrue(any(step.get("run") == "python tools/rust_quality_gate.py branch-ci" for step in jobs["check"]["steps"]))
