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
            if job == "supply-chain":
                # The pinned container action is an adapter until tool setup is unified.
                command = next(step["with"]["command"] for step in steps if "cargo-deny-action@" in step.get("uses", ""))
                self.assertEqual(command.split(), QUALITY.supply_chain_step()[1][2:])
            else:
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

    def test_branch_workflow_dispatches_the_shared_light_gate(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/branch-check.yml").read_text(encoding="utf-8"))["jobs"]
        self.assertTrue(any(step.get("run") == "python tools/rust_quality_gate.py branch-ci" for step in jobs["check"]["steps"]))
