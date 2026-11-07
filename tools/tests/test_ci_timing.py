"""Failures retain timing evidence and never execute later checks."""
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rust_quality_gate as QUALITY
from build_webui import asset_hashes, stage_dist


class CiTimingTests(unittest.TestCase):
    def test_failed_check_retains_durations_and_stops_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {"EMULEBB_WORKSPACE_OUTPUT_ROOT": directory}
            commands = [("first", ["first"]), ("failure", ["failure"]), ("never", ["never"])]
            with patch.object(QUALITY, "run_step", side_effect=[None, subprocess.CalledProcessError(3, "fixture")]) as run, patch.object(QUALITY, "perf_counter", side_effect=[10, 11, 20, 23]), patch("builtins.print"):
                with self.assertRaises(subprocess.CalledProcessError):
                    QUALITY.execute_gate("fixture", commands, env)
                self.assertEqual(run.call_count, 2)
            report = json.loads(next(Path(directory).rglob("results.json")).read_text())
            self.assertEqual(report["status"], "failed")
            self.assertEqual([item["elapsed_seconds"] for item in report["checks"]], [1, 3])
            self.assertEqual(report["elapsed_seconds"], 4)

    def test_supply_chain_failure_is_checked_before_expensive_work(self):
        checks = QUALITY.GATES["pre-push"]
        for name in ("clippy", "webui-test", "build", "test-workspace"):
            self.assertLess(checks.index("supply-chain"), checks.index(name))

    def test_staging_preserves_every_asset_and_records_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            dist, stage = output / "dist", output / "stage"
            (dist / "assets").mkdir(parents=True)
            (dist / "index.html").write_text("synthetic index")
            (dist / "assets/app.js").write_text("synthetic asset")
            stage_dist(dist, stage, output)
            self.assertEqual(asset_hashes(dist), asset_hashes(stage))
            report = json.loads((output / "reports/webui-stage/latest.json").read_text())
            self.assertEqual(report["assets"], asset_hashes(dist))
            with self.assertRaises(SystemExit):
                stage_dist(dist, dist, output)

    def test_corrupted_copy_cannot_be_reported_as_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            dist = output / "dist"
            dist.mkdir()
            (dist / "index.html").write_text("synthetic bundle")
            copytree = shutil.copytree

            def corrupt(source, target):
                copytree(source, target)
                (target / "index.html").write_text("changed synthetic bundle")

            with patch("build_webui.shutil.copytree", side_effect=corrupt):
                with self.assertRaisesRegex(SystemExit, "differ"):
                    stage_dist(dist, output / "stage", output)
            self.assertFalse((output / "reports/webui-stage/latest.json").exists())
