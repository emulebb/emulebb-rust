"""Toolchain differences and unverified tool archives must fail visibly."""
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import ci_environment as ENV
import yaml


class CiEnvironmentTests(unittest.TestCase):
    def test_version_mismatch_is_not_silently_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "version mismatch"):
            ENV.require_version("fixture", "1.0", "2.0")

    def test_workflow_lint_always_passes_an_explicit_shellcheck(self):
        with patch.object(ENV, "command_version", return_value=ENV.TOOLCHAIN["go"]), patch.object(ENV, "ensure_shellcheck", return_value=Path("fixture-shellcheck")):
            command = ENV.prepare_command(["go", "run", "fixture-actionlint"], {"EMULEBB_WORKSPACE_OUTPUT_ROOT": "fixture-output"})
            self.assertEqual(command[-1], "-shellcheck=fixture-shellcheck")

    def test_corrupted_cached_archive_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            cache = output / "cache" / "ci-tools"
            cache.mkdir(parents=True)
            (cache / "fixture.zip").write_bytes(b"corrupted fixture")
            config = {"shellcheck": {"version": "0.11.0", "assets": {"windows-x86_64": ["fixture.zip", "0" * 64]}}}
            with patch.object(ENV, "TOOLCHAIN", config), patch.object(ENV.platform, "system", return_value="Windows"), patch.object(ENV.platform, "machine", return_value="AMD64"), patch.object(ENV, "command_version") as execute:
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    ENV.ensure_shellcheck(output)
                execute.assert_not_called()

    def test_archive_members_are_read_without_extracting_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "fixture.zip"
            escaped = f"{Path(directory).name}-outside.txt"
            with zipfile.ZipFile(archive, "w") as source:
                source.writestr(f"../{escaped}", "unrelated fixture")
                source.writestr("release/shellcheck.exe", b"expected fixture binary")
            self.assertEqual(ENV.archive_binary(archive, "shellcheck.exe"), b"expected fixture binary")
            self.assertFalse((Path(directory).parent / escaped).exists())

    def test_contract_override_is_fingerprinted_and_differences_are_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = root / "fixture.yaml"
            contract.write_bytes(b"synthetic contract")
            config = {"inputs": {"emulebb-tooling": "1" * 40}, "openapi_sha256": hashlib.sha256(contract.read_bytes()).hexdigest()}
            with patch.object(ENV, "TOOLCHAIN", config), patch("rust_quality_gate.require_workspace_root_env", return_value=root):
                env = {"EMULEBB_REST_OPENAPI_CONTRACT_PATH": str(contract)}
                result = ENV.report_inputs(env, ("emulebb-tooling",))["REST-API-OPENAPI.yaml"]
                self.assertTrue(result["override"])
                self.assertEqual(result["status"], "matching")
                contract.write_bytes(b"changed synthetic contract")
                self.assertEqual(ENV.report_inputs(env, ("emulebb-tooling",))["REST-API-OPENAPI.yaml"]["status"], "different")

    def test_setup_versions_match_the_declared_toolchain(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
            for variable, name in (("MINIUPNP_REF", "emulebb-miniupnp"), ("PCPNATPMP_REF", "emulebb-libpcpnatpmp")):
                if variable in workflow.get("env", {}):
                    self.assertEqual(workflow["env"][variable], ENV.TOOLCHAIN["inputs"][name])
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    action = step.get("uses", "")
                    inputs = step.get("with", {})
                    if action.startswith("actions/setup-python@"):
                        self.assertEqual(str(inputs["python-version"]), ENV.TOOLCHAIN["python"], str(path))
                    if action.startswith("actions/setup-go@"):
                        self.assertEqual(str(inputs["go-version"]), ENV.TOOLCHAIN["go"], str(path))
                    if action.startswith("actions/setup-node@"):
                        self.assertEqual(str(inputs["node-version"]), ENV.TOOLCHAIN["node"], str(path))
                        self.assertTrue(any(step.get("run") == f"npm install --global npm@{ENV.TOOLCHAIN['npm']}" for step in job["steps"]))
                    if action.startswith("taiki-e/install-action@"):
                        self.assertEqual(inputs["tool"], f"cargo-deny@{ENV.TOOLCHAIN['cargo_deny']}")

    def test_conformance_inputs_match_the_workflow_checkouts(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        for step in workflow["jobs"]["rest-openapi"]["steps"]:
            inputs = step.get("with", {})
            name = inputs.get("repository", "").removeprefix("emulebb/")
            if name in ENV.TOOLCHAIN["inputs"]:
                self.assertEqual(inputs["ref"], ENV.TOOLCHAIN["inputs"][name])
