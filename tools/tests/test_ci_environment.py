"""Toolchain differences and unverified tool archives must fail visibly."""
import json
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import call, patch
import urllib.error
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import ci_environment as ENV
import yaml


class CiEnvironmentTests(unittest.TestCase):
    def test_release_documents_are_preflighted_before_packaging_and_downloaded_before_assembly(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        prepare = workflow["jobs"]["prepare"]["steps"]
        source = next(step for step in prepare if step.get("with", {}).get("path") == ".ci/candidate")
        self.assertEqual(source["with"]["fetch-depth"], 0)
        generate = next(step for step in prepare if "nightly_release.py release-docs" in step.get("run", ""))
        self.assertIn('--source-sha "$SOURCE_SHA"', generate["run"])
        self.assertEqual(generate["env"]["SOURCE_SHA"], "${{ steps.source.outputs.sha }}")
        upload = next(step for step in prepare if step.get("with", {}).get("name") == "emulebb-rust-release-documents")
        self.assertLess(prepare.index(generate), prepare.index(upload))
        assembly = workflow["jobs"]["assemble-candidate"]["steps"]
        download = next(step for step in assembly if step.get("with", {}).get("name") == "emulebb-rust-release-documents")
        checksum = next(step for step in assembly if "assemble-emulebb-rust-release-ci" in step.get("run", ""))
        self.assertLess(assembly.index(download), assembly.index(checksum))
        self.assertFalse(any('cp "emulebb-tooling/docs/' in step.get("run", "") for step in assembly))

    def test_android_ci_uses_both_local_abis_and_immutable_orchestration(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        android = workflow["jobs"]["build-android"]
        self.assertEqual(set(android["strategy"]["matrix"]["abi"]), {"arm64-v8a", "x86_64"})
        self.assertFalse(android["strategy"]["fail-fast"])
        self.assertRegex(workflow["env"]["EMULEBB_ANDROID_BUILD_REF"], r"^[0-9a-f]{40}$")
        checkout = next(step for step in android["steps"]
                        if step.get("with", {}).get("repository") == "emulebb/emulebb-build")
        self.assertEqual(checkout["with"]["ref"], "${{ env.EMULEBB_ANDROID_BUILD_REF }}")
        compile_step = next(step for step in android["steps"]
                            if "validate-rust-android-ci" in step.get("run", ""))
        self.assertIn("--abi ${{ matrix.abi }}", compile_step["run"])
        self.assertEqual(compile_step["working-directory"], checkout["with"]["path"])
        self.assertIn('mkdir -p "$CARGO_TARGET_DIR"', compile_step["run"])
        self.assertEqual(compile_step["env"]["EMULEBB_WORKSPACE_OUTPUT_ROOT"],
                         "${{ runner.temp }}/emulebb-rust-out")
        self.assertIn("build-android", workflow["jobs"]["required-ci"]["needs"])

    def test_release_packaging_installs_policy_dependencies_before_policy_check(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        steps = workflow["jobs"]["native-package"]["steps"]
        checks = [index for index, step in enumerate(steps)
                  if "tools/check_rust_client_policy.py" in step.get("run", "")]
        self.assertTrue(checks, "Native releases must check production feature policy")
        for index in checks:
            self.assertTrue(any("pip install" in step.get("run", "")
                                and "-r tools/requirements-ci.txt" in step["run"]
                                for step in steps[:index]),
                            "Fresh release runners must install the canonical policy dependencies first")

    def test_release_packaging_declares_workspace_root_for_webui_builds(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())
        for job in ("native-package", "musl-package"):
            with self.subTest(job=job):
                self.assertEqual(workflow["jobs"][job].get("env", {}).get("EMULEBB_WORKSPACE_ROOT"),
                                 "${{ github.workspace }}")

    def test_version_mismatch_is_not_silently_accepted(self):
        with self.assertRaisesRegex(RuntimeError, "version mismatch"):
            ENV.require_version("fixture", "1.0", "2.0")

    def _report_for_scope(self, scope):
        rust = ENV.tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        packages = dict(line.split("==") for line in (ROOT / "tools/requirements-ci.txt").read_text().splitlines() if "==" in line)
        commands = []
        def version(command, pattern):
            commands.append(command)
            return {"rustc": rust, "go": ENV.TOOLCHAIN["go"], "cargo": ENV.TOOLCHAIN["cargo_deny"]}[command[0]]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ENV, "command_version", side_effect=version), patch.object(ENV, "ensure_shellcheck", return_value=Path("fixture-shellcheck")) as shellcheck, patch.object(ENV, "node_versions", return_value={"node": ENV.TOOLCHAIN["node"], "npm": ENV.TOOLCHAIN["npm"]}), patch.object(ENV, "report_inputs", return_value={"fixture": {"status": "matching"}}), patch.object(ENV.platform, "python_version", return_value=ENV.TOOLCHAIN["python"]), patch.object(ENV.importlib.metadata, "version", side_effect=packages.__getitem__):
                report = ENV.environment_report({"EMULEBB_WORKSPACE_OUTPUT_ROOT": directory}, scope=scope)
                retained = json.loads((Path(directory) / "reports/ci-environment/latest.json").read_text())
                self.assertEqual(retained, report)
                return report, commands, shellcheck.call_count

    def test_quality_environment_never_downloads_or_executes_unrelated_tools(self):
        report, commands, downloads = self._report_for_scope("quality")
        self.assertEqual(commands, [["rustc", "--version"]])
        self.assertEqual(downloads, 0)
        self.assertEqual(set(report["tools"]), {"python", "rust", "node", "npm", "python_packages"})
        self.assertEqual(report["scope"], "quality")
        self.assertIsNone(report["shellcheck"])
        self.assertEqual(report["inputs"]["fixture"]["status"], "matching")

    def test_unknown_environment_scope_cannot_silently_skip_tool_checks(self):
        with patch.object(ENV, "ensure_shellcheck") as download, patch.object(ENV, "command_version") as execute:
            with self.assertRaisesRegex(ValueError, "scope"):
                ENV.environment_report({}, scope="misspelled")
            download.assert_not_called()
            execute.assert_not_called()

    def test_full_local_environment_keeps_all_tool_version_checks(self):
        report, commands, downloads = self._report_for_scope("full")
        self.assertEqual(commands, [["go", "version"], ["cargo", "deny", "--version"], ["rustc", "--version"]])
        self.assertEqual(downloads, 1)
        self.assertEqual(report["tools"]["go"], ENV.TOOLCHAIN["go"])
        self.assertEqual(report["tools"]["cargo_deny"], ENV.TOOLCHAIN["cargo_deny"])
        self.assertEqual(report["tools"]["shellcheck"], ENV.TOOLCHAIN["shellcheck"]["version"])
        self.assertEqual(report["tools"]["actionlint"], ENV.TOOLCHAIN["actionlint"])
        self.assertEqual(report["shellcheck"], "fixture-shellcheck")

    def _shellcheck_archive_fixture(self):
        stream = io.BytesIO()
        executable = "shellcheck.exe" if ENV.os.name == "nt" else "shellcheck"
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(executable, b"fixture binary, never executed")
        content = stream.getvalue()
        config = {"shellcheck": {"version": "0.11.0", "assets": {"windows-x86_64": ["fixture.zip", hashlib.sha256(content).hexdigest()]}}}
        return content, config

    def test_shellcheck_retries_transient_download_failure_then_verifies_bytes(self):
        for error in (TimeoutError("fixture"), ConnectionResetError("fixture"), urllib.error.HTTPError("https://fixture.invalid", 504, "fixture", None, None)):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory:
                content, config = self._shellcheck_archive_fixture()
                with patch.object(ENV, "TOOLCHAIN", config), patch.object(ENV.platform, "system", return_value="Windows"), patch.object(ENV.platform, "machine", return_value="AMD64"), patch.object(ENV.urllib.request, "urlopen", side_effect=[error, io.BytesIO(content)]) as download, patch.object(ENV.time, "sleep") as sleep, patch.object(ENV, "command_version", return_value="0.11.0"):
                    target = ENV.ensure_shellcheck(Path(directory))
                    self.assertTrue(target.is_file())
                    self.assertEqual(download.call_count, 2)
                    sleep.assert_called_once_with(1)
                    self.assertEqual((Path(directory) / "cache/ci-tools/fixture.zip").read_bytes(), content)

    def test_shellcheck_download_retries_are_bounded_and_do_not_execute_partial_bytes(self):
        content, config = self._shellcheck_archive_fixture()
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ENV, "TOOLCHAIN", config), patch.object(ENV.platform, "system", return_value="Windows"), patch.object(ENV.platform, "machine", return_value="AMD64"), patch.object(ENV.urllib.request, "urlopen", side_effect=TimeoutError("fixture")) as download, patch.object(ENV.time, "sleep") as sleep, patch.object(ENV, "command_version") as execute:
                with self.assertRaises(TimeoutError):
                    ENV.ensure_shellcheck(Path(directory))
                self.assertEqual(download.call_count, 3)
                self.assertEqual(sleep.call_args_list, [call(1), call(2)])
                execute.assert_not_called()
                self.assertEqual(list((Path(directory) / "cache/ci-tools").iterdir()), [])

    def test_shellcheck_retry_discards_bytes_from_an_interrupted_response(self):
        class InterruptedDownload(io.BytesIO):
            def read(self, size=-1):
                if self.tell():
                    raise ConnectionResetError("fixture interrupted after a partial write")
                return super().read(size)
        content, config = self._shellcheck_archive_fixture()
        responses = [InterruptedDownload(b"unverified partial content" * 10000), io.BytesIO(content)]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(ENV, "TOOLCHAIN", config), patch.object(ENV.platform, "system", return_value="Windows"), patch.object(ENV.platform, "machine", return_value="AMD64"), patch.object(ENV.urllib.request, "urlopen", side_effect=responses) as download, patch.object(ENV.time, "sleep"), patch.object(ENV, "command_version", return_value="0.11.0"):
                ENV.ensure_shellcheck(Path(directory))
                self.assertEqual(download.call_count, 2)
                self.assertEqual((Path(directory) / "cache/ci-tools/fixture.zip").read_bytes(), content)

    def test_shellcheck_permanent_download_error_and_bad_hash_are_not_retried(self):
        content, config = self._shellcheck_archive_fixture()
        for failure in ("not-found", "bad-hash"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                error = urllib.error.HTTPError("https://fixture.invalid", 404, "fixture", None, None)
                with patch.object(ENV, "TOOLCHAIN", config), patch.object(ENV.platform, "system", return_value="Windows"), patch.object(ENV.platform, "machine", return_value="AMD64"), patch.object(ENV.urllib.request, "urlopen", side_effect=error if failure == "not-found" else None, return_value=io.BytesIO(b"unverified fixture")) as download, patch.object(ENV.time, "sleep") as sleep, patch.object(ENV, "command_version") as execute:
                    with self.assertRaises(urllib.error.HTTPError if failure == "not-found" else RuntimeError):
                        ENV.ensure_shellcheck(Path(directory))
                    download.assert_called_once()
                    sleep.assert_not_called()
                    execute.assert_not_called()
                    self.assertEqual(list((Path(directory) / "cache/ci-tools").iterdir()), [])

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
