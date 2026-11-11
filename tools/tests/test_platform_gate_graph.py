"""Exercise real profile selection and aggregate scripts with failed producers."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("platform_release_control", ROOT / "tools/release_publish.py")
PUBLISH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISH)


def jobs(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"))["jobs"]


class TestPlatformGraph(unittest.TestCase):
    def test_selected_package_and_smoke_graphs_share_the_actual_profile_matrix(self):
        release = jobs("release.yml")
        selected_matrix = "${{ fromJSON(needs.prepare.outputs.native_matrix) }}"
        for name in ("native-package", "native-package-smoke"):
            self.assertEqual(release[name]["strategy"]["matrix"]["include"], selected_matrix)
        self.assertEqual({row["slug"] for row in PUBLISH.native_matrix("full")}, {
            "windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64",
        })
        self.assertEqual({row["slug"] for row in PUBLISH.native_matrix("windows-linux")}, {
            "windows-x64", "windows-arm64", "linux-x64", "linux-arm64",
        })
        self.assertEqual(set(release["assemble-candidate"]["needs"]), {
            "prepare", "native-package-smoke", "musl-package", "image-native-validation", "android-package",
        })
        self.assertEqual(set(release["image-candidate"]["needs"]), {"prepare", "native-package", "musl-package"})
        self.assertEqual(release["native-package-smoke"]["needs"], ["prepare", "native-package"])
        for name in ("optional-macos-package", "optional-macos-smoke"):
            self.assertIn("platform_profile == 'windows-linux'", release[name]["if"])
            self.assertEqual({row["os"] for row in release[name]["strategy"]["matrix"]["include"]}, {"macos"})
        self.assertIs(release["native-package"]["steps"], release["optional-macos-package"]["steps"])
        self.assertIs(release["native-package-smoke"]["steps"], release["optional-macos-smoke"]["steps"])
        for name, payload, smoke in (
            ("native-package", "emulebb-rust-native-payload", None),
            ("optional-macos-package", "emulebb-rust-optional-native-payload", None),
            ("native-package-smoke", "emulebb-rust-native-payload", "emulebb-rust-package-smoke"),
            ("optional-macos-smoke", "emulebb-rust-optional-native-payload", "emulebb-rust-optional-package-smoke"),
        ):
            job = release[name]
            self.assertEqual(job["env"]["NATIVE_PAYLOAD_PREFIX"], payload)
            if smoke:
                self.assertEqual(job["env"]["PACKAGE_SMOKE_PREFIX"], smoke)
            artifacts = [step["with"]["name"] for step in job["steps"]
                         if step.get("uses", "").startswith(("actions/upload-artifact@", "actions/download-artifact@"))]
            self.assertIn("${{ env.NATIVE_PAYLOAD_PREFIX }}-${{ matrix.slug }}", artifacts)
            if smoke:
                self.assertIn("${{ env.PACKAGE_SMOKE_PREFIX }}-${{ matrix.slug }}", artifacts)

    def test_reduced_profile_is_only_an_explicit_unpublished_manual_candidate(self):
        self.assertEqual(PUBLISH.resolve_platform_profile(
            "windows-linux", event_name="workflow_dispatch", channel="candidate", publish="false"), "windows-linux")
        for event, channel, publish in (("push", "beta", "false"), ("schedule", "nightly", "true"),
                                         ("workflow_dispatch", "nightly", "false"),
                                         ("workflow_dispatch", "candidate", "true")):
            with self.subTest(event=event, channel=channel, publish=publish), self.assertRaises(RuntimeError):
                PUBLISH.resolve_platform_profile("windows-linux", event_name=event, channel=channel, publish=publish)
        for profile in ("unknown", "", "FULL"):
            with self.assertRaises(RuntimeError):
                PUBLISH.resolve_platform_profile(profile, event_name="workflow_dispatch", channel="candidate", publish="false")

    def test_optional_workflow_has_independent_concurrency_and_retains_pins(self):
        main = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
        optional = yaml.safe_load((ROOT / ".github/workflows/optional-platforms.yml").read_text(encoding="utf-8"))
        self.assertNotEqual(main["concurrency"]["group"], optional["concurrency"]["group"])
        self.assertEqual(main["permissions"], optional["permissions"])
        self.assertEqual(main["env"], optional["env"])
        self.assertEqual(optional["jobs"]["optional-platform-ci"]["needs"],
                         ["single-active-pr", "workflow-lint", "build-macos", "build-android"])
        self.assertFalse(any("optional" in name or "android" in name or "macos" in name
                             for name in main["jobs"]["required-ci"]["needs"]))

    def test_reduced_profile_publication_is_rejected_before_loading_any_packaging_owner(self):
        for command in ("publish-images", "release-assets"):
            with self.subTest(command=command), mock.patch.object(PUBLISH, "build_parser") as parser, \
                    mock.patch.object(PUBLISH, "candidate_owner") as owner:
                parser.return_value.parse_args.return_value = SimpleNamespace(command=command, platform_profile="windows-linux")
                with self.assertRaisesRegex(RuntimeError, "Publication requires the full"):
                    PUBLISH.main([])
                owner.assert_not_called()

    @unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "Aggregate scripts execute on Ubuntu; source/profile tests are portable")
    def test_actual_aggregate_shell_fails_for_each_failed_cancelled_or_skipped_dependency(self):
        for workflow, name in (("ci.yml", "required-ci"), ("optional-platforms.yml", "optional-platform-ci")):
            step = jobs(workflow)[name]["steps"][0]
            environment = {**os.environ, **dict.fromkeys(step["env"], "success"), "GITHUB_STEP_SUMMARY": "/dev/null"}
            def execute():
                return subprocess.run(["bash", "-c", step["run"]], env=environment,
                                      capture_output=True, text=True, timeout=5).returncode
            self.assertEqual(execute(), 0)
            for key in step["env"]:
                for failed in ("failure", "cancelled", "skipped"):
                    with self.subTest(workflow=workflow, dependency=key, state=failed):
                        environment[key] = failed
                        self.assertNotEqual(execute(), 0)
                environment[key] = "success"


if __name__ == "__main__":
    unittest.main()
