"""Linux release packaging must use the verified prepared Builder pipeline."""

from pathlib import Path
import shlex
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ReleaseLinuxProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
        self.job = self.workflow["jobs"]["native-package"]
        self.steps = self.job["steps"]
        self.prepared = next(step for step in self.steps
                             if "package-emulebb-rust-prepared-ci" in step.get("run", ""))
        self.host = next(step for step in self.steps
                         if "package-emulebb-rust-ci --release-version" in step.get("run", ""))

    def test_linux_uses_prepared_pipeline_without_host_provisioning_or_fallback(self):
        self.assertEqual(self.prepared["if"], "matrix.os == 'linux'")
        self.assertEqual(self.host["if"], "matrix.os != 'linux'")
        self.assertEqual(shlex.split(self.prepared["run"]), [
            "python", "-B", "-m", "emule_workspace", "package-emulebb-rust-prepared-ci",
            "--image", "$PREPARED_IMAGE", "--release-version", "$RELEASE_VERSION",
            "--platform", "${{", "matrix.arch", "}}",
        ])
        commands = "\n".join(step.get("run", "") for step in self.steps)
        for forbidden in ("apt-get", "provision-ubuntu-dependencies-ci", "appimagetool-", "APPIMAGE_EXTRACT_AND_RUN"):
            self.assertNotIn(forbidden, commands)
        self.assertNotIn("||", self.prepared["run"], "An unverified image must never select a host fallback")

    def test_prepared_source_identity_output_and_host_verification_are_explicit(self):
        self.assertEqual(self.prepared["env"], {
            **self.host["env"],
            "PREPARED_IMAGE": "${{ env.EMULEBB_LINUX_PREPARED_IMAGE }}",
            "GH_TOKEN": "${{ secrets.GITHUB_TOKEN }}",
        })
        self.assertEqual(self.prepared["env"]["EMULEBB_SOURCE_REVISION"], "${{ needs.prepare.outputs.source_sha }}")
        self.assertEqual(self.prepared["timeout-minutes"], 40)
        self.assertEqual(self.job["timeout-minutes"], 45)
        self.assertNotIn("continue-on-error", self.prepared)
        self.assertNotIn("continue-on-error", self.job)

    def test_prepared_packaging_uses_pinned_owner_and_native_docker_before_upload(self):
        checkout = next(step for step in self.steps
                        if step.get("with", {}).get("repository") == "emulebb/emulebb-build")
        self.assertEqual(checkout["with"]["ref"], "${{ env.EMULEBB_BUILD_REF }}")
        self.assertRegex(self.workflow["env"]["EMULEBB_BUILD_REF"], r"^[0-9a-f]{40}$")
        self.assertEqual(self.prepared["working-directory"], checkout["with"]["path"])
        docker = next(step for step in self.steps if step.get("uses", "").startswith("docker/setup-docker-action@"))
        self.assertEqual(docker["if"], "matrix.os == 'linux'")
        self.assertEqual(docker["with"]["version"], "v29.6.1")
        self.assertRegex(docker["uses"], r"@[0-9a-f]{40}$")
        index = self.steps.index(self.prepared)
        self.assertLess(self.steps.index(checkout), index)
        self.assertLess(self.steps.index(docker), index)
        upload = next(step for step in self.steps if step.get("with", {}).get("name") ==
                      "emulebb-rust-native-payload-${{ matrix.slug }}")
        self.assertLess(index, self.steps.index(upload))
        self.assertEqual(upload["with"]["if-no-files-found"], "error")

    def test_all_six_platforms_keep_existing_smoke_and_artifact_graph(self):
        self.assertEqual({row["slug"] for row in self.job["strategy"]["matrix"]["include"]},
                         {"windows-x64", "windows-arm64", "linux-x64", "linux-arm64", "macos-x64", "macos-arm64"})
        self.assertEqual(self.workflow["jobs"]["native-package-smoke"]["needs"], ["prepare", "native-package"])
        self.assertEqual(self.host["run"],
                         "python -m emule_workspace package-emulebb-rust-ci --release-version ${{ env.RELEASE_VERSION }} "
                         "--target-os ${{ matrix.os }} --platform ${{ matrix.arch }}")


if __name__ == "__main__":
    unittest.main()
