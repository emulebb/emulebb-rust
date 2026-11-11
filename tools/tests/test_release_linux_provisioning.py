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
        self.assertRegex(
            self.workflow["env"]["EMULEBB_LINUX_PREPARED_IMAGE"],
            r"^ghcr\.io/emulebb/emulebb-build-ci/ubuntu-rust@sha256:[0-9a-f]{64}$",
        )
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

    def test_linux_image_owns_toolchains_while_host_keeps_python_control(self):
        setup = [step for step in self.steps
                 if step.get("uses", "").startswith(("dtolnay/rust-toolchain@", "actions/setup-node@"))
                 or step.get("run") == "npm install --global npm@11.20.0"]
        self.assertEqual(len(setup), 3)
        for step in setup:
            self.assertEqual(step["if"], "matrix.os != 'linux'")
        python = next(step for step in self.steps if step.get("uses", "").startswith("actions/setup-python@"))
        dependencies = next(step for step in self.steps
                            if "pip install -r tools/requirements-ci.txt" in step.get("run", ""))
        policy = next(step for step in self.steps if step.get("run") == "python tools/check_rust_client_policy.py")
        for step in (python, dependencies, policy):
            self.assertNotIn("if", step)
            self.assertLess(self.steps.index(step), self.steps.index(self.prepared))

    def test_musl_and_image_consumers_select_mirrors_without_changing_runtime_base(self):
        for job, command in (("musl-package", "package-emulebb-rust-linux-ci"),
                             ("image-candidate", "package-emulebb-rust-image-ci")):
            package = next(step for step in self.workflow["jobs"][job]["steps"]
                           if command in step.get("run", ""))
            self.assertIn("--use-ci-image-mirrors", shlex.split(package["run"]))
            self.assertNotIn("continue-on-error", package)
        recipe = (ROOT / "packaging/docker/Dockerfile.alpine").read_text(encoding="utf-8").splitlines()
        self.assertIn("ARG ALPINE_UNPACK_IMAGE=docker.io/library/alpine:3.24@sha256:"
                      "3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a", recipe)
        self.assertEqual([line for line in recipe if line.startswith("FROM ")], [
            "FROM ${ALPINE_UNPACK_IMAGE} AS unpack",
            "FROM ghcr.io/linuxserver/baseimage-alpine:3.24@sha256:"
            "7315b19a32460a84b4474993ef33065483ffec792fbc70dbe12eab918aa2bbf4",
        ])


if __name__ == "__main__":
    unittest.main()
