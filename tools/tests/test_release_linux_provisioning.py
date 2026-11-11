"""Native release setup must use bounded, pinned Ubuntu provisioning."""

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
        self.provision = next(step for step in self.steps
                              if "provision-ubuntu-dependencies-ci" in step.get("run", ""))

    def test_linux_setup_uses_the_shared_bounded_provisioner(self):
        self.assertEqual(self.provision["if"], "matrix.os == 'linux'")
        self.assertEqual(shlex.split(self.provision["run"]), [
            "python", "-B", "-m", "emule_workspace", "provision-ubuntu-dependencies-ci",
            "--profile", "rust-native-release", "--deadline-seconds", "300",
            "--network-timeout-seconds", "20", "--attempts", "3",
            "--report", "$RUNNER_TEMP/emulebb-rust-out/reports/native-linux-provisioning.json",
        ])
        self.assertFalse(any("apt-get" in step.get("run", "") for step in self.steps),
                         "APT source selection and retries belong to the pinned Builder")

    def test_setup_has_a_short_outer_deadline_and_failure_remains_blocking(self):
        self.assertEqual(self.provision["timeout-minutes"], 6)
        self.assertEqual(self.job["timeout-minutes"], 45)
        self.assertNotIn("continue-on-error", self.provision)
        self.assertNotIn("continue-on-error", self.job)
        self.assertNotIn("env", self.provision,
                         "Dependency setup must not repair inherited workspace inputs")

    def test_setup_uses_the_checked_out_packaging_owner_before_packaging(self):
        checkout = next(step for step in self.steps
                        if step.get("with", {}).get("repository") == "emulebb/emulebb-build")
        self.assertEqual(checkout["with"]["ref"], "${{ env.EMULEBB_BUILD_REF }}")
        self.assertRegex(self.workflow["env"]["EMULEBB_BUILD_REF"], r"^[0-9a-f]{40}$")
        self.assertEqual(self.provision["working-directory"], checkout["with"]["path"])
        provision_index = self.steps.index(self.provision)
        self.assertLess(self.steps.index(checkout), provision_index)
        self.assertTrue(any("pip install" in step.get("run", "")
                            and "click==8.4.1" in step["run"] for step in self.steps[:provision_index]))
        appimage = next(step for step in self.steps if step.get("name") == "Install verified AppImage builder")
        package = next(step for step in self.steps if "package-emulebb-rust-ci" in step.get("run", ""))
        self.assertLess(provision_index, self.steps.index(appimage))
        self.assertLess(provision_index, self.steps.index(package))
        self.assertIs(self.workflow["jobs"]["optional-macos-package"]["steps"], self.steps)

    def test_provisioning_evidence_is_retained_even_if_packaging_fails(self):
        diagnostics = next(step for step in self.steps if step.get("name") == "Retain build diagnostics")
        self.assertEqual(diagnostics["if"], "always()")
        self.assertIn("${{ runner.temp }}/emulebb-rust-out/reports/native-linux-provisioning.json",
                      diagnostics["with"]["path"])
        self.assertIn("${{ runner.temp }}/emulebb-rust-out/logs/builds/**/*.log", diagnostics["with"]["path"])

    def test_musl_host_cache_preflight_inherits_an_existing_owned_target(self):
        steps = self.workflow["jobs"]["musl-package"]["steps"]
        package = next(step for step in steps
                       if "package-emulebb-rust-linux-ci" in step.get("run", ""))
        prepare = next(step for step in steps
                       if step.get("name") == "Prepare inherited host Cargo target for the source-cache fence")
        target = "${{ runner.temp }}/emulebb-rust-out/builds/rust/target"
        self.assertEqual(package["env"]["CARGO_TARGET_DIR"], target)
        self.assertEqual(prepare["env"]["CARGO_TARGET_DIR"], target)
        self.assertIn("Path(os.environ['CARGO_TARGET_DIR']).mkdir(parents=True, exist_ok=True)", prepare["run"])
        self.assertLess(steps.index(prepare), steps.index(package))
        self.assertEqual(package["env"]["EMULEBB_WORKSPACE_OUTPUT_ROOT"],
                         "${{ runner.temp }}/emulebb-rust-out")


if __name__ == "__main__":
    unittest.main()
