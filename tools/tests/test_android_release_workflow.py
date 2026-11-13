"""Android developer artifacts extend nightly without replacing native proofs."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import check_rust_client_policy as POLICY
import release_publish as PUBLISH


class AndroidReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.workflow = yaml.safe_load(self.text)
        self.jobs = self.workflow["jobs"]

    def test_current_android_release_graph_passes_policy(self):
        self.assertEqual(POLICY.check_release_android_packages(self.text), [])

    def test_each_failed_prerequisite_remains_blocking_and_nightly_skip_is_not_success(self):
        # Mutate the actual workflow condition, rather than simulate an Actions runner.
        condition = self.jobs["assemble-candidate"]["if"]
        mutations = [condition.replace(f"needs.{job}.result == 'success'", "true", 1)
                     for job in ("prepare", "native-package-smoke", "musl-package",
                                 "image-native-validation", "android-package", "android-apk-package", "android-apk-qualification")]
        mutations.extend((condition.replace("inputs.channel != 'nightly' && ", ""),
                          condition.replace("!cancelled()", "always()"),
                          condition.replace("'skipped'", "'failure'")))
        for mutated in mutations:
            with self.subTest(condition=mutated):
                workflow = deepcopy(self.workflow)
                workflow["jobs"]["assemble-candidate"]["if"] = mutated
                self.assertTrue(POLICY.check_release_android_packages(yaml.safe_dump(workflow)))

    def test_apk_api_and_authority_mutations_are_rejected(self):
        for mutation in ("api", "source", "certificate", "version", "reader", "authority", "waiver"):
            workflow = deepcopy(self.workflow)
            job = workflow["jobs"]["android-apk-qualification"]
            step = next(step for step in job["steps"] if "qualify-rust-android-apk-ci" in step.get("run", ""))
            if mutation == "api":
                job["strategy"]["matrix"]["image"].pop()
            elif mutation == "source":
                step["env"]["EXPECTED_SOURCE_SHA"] = "${{ github.sha }}"
            elif mutation == "certificate":
                step["run"] = step["run"].replace('--expected-cert-sha256 "$EMULEBB_ANDROID_SIGNER_SHA256"', "")
            elif mutation == "version":
                job["env"]["EMULEBB_ANDROID_VERSION_CODE"] = "${{ github.run_number }}"
            elif mutation == "reader":
                reader = next(step for step in workflow["jobs"]["assemble-candidate"]["steps"]
                              if step.get("with", {}).get("path") == "emulebb-build")
                reader["with"]["ref"] = "${{ env.EMULEBB_BUILD_REF }}"
            elif mutation == "authority":
                workflow["env"].pop("EMULEBB_APK_BUILD_REF")
            else:
                job["continue-on-error"] = True
            with self.subTest(mutation=mutation):
                self.assertTrue(POLICY.check_release_android_packages(yaml.safe_dump(workflow)))

    def test_source_identity_and_exact_two_abis_cannot_be_removed(self):
        for mutation in ("source", "abi", "gate", "step-waiver", "job-waiver"):
            workflow = deepcopy(self.workflow)
            job = workflow["jobs"]["android-package"]
            if mutation == "source":
                step = next(step for step in job["steps"] if "package-rust-android-ci" in step.get("run", ""))
                step["env"]["EXPECTED_SOURCE_SHA"] = "${{ github.sha }}"
            elif mutation == "abi":
                job["strategy"]["matrix"]["abi"].pop()
            elif mutation == "gate":
                job["needs"].remove("verify-source")
            elif mutation == "step-waiver":
                job["steps"][0]["continue-on-error"] = True
            elif mutation == "authority":
                workflow["env"].pop("EMULEBB_APK_BUILD_REF")
            else:
                job["continue-on-error"] = True
            with self.subTest(mutation=mutation):
                self.assertTrue(POLICY.check_release_android_packages(yaml.safe_dump(workflow)))

    def test_only_four_public_files_per_abi_flow_into_unified_candidate(self):
        job = self.jobs["android-package"]
        upload = next(step for step in job["steps"]
                      if step.get("with", {}).get("name") == "emulebb-rust-android-developer-payload-${{ matrix.abi }}")
        paths = upload["with"]["path"].splitlines()
        self.assertEqual(len(paths), 4)
        self.assertEqual({Path(path).name for path in paths},
                         {"*.tar.zst", "*.manifest.json", "*.sbom.spdx.json", "*-compile-elf.json"})
        self.assertTrue(all("/packages/rust-android/${{ env.RELEASE_VERSION }}/${{ matrix.abi }}/" in path
                            for path in paths))
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertNotIn("SHA256SUMS", upload["with"]["path"])
        steps = self.jobs["assemble-candidate"]["steps"]
        download = next(step for step in steps if step.get("with", {}).get("pattern") ==
                        "emulebb-rust-android-developer-payload-*")
        checksum = next(step for step in steps if "assemble-emulebb-rust-release-ci" in step.get("run", ""))
        manifest = next(step for step in steps if "candidate-manifest" in step.get("run", ""))
        self.assertLess(steps.index(download), steps.index(checksum))
        self.assertLess(steps.index(checksum), steps.index(manifest))
        self.assertEqual(download["with"]["path"],
                         "${{ runner.temp }}/emulebb-rust-out/release/rust-v${{ env.RELEASE_VERSION }}")

    def test_existing_native_musl_and_oci_proofs_keep_full_inventory(self):
        self.assertEqual(len(PUBLISH.native_matrix("full")), 6)
        for job in ("native-package", "native-package-smoke"):
            self.assertEqual(self.jobs[job]["strategy"]["matrix"]["include"],
                             "${{ fromJSON(needs.prepare.outputs.native_matrix) }}")
        self.assertEqual({row["architecture"] for row in self.jobs["musl-package"]["strategy"]["matrix"]["include"]},
                         {"amd64", "arm64"})
        self.assertEqual(self.jobs["image-candidate"]["strategy"]["matrix"]["variant"], ["ubuntu", "alpine"])
        images = self.jobs["image-native-validation"]["strategy"]["matrix"]
        self.assertEqual(images["variant"], ["ubuntu", "alpine"])
        self.assertEqual({row["architecture"] for row in images["include"]}, {"amd64", "arm64"})
        self.assertEqual(self.text.count("smoke-rust-release-package.py"), 1)
        smoke = next(step["run"] for step in self.jobs["native-package-smoke"]["steps"]
                     if "smoke-rust-release-package.py" in step.get("run", ""))
        self.assertIn('--expected-channel "${{ env.RELEASE_CHANNEL }}"', smoke)
        self.assertIn('--expected-source-sha "${{ needs.prepare.outputs.source_sha }}"', smoke)
        self.assertIs(self.jobs["native-package-smoke"]["steps"], self.jobs["optional-macos-smoke"]["steps"])
        self.assertNotIn("package-smoke", str(self.jobs["android-package"]))

    def test_profile_ownership_proof_is_selected_only_for_windows_and_linux(self):
        step = next(step for step in self.jobs["native-package-smoke"]["steps"]
                    if "smoke-rust-release-package.py" in step.get("run", ""))
        self.assertIn("${{ matrix.os != 'macos' && '--verify-profile-ownership' || '' }}", step["run"])
        self.assertEqual(step["env"]["EMULEBB_WORKSPACE_ROOT"], "${{ github.workspace }}")
        self.assertEqual(step["env"]["EMULEBB_WORKSPACE_OUTPUT_ROOT"],
                         "${{ runner.temp }}/emulebb-rust-out")
        self.assertIn('--expected-channel "${{ env.RELEASE_CHANNEL }}"', step["run"])
        self.assertNotIn('$RELEASE_CHANNEL', step["run"],
                         "Native smoke also runs under PowerShell, which uses different environment syntax")

    def test_android_uses_pinned_frontend_and_compiler_recipe_inputs(self):
        job = self.jobs["android-package"]
        steps = job["steps"]
        self.assertEqual(steps[0]["with"]["ref"], "${{ github.workflow_sha }}")
        node = next(step for step in steps if step.get("uses", "").startswith("actions/setup-node@"))
        self.assertEqual(node["with"]["node-version"], "26.13.0")
        self.assertTrue(any(step.get("run") == "npm install --global npm@11.20.0" for step in steps))
        checkout = {step["with"]["repository"]: step["with"]["ref"] for step in steps
                    if "repository" in step.get("with", {})}
        self.assertEqual(checkout["emulebb/emulebb-build"], "${{ env.EMULEBB_BUILD_REF }}")
        self.assertEqual(checkout["emulebb/emulebb-tooling"], "${{ env.EMULEBB_TOOLING_REF }}")
        self.assertEqual(checkout["emulebb/emulebb-miniupnp"], "${{ env.MINIUPNP_REF }}")
        self.assertEqual(checkout["emulebb/emulebb-libpcpnatpmp"], "${{ env.PCPNATPMP_REF }}")


if __name__ == "__main__":
    unittest.main()
