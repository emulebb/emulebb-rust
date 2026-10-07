from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).resolve().parents[1] / "check_rust_client_policy.py"
SPEC = importlib.util.spec_from_file_location("check_rust_client_policy", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class TestBehaviorAuthority(unittest.TestCase):
    def test_accepts_stock_wire_and_mfc_operational_authority(self) -> None:
        policy = {"behavior_authority": dict(CHECKER.EXPECTED_BEHAVIOR_AUTHORITY)}

        self.assertEqual(CHECKER.check_behavior_authority(policy), [])

    def test_rejects_missing_or_changed_authority(self) -> None:
        policy = {
            "behavior_authority": {
                **CHECKER.EXPECTED_BEHAVIOR_AUTHORITY,
                "operational_limits": "stock-community-emule",
                "extra": "unsupported",
            }
        }
        del policy["behavior_authority"]["io_behavior"]

        errors = CHECKER.check_behavior_authority(policy)

        self.assertTrue(any("operational_limits" in error for error in errors))
        self.assertTrue(any("io_behavior" in error for error in errors))
        self.assertTrue(any("unsupported fields: extra" in error for error in errors))


class TestMaintainabilityAdvisories(unittest.TestCase):
    def test_toolchain_version_matches_workspace_minor(self) -> None:
        self.assertTrue(CHECKER.toolchain_versions_match("1.97.0", "1.97"))
        self.assertFalse(CHECKER.toolchain_versions_match("stable", "1.97"))
        self.assertFalse(CHECKER.toolchain_versions_match("1.96.1", "1.97"))

    def test_test_path_classification_covers_supported_layouts(self) -> None:
        self.assertTrue(CHECKER.is_test_path("crates/example/tests/scenario.rs"))
        self.assertTrue(CHECKER.is_test_path("crates/example/src/tests.rs"))
        self.assertTrue(CHECKER.is_test_path("crates/example/src/codec_tests.rs"))
        self.assertFalse(CHECKER.is_test_path("crates/example/src/codec.rs"))

    def test_inline_test_module_counts_only_braced_inline_modules(self) -> None:
        text = """\
fn production() {}

#[cfg(test)]
mod external_tests;

#[cfg(test)]
mod tests {
    #[test]
    fn works() {
        assert!(true);
    }
}
"""
        self.assertEqual(CHECKER.inline_test_module_line_counts(text), [7])

    def test_ranked_advisories_are_non_mutating_and_limited(self) -> None:
        files = [(f"src/file_{index}.rs", index) for index in range(10)]
        advisories = CHECKER.ranked_file_advisories("production", files)
        self.assertEqual(len(advisories), CHECKER.LARGEST_FILES_REPORTED_PER_KIND)
        self.assertIn("src/file_9.rs (9 lines)", advisories[0])

    def test_changed_files_are_prioritized_and_limited(self) -> None:
        files = [(f"src/file_{index}.rs", index) for index in range(25)]
        changed = {path for path, _ in files}
        advisories = CHECKER.changed_file_advisories("production", files, changed)
        self.assertEqual(len(advisories), CHECKER.CHANGED_FILES_REPORTED)
        self.assertIn("changed production file: src/file_24.rs", advisories[0])


class TestLintSuppressions(unittest.TestCase):
    def test_rejects_direct_and_conditional_broad_allows(self) -> None:
        self.assertTrue(CHECKER.contains_permanent_lint_allow("#[allow(dead_code)]"))
        self.assertTrue(
            CHECKER.contains_permanent_lint_allow(
                '#![cfg_attr(not(feature = "trace"), allow(dead_code, unused_imports))]'
            )
        )

    def test_accepts_reasoned_expectations_and_unrelated_allows(self) -> None:
        self.assertFalse(
            CHECKER.contains_permanent_lint_allow(
                '#[expect(dead_code, reason = "feature-disabled seam")]'
            )
        )
        self.assertFalse(CHECKER.contains_permanent_lint_allow("#[allow(non_snake_case)]"))


class TestCurrentOnlyMetadataSchema(unittest.TestCase):
    def test_forbids_retired_nat_settings_repair_bridge(self) -> None:
        self.assertEqual(
            CHECKER.FORBIDDEN_RUST_NATIVE_SURFACE["reset_legacy_nat_backend_order"],
            "retired NAT settings repair bridge",
        )

    def test_rejects_rust_side_schema_repair_patterns(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/store.rs": """
fn reset_schema(&mut self) {}
fn open() {
    self.reset_schema()?;
    tx.execute_batch("DROP TABLE old");
    tx.execute_batch("ALTER TABLE files ADD COLUMN old INTEGER");
}
""",
            }
        )

        self.assertGreaterEqual(len(errors), 4)
        self.assertTrue(any("reset helper" in error for error in errors))
        self.assertTrue(any("fresh profile" in error for error in errors))
        self.assertTrue(any("ALTER TABLE" in error for error in errors))
        self.assertFalse(any("Python" in error for error in errors))

    def test_rejects_retired_recursive_schema_field(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/schema.sql": """
CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    recursive INTEGER NOT NULL DEFAULT 0
);
""",
            }
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("shared_directory_roots.recursive", errors[0])

    def test_accepts_current_schema_open_path(self) -> None:
        errors = CHECKER.check_current_only_metadata_schema(
            {
                "crates/emulebb-metadata/src/store.rs": """
fn ensure_schema(&mut self) -> Result<()> {
    ensure!(stored_version == SCHEMA_VERSION, "not current");
    Ok(())
}
""",
                "crates/emulebb-metadata/src/schema.sql": """
CREATE TABLE shared_directory_roots (
    id INTEGER PRIMARY KEY,
    path_id INTEGER NOT NULL
);
""",
            }
        )

        self.assertEqual(errors, [])


class TestActionPins(unittest.TestCase):
    def test_accepts_only_full_lowercase_commit_ids(self) -> None:
        self.assertTrue(CHECKER.action_ref_is_immutable("a" * 40))
        self.assertFalse(CHECKER.action_ref_is_immutable("v4"))
        self.assertFalse(CHECKER.action_ref_is_immutable("A" * 40))
        self.assertFalse(CHECKER.action_ref_is_immutable("a" * 39))


class TestSecurityPolicy(unittest.TestCase):
    def test_current_security_policy_has_private_intake_and_support_boundary(self) -> None:
        self.assertEqual(CHECKER.check_security_policy(), [])

    def test_rejects_public_or_ambiguous_security_intake(self) -> None:
        errors = CHECKER.check_security_policy("Report security bugs in an issue.\n")

        self.assertEqual(len(errors), 6)
        self.assertTrue(any("private vulnerability" in error for error in errors))
        self.assertTrue(any("response boundary" in error for error in errors))
        self.assertTrue(any("supported beta" in error for error in errors))


class TestDependencyUpdateCoverage(unittest.TestCase):
    def test_current_dependabot_covers_every_dependency_authority(self) -> None:
        self.assertEqual(CHECKER.check_dependency_update_coverage(), [])

    def test_rejects_missing_ecosystem_directories(self) -> None:
        errors = CHECKER.check_dependency_update_coverage(
            "  - package-ecosystem: cargo\n    directory: /\n"
        )

        self.assertEqual(len(errors), 4)
        self.assertTrue(any("cargo dependencies in /fuzz" in error for error in errors))
        self.assertTrue(any("npm dependencies in /webui" in error for error in errors))
        self.assertTrue(any("docker dependencies" in error for error in errors))


class TestCodeScanningCi(unittest.TestCase):
    def test_current_workflow_scans_release_relevant_sources(self) -> None:
        self.assertEqual(CHECKER.check_code_scanning_ci(), [])

    def test_rejects_missing_languages_permissions_and_immutable_actions(self) -> None:
        workflow = """
schedule:
workflow_dispatch:
security-events: read
- language: rust
  build-mode: autobuild
uses: github/codeql-action/init@v4
uses: github/codeql-action/analyze@v4
"""

        errors = CHECKER.check_code_scanning_ci(workflow)

        self.assertEqual(len(errors), 9)
        self.assertTrue(any("security event upload permission" in error for error in errors))
        self.assertTrue(any("stable per-language check name" in error for error in errors))
        self.assertTrue(any("actions with build-mode none" in error for error in errors))
        self.assertTrue(any("rust with build-mode none" in error for error in errors))
        self.assertTrue(any("full commit SHA" in error for error in errors))

    def test_rejects_mixed_codeql_action_revisions(self) -> None:
        workflow = f"""
schedule:
workflow_dispatch:
security-events: write
name: CodeQL (${{{{ matrix.language }}}})
queries: security-extended
category: /language:${{{{ matrix.language }}}}
- language: actions
  build-mode: none
- language: javascript-typescript
  build-mode: none
- language: python
  build-mode: none
- language: rust
  build-mode: none
uses: github/codeql-action/init@{'a' * 40}
uses: github/codeql-action/analyze@{'b' * 40}
"""

        errors = CHECKER.check_code_scanning_ci(workflow)

        self.assertEqual(
            errors,
            [".github/workflows/codeql.yml must use one CodeQL action revision"],
        )


class TestWorkflowLintCi(unittest.TestCase):
    def test_current_ci_lints_workflows(self) -> None:
        self.assertEqual(CHECKER.check_workflow_lint_ci(), [])

    def test_accepts_immutable_workflow_tooling(self) -> None:
        workflow = f"""
workflow-lint:
  name: GitHub Actions workflow lint
  uses: actions/setup-go@{'a' * 40}
  go-version: "1.27.1"
  cache: false
  run: go run github.com/rhysd/actionlint/cmd/actionlint@{'b' * 40}
"""

        self.assertEqual(CHECKER.check_workflow_lint_ci(workflow), [])

    def test_rejects_missing_job_and_mutable_tooling(self) -> None:
        workflow = """
uses: actions/setup-go@v7
run: go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
"""

        errors = CHECKER.check_workflow_lint_ci(workflow)

        self.assertEqual(len(errors), 6)
        self.assertTrue(any("workflow lint job" in error for error in errors))
        self.assertTrue(any("setup-go" in error for error in errors))
        self.assertTrue(any("actionlint" in error for error in errors))


class TestRequiredCiGates(unittest.TestCase):
    def test_current_workflows_expose_stable_aggregate_checks(self) -> None:
        self.assertEqual(CHECKER.check_required_ci_gates(), [])

    def test_rejects_incomplete_aggregate_checks(self) -> None:
        errors = CHECKER.check_required_ci_gates("jobs: {}\n", "jobs: {}\n")

        self.assertEqual(len(errors), 9)
        self.assertTrue(any("complete CI aggregate dependency" in error for error in errors))
        self.assertTrue(any("complete CodeQL matrix dependency" in error for error in errors))


class TestDefaultBranchPolicy(unittest.TestCase):
    def test_current_policy_is_single_maintainer_safe_and_fail_closed(self) -> None:
        self.assertEqual(CHECKER.check_default_branch_policy(), [])

    def test_rejects_ruleset_drift_and_undocumented_break_glass(self) -> None:
        errors = CHECKER.check_default_branch_policy("{}\n", "policy\n")

        self.assertEqual(len(errors), 7)
        self.assertTrue(any("no-bypass" in error for error in errors))
        self.assertTrue(any("break-glass" in error for error in errors))


class TestWorkflowJobTimeouts(unittest.TestCase):
    def test_current_workflows_bound_every_runnable_job(self) -> None:
        self.assertEqual(CHECKER.check_workflow_job_timeouts(), [])

    def test_rejects_missing_timeout_budgets(self) -> None:
        incomplete = {
            filename: "jobs: {}\n"
            for filename in (
                "ci.yml",
                "codeql.yml",
                "fuzz.yml",
                "nightly.yml",
                "release.yml",
            )
        }

        errors = CHECKER.check_workflow_job_timeouts(incomplete)

        self.assertEqual(len(errors), 19)
        self.assertTrue(any("ci.yml job build-test" in error for error in errors))
        self.assertTrue(any("release.yml job publish-native" in error for error in errors))


class TestCiLinuxRunnerPin(unittest.TestCase):
    def test_current_ci_pins_linux_runners(self) -> None:
        self.assertEqual(CHECKER.check_ci_linux_runner_pin(), [])

    def test_rejects_mutable_or_incomplete_linux_runner_pins(self) -> None:
        workflow = "ubuntu-latest\nubuntu-24.04\n"

        self.assertEqual(len(CHECKER.check_ci_linux_runner_pin(workflow)), 2)


class TestScheduledFuzzCi(unittest.TestCase):
    def test_current_ci_fuzzes_all_protocol_parsers(self) -> None:
        self.assertEqual(CHECKER.check_scheduled_fuzz_ci(), [])

    def test_rejects_missing_schedule_targets_and_bounds(self) -> None:
        errors = CHECKER.check_scheduled_fuzz_ci("name: incomplete fuzzing\n")

        self.assertGreaterEqual(len(errors), 18)
        self.assertTrue(any("weekly schedule" in error for error in errors))
        self.assertTrue(any("ed2k_server_parsers" in error for error in errors))
        self.assertTrue(any("kad_packet_parser" in error for error in errors))
        self.assertTrue(any("native source revisions" in error for error in errors))


class TestLiveRestOpenApiCi(unittest.TestCase):
    def test_current_workflow_keeps_live_openapi_gate(self) -> None:
        self.assertEqual(CHECKER.check_live_rest_openapi_ci(), [])

    def test_accepts_tested_artifact_and_pinned_support_repositories(self) -> None:
        workflow = f"""
rest-openapi:
  needs: build-test
  EMULEBB_WORKSPACE_OUTPUT_ROOT: ${{{{ runner.temp }}}}/emulebb-rust-out
  repository: emulebb/emulebb-build-tests
  ref: {'a' * 40}
  repository: emulebb/emulebb-tooling
  ref: {'b' * 40}
  name: emulebb-rust-Linux-X64-${{{{ github.sha }}}}
  run: python scripts/rust-rest-openapi-ci.py
  name: rust-rest-openapi-${{{{ github.sha }}}}
"""
        self.assertEqual(CHECKER.check_live_rest_openapi_ci(workflow), [])

    def test_rejects_missing_gate_and_mutable_support_refs(self) -> None:
        workflow = """
repository: emulebb/emulebb-build-tests
ref: main
repository: emulebb/emulebb-tooling
ref: main
"""
        errors = CHECKER.check_live_rest_openapi_ci(workflow)

        self.assertGreaterEqual(len(errors), 8)
        self.assertTrue(any("live REST/OpenAPI job" in error for error in errors))
        self.assertTrue(any("must pin emulebb/emulebb-build-tests" in error for error in errors))


class TestReleaseCiGate(unittest.TestCase):
    def test_current_workflow_requires_all_green_source_checks(self) -> None:
        self.assertEqual(CHECKER.check_release_ci_gate(), [])

    def test_rejects_release_packaging_without_exact_source_gate(self) -> None:
        errors = CHECKER.check_release_ci_gate(
            "native-package:\n  runs-on: ubuntu-latest\n",
            "  package:\n    permissions:\n      checks: read\n",
        )

        self.assertEqual(len(errors), 6)
        self.assertTrue(any("source-check verification job" in error for error in errors))
        self.assertTrue(any("packaging dependency" in error for error in errors))

    def test_rejects_nightly_caller_without_check_permission(self) -> None:
        errors = CHECKER.check_release_ci_gate(
            nightly_text="  package:\n    permissions:\n      contents: write\n"
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("nightly.yml", errors[0])

    def test_rejects_source_gate_without_stable_aggregate_checks(self) -> None:
        errors = CHECKER.check_release_ci_gate(helper_text="REQUIRED_SOURCE_CHECKS = ()\n")

        self.assertEqual(len(errors), 2)
        self.assertTrue(any("Required CI" in error for error in errors))
        self.assertTrue(any("Required CodeQL" in error for error in errors))


class TestNightlyCoordination(unittest.TestCase):
    def test_current_workflow_selects_one_daily_green_main_nightly(self) -> None:
        self.assertEqual(CHECKER.check_nightly_coordination(), [])

    def test_rejects_unwired_or_unbounded_nightly_coordination(self) -> None:
        errors = CHECKER.check_nightly_coordination(
            workflow_text="name: Nightly\n",
            helper_text="def metadata(): pass\n",
        )

        self.assertEqual(len(errors), 7)
        self.assertTrue(any("latest-green-main" in error for error in errors))
        self.assertTrue(any("daily publication guard" in error for error in errors))


class TestReleaseImagePromotion(unittest.TestCase):
    def test_current_workflow_promotes_smoke_tested_archive(self) -> None:
        self.assertEqual(CHECKER.check_release_image_promotion(), [])

    def test_rejects_rebuilding_the_image_for_publication(self) -> None:
        workflow = f"""
  publish-image:
    steps:
      - uses: regclient/actions/regctl-installer@{'a' * 40}
        with:
          release: v0.11.6
      - run: python -m emule_workspace package-emulebb-rust-image-ci --push
      - uses: docker/setup-buildx-action@{'b' * 40}
      - with:
          pattern: emulebb-rust-package-*
"""

        errors = CHECKER.check_release_image_promotion(workflow)

        self.assertGreaterEqual(len(errors), 7)
        self.assertTrue(any("exact OCI archive import" in error for error in errors))
        self.assertTrue(any("rebuilds the image" in error for error in errors))

    def test_rejects_mutable_registry_client_action_ref(self) -> None:
        workflow = """
  publish-image:
    steps:
      - name: Download image
        with:
          name: emulebb-rust-image-candidate
      - uses: regclient/actions/regctl-installer@v0
        with:
          release: v0.11.6
      - run: |
          regctl image import "$VERSIONED_IMAGE" "$OCI_ARCHIVE"
          regctl image copy "$VERSIONED_IMAGE" "$CHANNEL_IMAGE"
          regctl image digest "$CHANNEL_IMAGE"
"""

        errors = CHECKER.check_release_image_promotion(workflow)

        self.assertTrue(any("full commit SHA" in error for error in errors))

    def test_rejects_release_assets_that_are_not_draft_first_and_write_once(self) -> None:
        workflow = (CHECKER.ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        workflow = workflow.replace("          draft: true\n", "          draft: false\n", 1)
        workflow = workflow.replace(
            "          overwrite_files: false\n",
            "          overwrite_files: true\n",
            1,
        )

        errors = CHECKER.check_release_image_promotion(workflow)

        self.assertTrue(any("draft-first" in error for error in errors))
        self.assertTrue(any("write-once" in error for error in errors))

    def test_rejects_advancing_channel_before_release(self) -> None:
        workflow = (CHECKER.ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        workflow = workflow.replace(
            "  publish-native:\n",
            '      - run: regctl image copy "$VERSIONED_IMAGE" "$CHANNEL_IMAGE"\n\n'
            "  publish-native:\n",
            1,
        )

        errors = CHECKER.check_release_image_promotion(workflow)

        self.assertTrue(any("before the GitHub release" in error for error in errors))

    def test_rejects_fatal_post_publication_cleanup(self) -> None:
        workflow = (CHECKER.ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        ).replace("        continue-on-error: true\n", "        continue-on-error: false\n", 1)

        errors = CHECKER.check_release_image_promotion(workflow)

        self.assertTrue(any("non-fatal retention cleanup" in error for error in errors))


class TestReleaseImageSecurity(unittest.TestCase):
    def test_current_release_image_is_pinned_inventoried_and_scanned(self) -> None:
        self.assertEqual(CHECKER.check_release_image_security(), [])

    def test_rejects_mutable_unscanned_image(self) -> None:
        errors = CHECKER.check_release_image_security(
            "  image-candidate:\n    steps: []\n  publish-native:\n    steps: []\n",
            "FROM lscr.io/linuxserver/baseimage-ubuntu:noble\n",
            "version: 2\nupdates: []\n",
        )

        self.assertGreaterEqual(len(errors), 13)
        self.assertTrue(any("SPDX JSON" in error for error in errors))
        self.assertTrue(any("high and critical" in error for error in errors))
        self.assertTrue(any("pin the LinuxServer" in error for error in errors))
        self.assertTrue(any("dependabot" in error.lower() for error in errors))

    def test_rejects_mutable_trivy_installer(self) -> None:
        workflow = """
  image-candidate:
    steps:
      - uses: aquasecurity/setup-trivy@v0.3.1
        with:
          version: v0.75.0
      - run: |
          trivy image --image-src docker --platform "$platform" --format spdx-json "$IMAGE"
          trivy image --image-src docker --platform "$platform" --scanners vuln \
            --ignore-unfixed --severity HIGH,CRITICAL --exit-code 1 "$IMAGE"
      - with:
          name: emulebb-rust-image-security
  publish-native:
    steps:
      - with:
          name: emulebb-rust-image-security
"""

        errors = CHECKER.check_release_image_security(
            workflow,
            f"FROM lscr.io/linuxserver/baseimage-ubuntu:noble@sha256:{'a' * 64}\n",
            "- package-ecosystem: docker\n  directory: /packaging/docker\n",
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("full commit SHA", errors[0])


class TestContainerHealthContract(unittest.TestCase):
    def test_current_container_has_bounded_readiness_probe(self) -> None:
        self.assertEqual(CHECKER.check_container_health_contract(), [])

    def test_rejects_authenticated_or_unbounded_probe(self) -> None:
        errors = CHECKER.check_container_health_contract("", "", "")

        self.assertEqual(len(errors), 9)
        self.assertTrue(any("outside API-key" in error for error in errors))
        self.assertTrue(any("bounded Docker" in error for error in errors))
        self.assertTrue(any("loopback-only" in error for error in errors))


class TestReleaseBuildIdentity(unittest.TestCase):
    def test_current_workflow_injects_exact_runtime_identity(self) -> None:
        self.assertEqual(CHECKER.check_release_build_identity(), [])

    def test_rejects_release_without_runtime_identity(self) -> None:
        errors = CHECKER.check_release_build_identity("jobs: {}\n")

        self.assertEqual(len(errors), 10)
        self.assertTrue(any("distribution version" in error for error in errors))
        self.assertTrue(any("source revision" in error for error in errors))

    def test_rejects_hardcoded_release_version_fallback(self) -> None:
        workflow = (CHECKER.ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        ).replace(
            "env:\n",
            "env:\n  RELEASE_VERSION: ${{ inputs.release_version || '0.1.0-beta.2' }}\n",
            1,
        )

        errors = CHECKER.check_release_build_identity(workflow)

        self.assertEqual(len(errors), 1)
        self.assertIn("hardcoded release-version fallback", errors[0])


class TestOmissionRegistry(unittest.TestCase):
    def test_active_registry_rejects_fixed_entries(self) -> None:
        policy = {"protocol": {"omission_registry": "policy/rust-client-omissions.toml"}}
        omissions = {
            "omissions": [
                {
                    "id": "already-fixed",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "done",
                    "compatibility": "compatible",
                    "disposition": "fixed",
                    "owner": "core-protocol",
                    "target": "implemented",
                    "beta_blocker": False,
                }
            ]
        }

        errors = CHECKER.check_omission_registry(policy, omissions)

        self.assertTrue(any("unsupported disposition: fixed" in error for error in errors))

    def test_active_registry_rejects_contradictory_review_disposition(self) -> None:
        policy = {"protocol": {"omission_registry": "policy/rust-client-omissions.toml"}}
        omissions = {
            "omissions": [
                {
                    "id": "preview",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "drop",
                    "compatibility": "compatible",
                    "disposition": "protocol_drop_approved",
                    "review_disposition": "defer",
                    "owner": "operator",
                    "target": "beta",
                    "beta_blocker": False,
                }
            ]
        }

        errors = CHECKER.check_omission_registry(policy, omissions)

        self.assertTrue(any("contradicts disposition" in error for error in errors))

    def test_resolved_history_rejects_active_overlap(self) -> None:
        omissions = {
            "omissions": [
                {
                    "id": "same-id",
                    "area": "ed2k",
                    "stock_behavior": "stock",
                    "rust_behavior": "rust",
                    "reason": "defer",
                    "compatibility": "compatible",
                    "disposition": "protocol_defer",
                    "owner": "core-protocol",
                    "target": "post-beta",
                    "beta_blocker": False,
                }
            ]
        }
        history = {
            "resolved_omissions": [
                {
                    "id": "same-id",
                    "disposition": "fixed",
                }
            ]
        }

        errors = CHECKER.check_omission_history(omissions, history)

        self.assertTrue(any("also appears in active registry" in error for error in errors))


class TestReleaseOutputPaths(unittest.TestCase):
    def test_current_workflow_keeps_release_outputs_external(self) -> None:
        self.assertEqual(CHECKER.check_release_output_paths(), [])

    def test_accepts_external_release_paths(self) -> None:
        workflow = """
EMULEBB_WORKSPACE_ROOT: ${{ github.workspace }}
EMULEBB_WORKSPACE_OUTPUT_ROOT: ${{ runner.temp }}/emulebb-rust-out
CARGO_TARGET_DIR: ${{ runner.temp }}/emulebb-rust-out/builds/rust/target
path: .ci/emulebb-tooling
working-directory: .ci/emulebb-build
package-emulebb-rust-ci --release-version 0.1.0-beta.2 --target-os ${{ matrix.os }} --platform ${{ matrix.arch }}
smoke-rust-release-package.py
smoke-rust-container.py
path: ${{ runner.temp }}/emulebb-rust-out/release/rust-v0.1.0-beta.2
assemble-emulebb-rust-release-ci
RELEASE-${RELEASE_VERSION}-NOTES.md
RELEASE-${RELEASE_VERSION}-CHANGELOG.md
body_path: ${{ inputs.channel == 'nightly' && 'nightly-release-notes.md' || 'release-notes.md' }}
"""
        self.assertEqual(CHECKER.check_release_output_paths(workflow), [])

    def test_reports_in_checkout_release_paths(self) -> None:
        errors = CHECKER.check_release_output_paths(
            "python tools/package_release_zip.py --target-dir target/release --out dist"
        )
        self.assertEqual(len(errors), 14)


if __name__ == "__main__":
    unittest.main()
