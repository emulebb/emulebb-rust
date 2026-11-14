"""Keep original-byte diagnostic replay isolated from the Nightly release graph."""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
FIELDS = ("diagnostic_run_id", "diagnostic_source_sha", "diagnostic_manifest_sha256", "diagnostic_image")
VALID = dict(zip(FIELDS, ("43524927475", "a" * 40, "b" * 64, "apk34")))


def evaluate(expression, values, event="workflow_dispatch"):
    """Evaluate only the boolean/string subset used by the actual routing guards."""
    source = expression.removeprefix("${{").removesuffix("}}").strip()
    source = source.replace("github.event_name", repr(event))
    source = source.replace("github.ref", repr("refs/heads/fix/android-delivery-diagnostics"))
    source = re.sub(r"inputs\.([a-z0-9_]+)", lambda match: repr(values.get(match[1], "")), source)
    source = re.sub(r"!(?!=)", " not ", source).replace("&&", " and ").replace("||", " or ")

    def visit(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not visit(node.operand)
        if isinstance(node, ast.BoolOp):
            result = visit(node.values[0])
            for value in node.values[1:]:
                if (isinstance(node.op, ast.And) and result) or (isinstance(node.op, ast.Or) and not result):
                    result = visit(value)
            return result
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = visit(node.left), visit(node.comparators[0])
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "format":
            template, *arguments = [visit(argument) for argument in node.args]
            return template.format(*arguments)
        raise AssertionError("Unsupported routing expression")

    return visit(ast.parse("(" + source.strip() + ")", mode="eval").body)


def selected(expression, values, event="workflow_dispatch"):
    return bool(evaluate(expression, values, event))


class ApkDiagnosticWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github/workflows/nightly.yml").read_text(encoding="utf-8"))
        self.jobs = self.workflow["jobs"]
        self.diagnostic = self.jobs["apk-diagnostic"]

    def test_absent_inputs_preserve_normal_manual_and_scheduled_nightlies(self):
        for event in ("schedule", "workflow_dispatch"):
            for values in ({}, {"diagnostic_image": "none"}):
                with self.subTest(event=event, values=values):
                    self.assertTrue(selected(self.jobs["prepare"]["if"], values, event))
                    self.assertFalse(selected(self.diagnostic["if"], values, event))
        self.assertEqual(self.jobs["verify-source"]["needs"], "prepare")
        self.assertEqual(self.jobs["package"]["needs"], ["prepare", "verify-source"])
        self.assertEqual(self.jobs["package"]["if"],
                         "${{ needs.prepare.outputs.should_build == 'true' && needs.verify-source.result == 'success' }}")
        self.assertEqual(self.jobs["package"]["uses"], "./.github/workflows/release.yml")

    def test_diagnostics_do_not_hold_the_normal_publication_concurrency_lock(self):
        concurrency = self.workflow["concurrency"]
        self.assertIs(concurrency["cancel-in-progress"], False)
        for event in ("schedule", "workflow_dispatch"):
            for values in ({}, {"diagnostic_image": "none"}, {"publish": True}):
                self.assertEqual(evaluate(concurrency["group"], values, event), "rust-nightly")
        for field in FIELDS:
            self.assertEqual(evaluate(concurrency["group"], {field: VALID[field]}),
                             "rust-nightly-android-diagnostic-refs/heads/fix/android-delivery-diagnostics-" +
                             (VALID[field] if field == "diagnostic_image" else ""))
        self.assertNotEqual(evaluate(concurrency["group"], {**VALID, "diagnostic_image": "apk35"}),
                            evaluate(concurrency["group"], {**VALID, "diagnostic_image": "apk36"}))

    def test_every_diagnostic_field_routes_partial_requests_away_from_publication(self):
        for field in FIELDS:
            for publish in (False, True):
                values = {field: VALID[field], "publish": publish}
                with self.subTest(field=field, publish=publish):
                    self.assertFalse(selected(self.jobs["prepare"]["if"], values))
                    self.assertTrue(selected(self.diagnostic["if"], values))
        self.assertFalse(selected(self.jobs["prepare"]["if"], VALID))
        self.assertTrue(selected(self.diagnostic["if"], VALID))

    def run_guard(self, values, publish="false"):
        first = self.diagnostic["steps"][0]
        self.assertEqual(first["shell"], "python")
        self.assertEqual(first["env"], {
            "DIAGNOSTIC_PUBLISH": "${{ inputs.publish }}", "PRODUCER_RUN_ID": "${{ inputs.diagnostic_run_id }}",
            "PRODUCER_SOURCE_SHA": "${{ inputs.diagnostic_source_sha }}",
            "APK_MANIFEST_SHA256": "${{ inputs.diagnostic_manifest_sha256 }}",
            "DIAGNOSTIC_IMAGE": "${{ inputs.diagnostic_image }}",
        })
        names = {"DIAGNOSTIC_PUBLISH": publish, "PRODUCER_RUN_ID": values.get(FIELDS[0], ""),
                 "PRODUCER_SOURCE_SHA": values.get(FIELDS[1], ""), "APK_MANIFEST_SHA256": values.get(FIELDS[2], ""),
                 "DIAGNOSTIC_IMAGE": values.get(FIELDS[3], "")}
        return subprocess.run([sys.executable, "-c", first["run"]], env={**os.environ, **names},
                              capture_output=True, text=True, timeout=10)

    def test_actual_first_step_rejects_publication_partial_and_malformed_requests(self):
        for api in (34, 35, 36, 37):
            self.assertEqual(self.run_guard({**VALID, FIELDS[3]: f"apk{api}"}).returncode, 0)
        self.assertNotEqual(self.run_guard(VALID, publish="true").returncode, 0)
        for field in FIELDS:
            with self.subTest(missing=field):
                self.assertNotEqual(self.run_guard({key: value for key, value in VALID.items() if key != field}).returncode, 0)
        for field, value in ((FIELDS[0], "0"), (FIELDS[0], "12;echo unsafe"), (FIELDS[1], "refs/heads/main"),
                             (FIELDS[1], "A" * 40), (FIELDS[2], "b" * 63), (FIELDS[3], "none"), (FIELDS[3], "current")):
            with self.subTest(field=field, value=value):
                self.assertNotEqual(self.run_guard({**VALID, field: value}).returncode, 0)

    def test_replay_has_only_read_permissions_and_no_publication_dependency(self):
        self.assertEqual(self.diagnostic["permissions"], {"actions": "read", "contents": "read"})
        self.assertNotIn("needs", self.diagnostic)
        self.assertNotIn("secrets", self.diagnostic)
        self.assertNotIn("uses", self.diagnostic)
        self.assertEqual(set(self.jobs), {"prepare", "verify-source", "package", "apk-diagnostic"})
        for step in self.diagnostic["steps"]:
            self.assertNotIn("continue-on-error", step)
            self.assertNotIn("EMULEBB_ANDROID_KEYSTORE", str(step))
            self.assertNotIn("secrets.", str(step))
        # Existing release jobs depend solely on the original prepare/source gates.
        self.assertNotIn("apk-diagnostic", str(self.jobs["package"]))

    def test_executor_and_original_source_authorities_are_separate(self):
        constants = self.workflow["env"]
        for name in ("EMULEBB_APK_DIAGNOSTIC_BUILD_REF", "EMULEBB_APK_DIAGNOSTIC_HARNESS_REF",
                     "EMULEBB_APK_DIAGNOSTIC_TOOLING_REF", "EMULEBB_APK_DIAGNOSTIC_MINIUPNP_REF",
                     "EMULEBB_APK_DIAGNOSTIC_PCPNATPMP_REF"):
            self.assertRegex(constants[name], r"^[0-9a-f]{40}$")
        self.assertRegex(constants["EMULEBB_APK_DIAGNOSTIC_SIGNER_SHA256"], r"^[0-9a-f]{64}$")
        checkouts = {step["with"]["path"]: step["with"] for step in self.diagnostic["steps"]
                     if step.get("uses", "").startswith("actions/checkout@")}
        self.assertEqual(checkouts[".ci/original-rust"]["ref"], "${{ inputs.diagnostic_source_sha }}")
        self.assertEqual(checkouts[".ci/emulebb-build"]["ref"], "${{ env.EMULEBB_APK_DIAGNOSTIC_BUILD_REF }}")
        self.assertEqual(checkouts[".ci/emulebb-build-tests"]["ref"], "${{ env.EMULEBB_APK_DIAGNOSTIC_HARNESS_REF }}")
        self.assertTrue(all(value["persist-credentials"] is False for value in checkouts.values()))
        replay = next(step for step in self.diagnostic["steps"] if step.get("id") == "replay")
        self.assertIn("diagnose-rust-android-apk-ci", replay["run"])
        for flag in ("--producer-run-id", "--producer-source-sha", "--apk-manifest-sha256", "--image",
                     "--diagnostic-build-ref", "--diagnostic-harness-ref", "--expected-cert-sha256"):
            self.assertIn(flag, replay["run"])
        self.assertEqual(replay["env"]["GH_TOKEN"], "${{ github.token }}")

    def test_retained_evidence_is_only_the_ineligible_outer_public_projection(self):
        upload = self.diagnostic["steps"][-1]
        self.assertTrue(upload["uses"].startswith("actions/upload-artifact@"))
        self.assertEqual(upload["if"], "always()")
        self.assertEqual(upload["with"]["path"],
                         "${{ runner.temp }}/emulebb-rust-out/reports/android-emulator-boot/*/validation.json")
        self.assertIn("diagnostic", upload["with"]["name"])
        self.assertEqual(upload["with"]["if-no-files-found"], "warn")


if __name__ == "__main__":
    unittest.main()
