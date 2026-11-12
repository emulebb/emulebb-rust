from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "webui_workspace.py"
SPEC = importlib.util.spec_from_file_location("webui_workspace", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
WEBUI_WORKSPACE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WEBUI_WORKSPACE
SPEC.loader.exec_module(WEBUI_WORKSPACE)

TEST_SPEC = importlib.util.spec_from_file_location("webui_test_owner", SCRIPT_PATH.with_name("test_webui.py"))
WEBUI_TEST = importlib.util.module_from_spec(TEST_SPEC)
TEST_SPEC.loader.exec_module(WEBUI_TEST)


class TestWebUiExecutionModes(unittest.TestCase):
    def exercise(self, arguments, *, failure=None):
        workspace = SimpleNamespace(dist=Path("synthetic-dist"))
        pinned = Mock()
        with patch.dict(sys.modules, {"ci_environment": SimpleNamespace(prepare_command=pinned)}), \
                patch.object(WEBUI_TEST, "npm_command", return_value="pinned-npm"), \
                patch.object(WEBUI_TEST, "prepare_webui_workspace", return_value=workspace) as stage, \
                patch.object(WEBUI_TEST, "run", side_effect=failure) as run:
            if failure:
                with self.assertRaises(subprocess.CalledProcessError):
                    WEBUI_TEST.main(arguments)
            else:
                self.assertEqual(WEBUI_TEST.main(arguments), 0)
        return pinned, stage, [call.args[0] for call in run.call_args_list]

    def test_default_keeps_complete_test_browser_and_build_sequence(self):
        pinned, stage, commands = self.exercise([])
        pinned.assert_not_called()
        stage.assert_called_once_with("webui-test")
        self.assertEqual(commands, [
            ["pinned-npm", "ci", "--ignore-scripts"],
            ["pinned-npm", "run", "test:unit"],
            ["pinned-npm", "exec", "--", "playwright", "install", "chromium"],
            ["pinned-npm", "run", "test:e2e"],
            ["pinned-npm", "run", "build", "--", "--outDir", "synthetic-dist", "--emptyOutDir"],
        ])

    def test_typecheck_only_uses_separate_stage_pins_and_locked_install(self):
        pinned, stage, commands = self.exercise(["--typecheck-only"])
        pinned.assert_called_once()
        self.assertEqual(pinned.call_args.args[0], [sys.executable, str(SCRIPT_PATH.with_name("test_webui.py"))])
        stage.assert_called_once_with("webui-typecheck")
        self.assertEqual(commands, [["pinned-npm", "ci", "--ignore-scripts"], ["pinned-npm", "run", "typecheck"]])

    def test_failed_install_or_typecheck_cannot_execute_later_work(self):
        for failing in (0, 1):
            with self.subTest(failing=failing):
                failure = [None] * failing + [subprocess.CalledProcessError(1, "synthetic")]
                _, _, commands = self.exercise(["--typecheck-only"], failure=failure)
                self.assertEqual(len(commands), failing + 1)

    def test_tool_mismatch_fails_before_staging_or_install(self):
        with patch.dict(sys.modules, {"ci_environment": SimpleNamespace(
                prepare_command=Mock(side_effect=RuntimeError("pinned tool mismatch")))}), \
                patch.object(WEBUI_TEST, "prepare_webui_workspace") as stage, \
                patch.object(WEBUI_TEST, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "pinned tool mismatch"):
                WEBUI_TEST.main(["--typecheck-only"])
        stage.assert_not_called()
        run.assert_not_called()


class TestWebUiWorkspace(unittest.TestCase):
    def test_stages_source_and_generated_outputs_below_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            workspace_root = temp_root / "workspace"
            repo_root = workspace_root / "repos" / "emulebb-rust"
            webui_root = repo_root / "webui"
            output_root = temp_root / "output"
            webui_root.mkdir(parents=True)
            (webui_root / "package.json").write_text("{}\n", encoding="utf-8")
            for name in WEBUI_WORKSPACE.GENERATED_DIRECTORY_NAMES:
                generated = webui_root / name
                generated.mkdir()
                (generated / "generated.txt").write_text("generated\n", encoding="utf-8")

            original_root = WEBUI_WORKSPACE.ROOT
            original_webui_root = WEBUI_WORKSPACE.WEBUI_ROOT
            WEBUI_WORKSPACE.ROOT = repo_root
            WEBUI_WORKSPACE.WEBUI_ROOT = webui_root
            try:
                staged = WEBUI_WORKSPACE.prepare_webui_workspace(
                    "webui-test",
                    {
                        "EMULEBB_WORKSPACE_ROOT": str(workspace_root),
                        "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output_root),
                    },
                )
            finally:
                WEBUI_WORKSPACE.ROOT = original_root
                WEBUI_WORKSPACE.WEBUI_ROOT = original_webui_root

            self.assertEqual(staged.source, output_root / "builds" / "rust" / "webui-test-source")
            self.assertEqual(staged.dist, output_root / "builds" / "rust" / "webui-test-dist")
            self.assertTrue((staged.source / "package.json").is_file())
            for name in WEBUI_WORKSPACE.GENERATED_DIRECTORY_NAMES:
                self.assertFalse((staged.source / name).exists())
            self.assertEqual(staged.env["NPM_CONFIG_CACHE"], str(output_root / "cache" / "npm"))
            self.assertEqual(
                staged.env["PLAYWRIGHT_BROWSERS_PATH"],
                str(output_root / "cache" / "ms-playwright"),
            )
            for variable in ("TEMP", "TMP", "TMPDIR"):
                self.assertEqual(staged.env[variable], str(output_root / "cache" / "tmp"))
            self.assertEqual(
                staged.env["PYTHONPYCACHEPREFIX"],
                str(output_root / "cache" / "pycache"),
            )

    def test_rejects_output_root_inside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace_root = Path(temp_dir) / "workspace"
            repo_root = workspace_root / "repos" / "emulebb-rust"
            webui_root = repo_root / "webui"
            webui_root.mkdir(parents=True)

            original_root = WEBUI_WORKSPACE.ROOT
            original_webui_root = WEBUI_WORKSPACE.WEBUI_ROOT
            WEBUI_WORKSPACE.ROOT = repo_root
            WEBUI_WORKSPACE.WEBUI_ROOT = webui_root
            try:
                with self.assertRaises(SystemExit):
                    WEBUI_WORKSPACE.prepare_webui_workspace(
                        "webui-test",
                        {
                            "EMULEBB_WORKSPACE_ROOT": str(workspace_root),
                            "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(workspace_root / "output"),
                        },
                    )
            finally:
                WEBUI_WORKSPACE.ROOT = original_root
                WEBUI_WORKSPACE.WEBUI_ROOT = original_webui_root

    def test_stage_destination_must_be_below_output_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            output_root = temp_root / "output"
            allowed = WEBUI_WORKSPACE.require_output_path(output_root / "tools" / "webui", output_root, "stage")
            self.assertEqual(allowed, (output_root / "tools" / "webui").resolve())
            with self.assertRaises(SystemExit):
                WEBUI_WORKSPACE.require_output_path(temp_root / "elsewhere", output_root, "stage")
            with self.assertRaises(SystemExit):
                WEBUI_WORKSPACE.require_output_path(output_root, output_root, "stage")

    def test_stage_destination_cannot_overlap_working_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_root = Path(temp_dir) / "output"
            source = output_root / "builds" / "rust" / "webui-build-source"
            dist = output_root / "builds" / "rust" / "webui-build-dist"
            WEBUI_WORKSPACE.assert_paths_do_not_overlap(
                output_root / "tools" / "emulebb-rust" / "webui",
                (source, dist),
                "stage",
            )
            with self.assertRaises(SystemExit):
                WEBUI_WORKSPACE.assert_paths_do_not_overlap(
                    output_root / "builds",
                    (source, dist),
                    "stage",
                )


if __name__ == "__main__":
    unittest.main()
