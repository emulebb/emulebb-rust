from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "webui_workspace.py"
SPEC = importlib.util.spec_from_file_location("webui_workspace", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
WEBUI_WORKSPACE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = WEBUI_WORKSPACE
SPEC.loader.exec_module(WEBUI_WORKSPACE)


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
