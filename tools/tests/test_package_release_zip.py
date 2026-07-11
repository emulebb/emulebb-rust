from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "package_release_zip.py"
SPEC = importlib.util.spec_from_file_location("package_release_zip", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class TestExternalReleasePaths(unittest.TestCase):
    def test_rejects_relative_path(self) -> None:
        with self.assertRaisesRegex(SystemExit, "must be an absolute path"):
            PACKAGER.external_path("target/release", "--target-dir")

    def test_requires_workspace_root_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(SystemExit, "EMULEBB_WORKSPACE_ROOT must be set"):
                PACKAGER.external_path(Path(tempfile.gettempdir()) / "release", "--out")

    def test_rejects_path_inside_repository(self) -> None:
        with self.assertRaisesRegex(SystemExit, "must be outside the source checkout"):
            PACKAGER.external_path(PACKAGER.ROOT / "dist", "--out")

    def test_rejects_workspace_sibling_source_path(self) -> None:
        workspace_root = PACKAGER.ROOT.parents[1]
        sibling = workspace_root / "repos" / "another-source" / "dist"
        with self.assertRaisesRegex(SystemExit, "must be outside the source checkout"):
            PACKAGER.external_path(sibling, "--out", workspace_root=workspace_root)

    def test_accepts_absolute_path_outside_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "release"
            self.assertEqual(
                PACKAGER.external_path(path, "--out", workspace_root=PACKAGER.ROOT.parents[1]),
                path.resolve(),
            )


if __name__ == "__main__":
    unittest.main()
