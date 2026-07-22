from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
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


class TestWebuiPackaging(unittest.TestCase):
    def test_collect_webui_files_requires_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            webui = Path(temp_dir) / "webui"
            webui.mkdir()

            with self.assertRaisesRegex(SystemExit, "index.html not found"):
                PACKAGER.collect_webui_files(webui)

    def test_collect_webui_files_preserves_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            webui = Path(temp_dir) / "webui"
            assets = webui / "assets"
            assets.mkdir(parents=True)
            (webui / "index.html").write_text("<!doctype html>", encoding="utf-8")
            (assets / "app.js").write_text("console.log('ok');", encoding="utf-8")

            files = PACKAGER.collect_webui_files(webui)

            self.assertEqual(
                [relative.as_posix() for relative, _ in files],
                ["assets/app.js", "index.html"],
            )


class TestReleasePackage(unittest.TestCase):
    def test_main_writes_manifest_sbom_and_rejects_dead_ui(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            output_root = temp_root / "out"
            target_dir = output_root / "tools" / "emulebb-rust" / "bin"
            webui = target_dir / "webui"
            release_scope = temp_root / "RELEASE-SCOPE.md"
            out_dir = temp_root / "dist"
            webui.mkdir(parents=True)
            (target_dir / PACKAGER.BIN_NAME).write_bytes(b"MZ regular exe\n")
            (target_dir / "emulebb-rust-ui.exe").write_bytes(b"MZ dead ui\n")
            (target_dir / "emulebb-rust-diagnostics.exe").write_bytes(b"MZ diagnostics\n")
            (webui / "index.html").write_text("<!doctype html>", encoding="utf-8")
            (webui / "assets.js").write_text("console.log('ok');", encoding="utf-8")
            release_scope.write_text("# scope\n", encoding="utf-8")

            with patch.dict(
                "os.environ",
                {
                    "EMULEBB_WORKSPACE_ROOT": str(PACKAGER.ROOT.parents[1]),
                    "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output_root),
                    "CARGO_TARGET_DIR": str(output_root / "builds" / "rust" / "target"),
                },
                clear=True,
            ):
                result = PACKAGER.main(
                    [
                        "--target-dir",
                        str(target_dir),
                        "--webui-dir",
                        str(webui),
                        "--release-scope",
                        str(release_scope),
                        "--out",
                        str(out_dir),
                    ]
                )

            self.assertEqual(result, 0)
            version = PACKAGER.workspace_version()
            zip_path = out_dir / f"emulebb-rust-v{version}-windows-x64.zip"
            manifest_path = out_dir / f"emulebb-rust-v{version}-windows-x64.manifest.json"
            sbom_path = out_dir / f"emulebb-rust-v{version}-windows-x64.sbom.spdx.json"
            sums_path = out_dir / "SHA256SUMS"
            self.assertTrue(zip_path.is_file())
            self.assertTrue(manifest_path.is_file())
            self.assertTrue(sbom_path.is_file())
            self.assertTrue(sums_path.is_file())
            with zipfile.ZipFile(zip_path) as archive:
                names = set(archive.namelist())
            self.assertIn("emulebb-rust/emulebb-rust.exe", names)
            self.assertIn("emulebb-rust/webui/index.html", names)
            self.assertIn("emulebb-rust/RELEASE-SCOPE.md", names)
            self.assertIn("emulebb-rust/SBOM.spdx.json", names)
            self.assertNotIn("emulebb-rust/emulebb-rust-ui.exe", names)
            self.assertNotIn("emulebb-rust/emulebb-rust-diagnostics.exe", names)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "emulebb.rust.package/1")
            self.assertEqual(manifest["asset"], zip_path.name)
            self.assertEqual(manifest["executable"], "emulebb-rust/emulebb-rust.exe")
            self.assertIn("emulebb-rust/webui/index.html", manifest["perFileSha256"])
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            self.assertEqual(sbom["spdxVersion"], "SPDX-2.3")
            self.assertEqual(
                [line.split("  ", 1)[1] for line in sums_path.read_text(encoding="ascii").splitlines()],
                [zip_path.name, manifest_path.name, sbom_path.name],
            )

    def test_assert_package_contents_rejects_dead_ui(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            zip_path = Path(temp_dir) / "bad.zip"
            with zipfile.ZipFile(zip_path, "w") as archive:
                archive.writestr("emulebb-rust/emulebb-rust.exe", b"MZ")
                archive.writestr("emulebb-rust/webui/index.html", b"<html></html>")
                archive.writestr("emulebb-rust/emulebb-rust-settings.example.toml", b"[rest]\n")
                archive.writestr("emulebb-rust/LICENSE", b"license\n")
                archive.writestr("emulebb-rust/README.md", b"readme\n")
                archive.writestr("emulebb-rust/RELEASE-SCOPE.md", b"scope\n")
                archive.writestr("emulebb-rust/SBOM.spdx.json", b"{}\n")
                archive.writestr("emulebb-rust/emulebb-rust-ui.exe", b"MZ")

            with self.assertRaisesRegex(SystemExit, "forbidden UI/diagnostics"):
                PACKAGER.assert_package_contents(zip_path)


if __name__ == "__main__":
    unittest.main()
