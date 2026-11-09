"""Exercise Cargo's resolver on Dependabot-style native path dependencies."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
NATIVE_PACKAGES = ("emulebb-miniupnpc-sys", "emulebb-pcpnatpmp-sys")


class DependabotManifestTests(unittest.TestCase):
    def _fixture(self, directory: Path, package: str, *, explicit_build: bool) -> Path:
        """Keep the actual manifest shape, replacing only registry cc with a local stub."""
        source = ROOT / "crates" / package
        content = (source / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('links = "', content)
        if not explicit_build:
            content = content.replace('build = "build.rs"\n', "")
        else:
            self.assertEqual(tomllib.loads(content)["package"]["build"], "build.rs")
        workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]
        fields = "\n".join(f"{key} = {json.dumps(value)}" for key, value in workspace.items())
        (directory / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["native", "cc"]\nresolver = "2"\n'
            f"[workspace.package]\n{fields}\n[workspace.lints]\n"
            '[workspace.dependencies]\ncc = { path = "cc" }\n', encoding="utf-8",
        )
        native = directory / "native"
        (native / "src").mkdir(parents=True)
        (native / "Cargo.toml").write_text(content, encoding="utf-8")
        (native / "src/lib.rs").write_text("", encoding="utf-8")
        cc = directory / "cc"
        (cc / "src").mkdir(parents=True)
        (cc / "Cargo.toml").write_text(
            '[package]\nname = "cc"\nversion = "1.0.0"\nedition = "2024"\n', encoding="utf-8",
        )
        (cc / "src/lib.rs").write_text("", encoding="utf-8")
        self.assertTrue((source / "build.rs").is_file())
        self.assertFalse((native / "build.rs").exists())
        return native / "Cargo.toml"

    def _check_resolver(self, *, explicit_build: bool) -> None:
        output = Path(os.environ["EMULEBB_WORKSPACE_OUTPUT_ROOT"])
        self.assertTrue(output.is_absolute() and output.is_dir())
        self.assertFalse(output.resolve().is_relative_to(Path(os.environ["EMULEBB_WORKSPACE_ROOT"]).resolve()))
        scratch = output / "tmp" / "dependabot-manifest-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        for package in NATIVE_PACKAGES:
            with self.subTest(package=package, explicit_build=explicit_build), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                manifest = self._fixture(Path(temporary), package, explicit_build=explicit_build)
                for args in (
                    ["metadata", "--no-deps", "--format-version", "1"],
                    ["generate-lockfile"],
                ):
                    result = subprocess.run(
                        ["cargo", *args, "--offline", "--manifest-path", str(manifest)],
                        cwd=ROOT, capture_output=True, text=True, timeout=60,
                    )
                    if not explicit_build:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("does not have a custom build script", result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stderr)
                        if args[0] == "metadata":
                            selected = next(p for p in json.loads(result.stdout)["packages"] if p["name"] == package)
                            actual = tomllib.loads((ROOT / "crates" / package / "Cargo.toml").read_text())["package"]
                            self.assertEqual(selected["links"], actual["links"])
                            self.assertTrue(any("custom-build" in target["kind"] for target in selected["targets"]))
                self.assertFalse((manifest.parent / "build.rs").exists())

    def test_implicit_build_script_is_lost_in_reconstructed_path_dependency(self):
        self._check_resolver(explicit_build=False)

    def test_explicit_build_script_preserves_offline_resolution_without_executing_it(self):
        self._check_resolver(explicit_build=True)


if __name__ == "__main__":
    unittest.main()
