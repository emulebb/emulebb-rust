#!/usr/bin/env python3
"""Package the unsigned Windows x64 release zip for emulebb-rust.

Stages the release binary plus its user-facing docs into
``emulebb-rust-v<version>-windows-x64.zip`` and writes a ``SHA256SUMS`` beside
it. Invoked by ``.github/workflows/release.yml`` after ``cargo build --release``;
stdlib-only so it needs no extra tooling on the runner.

The artifact is always UNSIGNED (workspace policy); do not add code signing.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import tomllib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN_NAME = "emulebb-rust.exe"
# Files staged into the zip alongside the binary (repo-relative).
DOC_FILES = (
    "emulebb-rust.example.toml",
    "docs/RELEASE-SCOPE.md",
    "LICENSE",
    "README.md",
    "THIRD-PARTY-LICENSES.md",
)


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    version = manifest["workspace"]["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", version):
        raise SystemExit(f"unexpected workspace version: {version!r}")
    return version


def required_path_env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set; refusing to derive or override it")
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raise SystemExit(f"{name} must be an absolute path: {raw_path}")
    path = raw_path.resolve()
    if name == "EMULEBB_WORKSPACE_ROOT":
        try:
            ROOT.resolve().relative_to(path)
        except ValueError as exc:
            raise SystemExit(f"{name} must contain this checkout: {path}") from exc
    return path


def external_path(value: str | Path, label: str, workspace_root: Path | None = None) -> Path:
    """Resolve a required absolute output path outside every source checkout."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SystemExit(f"{label} must be an absolute path outside the source checkout: {path}")
    resolved = path.resolve()
    roots = [ROOT.resolve()]
    if workspace_root is None:
        workspace_root = required_path_env("EMULEBB_WORKSPACE_ROOT")
    roots.append(workspace_root.expanduser().resolve())
    for root in roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise SystemExit(f"{label} must be outside the source checkout: {resolved}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-dir",
        required=True,
        help="cargo release output dir containing the built binary",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="output directory for the zip + SHA256SUMS",
    )
    args = parser.parse_args()

    version = workspace_version()
    target_dir = external_path(args.target_dir, "--target-dir")
    out_dir = external_path(args.out, "--out")
    binary = target_dir / BIN_NAME
    if not binary.is_file():
        raise SystemExit(f"release binary not found: {binary} (run cargo build --release first)")

    release_files = []
    for rel in DOC_FILES:
        source = ROOT / rel
        if not source.is_file():
            raise SystemExit(f"required release file missing: {rel}")
        release_files.append((rel, source))

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"emulebb-rust-v{version}-windows-x64.zip"
    zip_path = out_dir / zip_name

    # Stage the binary + user-facing docs under a versioned top-level folder.
    root_in_zip = f"emulebb-rust-v{version}"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, f"{root_in_zip}/{BIN_NAME}")
        for rel, source in release_files:
            archive.write(source, f"{root_in_zip}/{Path(rel).name}")

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(f"{digest}  {zip_name}\n", encoding="utf-8")

    print(f"packaged {zip_path} ({zip_path.stat().st_size} bytes)")
    print(f"sha256  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
