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
)


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    version = manifest["workspace"]["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", version):
        raise SystemExit(f"unexpected workspace version: {version!r}")
    return version


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-dir",
        default="target/release",
        help="cargo release output dir containing the built binary",
    )
    parser.add_argument("--out", default="dist", help="output directory for the zip + SHA256SUMS")
    args = parser.parse_args()

    version = workspace_version()
    binary = ROOT / args.target_dir / BIN_NAME
    if not binary.is_file():
        raise SystemExit(f"release binary not found: {binary} (run cargo build --release first)")

    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"emulebb-rust-v{version}-windows-x64.zip"
    zip_path = out_dir / zip_name

    # Stage the binary + user-facing docs under a versioned top-level folder.
    root_in_zip = f"emulebb-rust-v{version}"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(binary, f"{root_in_zip}/{BIN_NAME}")
        for rel in DOC_FILES:
            source = ROOT / rel
            if not source.is_file():
                raise SystemExit(f"required release file missing: {rel}")
            archive.write(source, f"{root_in_zip}/{Path(rel).name}")

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    (out_dir / "SHA256SUMS").write_text(f"{digest}  {zip_name}\n", encoding="utf-8")

    print(f"packaged {zip_path} ({zip_path.stat().st_size} bytes)")
    print(f"sha256  {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
