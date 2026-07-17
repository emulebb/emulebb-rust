#!/usr/bin/env python3
"""Build and stage the emulebb-rust browser WebUI."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBUI_ROOT = ROOT / "webui"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage-dir",
        required=True,
        type=Path,
        help="External directory that receives the built WebUI assets.",
    )
    args = parser.parse_args(argv)

    workspace_root = require_workspace_root_env()
    stage_dir = args.stage_dir.expanduser().resolve()
    assert_outside_repo(stage_dir, "--stage-dir")
    assert_outside_workspace(stage_dir, workspace_root, "--stage-dir")
    build_and_stage(stage_dir)
    return 0


def build_and_stage(stage_dir: Path) -> None:
    if not (WEBUI_ROOT / "package-lock.json").is_file():
        raise SystemExit("webui/package-lock.json is required; run npm install after dependency edits")
    npm = npm_command()
    run([npm, "ci"], WEBUI_ROOT)
    run([npm, "run", "build"], WEBUI_ROOT)
    dist = WEBUI_ROOT / "dist"
    if not (dist / "index.html").is_file():
        raise SystemExit("webui build did not produce dist/index.html")
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    shutil.copytree(dist, stage_dir)
    print(f"staged WebUI {stage_dir}", flush=True)


def assert_outside_repo(path: Path, label: str) -> None:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside the source checkout: {resolved}")


def require_workspace_root_env() -> Path:
    name = "EMULEBB_WORKSPACE_ROOT"
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set; refusing to derive or override it")
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raise SystemExit(f"{name} must be an absolute path: {raw_path}")
    path = raw_path.resolve()
    try:
        ROOT.resolve().relative_to(path)
    except ValueError as exc:
        raise SystemExit(f"{name} must contain this checkout: {path}") from exc
    return path


def assert_outside_workspace(path: Path, workspace_root: Path, label: str) -> None:
    try:
        path.resolve().relative_to(workspace_root.resolve())
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside EMULEBB_WORKSPACE_ROOT: {path.resolve()}")


def npm_command() -> str:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is required to build webui")
    return npm


def run(command: list[str], cwd: Path) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
