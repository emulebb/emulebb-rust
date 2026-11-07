#!/usr/bin/env python3
"""Build and stage the emulebb-rust browser WebUI."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from webui_workspace import (
    WebUiWorkspace,
    assert_paths_do_not_overlap,
    prepare_webui_workspace,
    require_output_path,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage-dir",
        required=True,
        type=Path,
        help="External directory that receives the built WebUI assets.",
    )
    args = parser.parse_args(argv)

    workspace = prepare_webui_workspace("webui-build")
    stage_dir = require_output_path(args.stage_dir, workspace.output_root, "--stage-dir")
    assert_paths_do_not_overlap(stage_dir, (workspace.source, workspace.dist), "--stage-dir")
    build_and_stage(stage_dir, workspace)
    return 0


def build_and_stage(stage_dir: Path, workspace: WebUiWorkspace) -> None:
    if not (workspace.source / "package-lock.json").is_file():
        raise SystemExit("webui/package-lock.json is required; run npm install after dependency edits")
    npm = npm_command()
    run([npm, "ci", "--ignore-scripts"], workspace)
    run(
        [npm, "run", "build", "--", "--outDir", str(workspace.dist), "--emptyOutDir"],
        workspace,
    )
    stage_dist(workspace.dist, stage_dir, workspace.output_root)


def asset_hashes(root: Path) -> dict[str, str]:
    """Fingerprint every staged asset using stable relative names."""
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def stage_dist(dist: Path, stage_dir: Path, output_root: Path) -> None:
    """Stage an existing bundle and verify its contents after copying."""
    dist = require_output_path(dist, output_root, "WebUI dist")
    stage_dir = require_output_path(stage_dir, output_root, "WebUI stage")
    assert_paths_do_not_overlap(stage_dir, (dist,), "WebUI stage")
    if not (dist / "index.html").is_file():
        raise SystemExit(f"webui build did not produce {dist / 'index.html'}")
    expected = asset_hashes(dist)
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    shutil.copytree(dist, stage_dir)
    if asset_hashes(stage_dir) != expected:
        raise SystemExit("Staged WebUI assets differ from the built bundle")
    reports = output_root / "reports" / "webui-stage"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "latest.json").write_text(json.dumps({"source": str(dist), "stage": str(stage_dir), "assets": expected}, indent=2) + "\n", encoding="utf-8")
    print(f"staged and verified WebUI {stage_dir}", flush=True)


def npm_command() -> str:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is required to build webui")
    return npm


def run(command: list[str], workspace: WebUiWorkspace) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=workspace.source, env=workspace.env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
