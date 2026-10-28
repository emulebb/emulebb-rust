#!/usr/bin/env python3
"""Build and stage the emulebb-rust browser WebUI."""

from __future__ import annotations

import argparse
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
    if not (workspace.dist / "index.html").is_file():
        raise SystemExit(f"webui build did not produce {workspace.dist / 'index.html'}")
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    shutil.copytree(workspace.dist, stage_dir)
    print(f"staged WebUI {stage_dir}", flush=True)


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
