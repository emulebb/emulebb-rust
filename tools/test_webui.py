#!/usr/bin/env python3
"""Run the emulebb-rust browser WebUI test lane."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from webui_workspace import WebUiWorkspace, prepare_webui_workspace


def main() -> int:
    npm = npm_command()
    workspace = prepare_webui_workspace("webui-test")
    run([npm, "ci", "--ignore-scripts"], workspace)
    run([npm, "run", "test:unit"], workspace)
    run([npm, "exec", "--", "playwright", "install", "chromium"], workspace)
    run([npm, "run", "test:e2e"], workspace)
    run(
        [npm, "run", "build", "--", "--outDir", str(workspace.dist), "--emptyOutDir"],
        workspace,
    )
    return 0


def npm_command() -> str:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is required to test webui")
    return npm


def run(command: list[str], workspace: WebUiWorkspace) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=workspace.source, env=workspace.env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
