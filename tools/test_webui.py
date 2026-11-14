#!/usr/bin/env python3
"""Run the emulebb-rust browser WebUI test lane."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from webui_workspace import WebUiWorkspace, prepare_webui_workspace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--typecheck-only", action="store_true",
                        help="Run locked installation and TypeScript checks without tests, browsers or a build.")
    args = parser.parse_args(argv)
    if args.typecheck_only:
        from ci_environment import prepare_command
        prepare_command([sys.executable, str(Path(__file__))], dict(os.environ))
    npm = npm_command()
    # WHY: the early type check must not clear or reuse the full test lane's
    # staged sources/dist; both keep the same locked installation contract.
    workspace = prepare_webui_workspace("webui-typecheck" if args.typecheck_only else "webui-test")
    run([npm, "ci", "--ignore-scripts"], workspace)
    if args.typecheck_only:
        run([npm, "run", "typecheck"], workspace)
        return 0
    run([npm, "run", "test:unit"], workspace)
    # WHY: Linux WebKit needs native libraries absent from the hosted base image;
    # Windows browser installation does not need the media-feature-pack path.
    dependencies = ["--with-deps"] if sys.platform == "linux" else []
    run([npm, "exec", "--", "playwright", "install", *dependencies, "chromium", "webkit"], workspace)
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
