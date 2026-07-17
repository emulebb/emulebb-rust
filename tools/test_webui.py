#!/usr/bin/env python3
"""Run the emulebb-rust browser WebUI test lane."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WEBUI_ROOT = ROOT / "webui"


def main() -> int:
    npm = npm_command()
    run([npm, "ci"])
    run([npm, "run", "test:unit"])
    run([npm, "exec", "--", "playwright", "install", "chromium"])
    run([npm, "run", "test:e2e"])
    run([npm, "run", "build"])
    return 0


def npm_command() -> str:
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm is required to test webui")
    return npm


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=WEBUI_ROOT, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
