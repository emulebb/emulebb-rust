#!/usr/bin/env python3
"""Prepare isolated emulebb-rust WebUI workspaces below the output root."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
WEBUI_ROOT = ROOT / "webui"
GENERATED_DIRECTORY_NAMES = (
    "coverage",
    "dist",
    "node_modules",
    "playwright-report",
    "test-results",
)


@dataclass(frozen=True)
class WebUiWorkspace:
    """One staged WebUI source tree and its external build environment."""

    source: Path
    dist: Path
    env: dict[str, str]
    output_root: Path


def prepare_webui_workspace(name: str, env: Mapping[str, str] | None = None) -> WebUiWorkspace:
    """Copy WebUI sources into a clean work area below the configured output root."""

    process_env = dict(os.environ if env is None else env)
    workspace_root = require_path_env(process_env, "EMULEBB_WORKSPACE_ROOT")
    output_root = require_path_env(process_env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    assert_contains_checkout(workspace_root)
    assert_outside_workspace(output_root, workspace_root, "EMULEBB_WORKSPACE_OUTPUT_ROOT")

    parent = output_root / "builds" / "rust"
    source = parent / f"{name}-source"
    dist = parent / f"{name}-dist"
    remove_directory(source)
    remove_directory(dist)
    parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        WEBUI_ROOT,
        source,
        ignore=shutil.ignore_patterns(*GENERATED_DIRECTORY_NAMES),
    )

    npm_cache = output_root / "cache" / "npm"
    playwright_browsers = output_root / "cache" / "ms-playwright"
    scratch = output_root / "cache" / "tmp"
    pycache = output_root / "cache" / "pycache"
    npm_cache.mkdir(parents=True, exist_ok=True)
    playwright_browsers.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=True)
    pycache.mkdir(parents=True, exist_ok=True)
    process_env["NPM_CONFIG_CACHE"] = str(npm_cache)
    process_env["PLAYWRIGHT_BROWSERS_PATH"] = str(playwright_browsers)
    process_env["PYTHONPYCACHEPREFIX"] = str(pycache)
    for variable in ("TEMP", "TMP", "TMPDIR"):
        process_env[variable] = str(scratch)
    return WebUiWorkspace(source=source, dist=dist, env=process_env, output_root=output_root)


def require_output_path(path: Path, output_root: Path, label: str) -> Path:
    """Return an absolute path only when it stays below the output root."""

    resolved = path.expanduser().resolve()
    try:
        relative = resolved.relative_to(output_root.resolve())
    except ValueError as exc:
        raise SystemExit(f"{label} must be below EMULEBB_WORKSPACE_OUTPUT_ROOT: {resolved}") from exc
    if not relative.parts:
        raise SystemExit(f"{label} must not be EMULEBB_WORKSPACE_OUTPUT_ROOT itself: {resolved}")
    return resolved


def assert_paths_do_not_overlap(path: Path, reserved_paths: tuple[Path, ...], label: str) -> None:
    """Reject a destination that contains or is contained by a working path."""

    resolved = path.resolve()
    for reserved_path in reserved_paths:
        reserved = reserved_path.resolve()
        if resolved == reserved or resolved in reserved.parents or reserved in resolved.parents:
            raise SystemExit(f"{label} overlaps WebUI working path: {resolved}")


def require_path_env(env: Mapping[str, str], name: str) -> Path:
    value = env.get(name)
    if not value:
        raise SystemExit(f"{name} must be set; refusing to derive or override it")
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raise SystemExit(f"{name} must be an absolute path: {raw_path}")
    return raw_path.resolve()


def assert_contains_checkout(workspace_root: Path) -> None:
    try:
        ROOT.resolve().relative_to(workspace_root.resolve())
    except ValueError as exc:
        raise SystemExit(f"EMULEBB_WORKSPACE_ROOT must contain this checkout: {workspace_root}") from exc


def assert_outside_workspace(path: Path, workspace_root: Path, label: str) -> None:
    try:
        path.resolve().relative_to(workspace_root.resolve())
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside EMULEBB_WORKSPACE_ROOT: {path.resolve()}")


def remove_directory(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        raise SystemExit(f"expected a directory path, got: {path}")
