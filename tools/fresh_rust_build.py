#!/usr/bin/env python3
"""Build fresh runnable emulebb-rust debug and release artifacts."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEBUG_BINARIES = ("emulebb-rust", "emulebb-rust-ui", "emulebb-nat-diagnostic")
RELEASE_BINARIES = (
    "emulebb-rust",
    "emulebb-rust-ui",
    "emulebb-rust-diagnostics",
    "emulebb-nat-diagnostic",
)
EXE_SUFFIX = ".exe" if os.name == "nt" else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stage-bin-dir",
        required=True,
        type=Path,
        help="External directory that receives fresh release executables.",
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Clean the configured Cargo target before building.",
    )
    args = parser.parse_args(argv)

    env = os.environ.copy()
    workspace_root = require_workspace_root_env(env)
    output_root = require_path_env(env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    assert_outside_workspace(output_root, workspace_root, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    target_dir = require_target_dir(env)
    stage_bin_dir = args.stage_bin_dir.expanduser().resolve()
    assert_outside_repo(stage_bin_dir, "--stage-bin-dir")
    expected_stage_bin_dir = output_root / "tools" / "emulebb-rust" / "bin"
    if stage_bin_dir != expected_stage_bin_dir:
        raise SystemExit(
            "--stage-bin-dir must be "
            f"{expected_stage_bin_dir}, got {stage_bin_dir}"
        )

    if args.force_rebuild:
        clean_target_dir(env)
    remove_profile_outputs(stage_bin_dir, RELEASE_BINARIES)

    run(["cargo", "build", "--workspace", "--locked"], env)
    verify_profile_outputs(target_dir / "debug", DEBUG_BINARIES)

    run(["cargo", "build", "--release", "--workspace", "--locked"], env)
    run(
        [
            "cargo",
            "build",
            "--release",
            "-p",
            "emulebb-daemon",
            "--bin",
            "emulebb-rust-diagnostics",
            "--features",
            "packet-diagnostics",
            "--locked",
        ],
        env,
    )
    release_outputs = verify_profile_outputs(target_dir / "release", RELEASE_BINARIES)
    stage_release_outputs(release_outputs, stage_bin_dir)
    stage_webui(stage_bin_dir / "webui")
    return 0


def require_target_dir(env: dict[str, str]) -> Path:
    workspace_root = require_workspace_root_env(env)
    output_root = require_path_env(env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    target = require_path_env(env, "CARGO_TARGET_DIR")
    assert_outside_workspace(target, workspace_root, "CARGO_TARGET_DIR")
    expected_target = output_root / "builds" / "rust" / "target"
    if target != expected_target:
        raise SystemExit(
            "CARGO_TARGET_DIR must be "
            f"{expected_target}, got {target}"
        )
    return target


def require_path_env(env: dict[str, str], name: str) -> Path:
    value = env.get(name)
    if not value:
        raise SystemExit(f"{name} must be set; refusing to derive or override it")
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raise SystemExit(f"{name} must be an absolute path: {raw_path}")
    path = raw_path.resolve()
    assert_outside_repo(path, name)
    return path


def require_workspace_root_env(env: dict[str, str]) -> Path:
    name = "EMULEBB_WORKSPACE_ROOT"
    value = env.get(name)
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


def assert_outside_repo(path: Path, label: str) -> None:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside the source checkout: {resolved}")


def assert_outside_workspace(path: Path, workspace_root: Path, label: str) -> None:
    try:
        path.resolve().relative_to(workspace_root.resolve())
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside EMULEBB_WORKSPACE_ROOT: {path.resolve()}")


def remove_profile_outputs(directory: Path, names: tuple[str, ...]) -> None:
    for name in names:
        for artifact in staged_artifact_names(name):
            (directory / artifact).unlink(missing_ok=True)


def clean_target_dir(env: dict[str, str]) -> None:
    run(["cargo", "clean"], env)


def verify_profile_outputs(directory: Path, names: tuple[str, ...]) -> dict[str, Path]:
    outputs = {}
    for name in names:
        artifact = directory / executable_name(name)
        if not artifact.is_file():
            raise SystemExit(f"expected build artifact was not produced: {artifact}")
        outputs[name] = artifact
    return outputs


def stage_release_outputs(outputs: dict[str, Path], stage_bin_dir: Path) -> None:
    stage_bin_dir.mkdir(parents=True, exist_ok=True)
    for name, source in outputs.items():
        destination = stage_bin_dir / executable_name(name)
        shutil.copyfile(source, destination)
        os.utime(destination, None)
        print(f"staged {destination}", flush=True)
        pdb_source = release_pdb_path(source, name)
        if pdb_source is not None:
            for pdb_artifact in staged_pdb_names(name):
                pdb_destination = stage_bin_dir / pdb_artifact
                shutil.copyfile(pdb_source, pdb_destination)
                os.utime(pdb_destination, None)
                print(f"staged {pdb_destination}", flush=True)


def stage_webui(stage_dir: Path) -> None:
    run([sys.executable, "tools/build_webui.py", "--stage-dir", str(stage_dir)], os.environ.copy())


def executable_name(name: str) -> str:
    return f"{name}{EXE_SUFFIX}"


def pdb_name(name: str) -> str:
    return f"{name}.pdb"


def cargo_pdb_name(name: str) -> str:
    return f"{name.replace('-', '_')}.pdb"


def staged_artifact_names(name: str) -> tuple[str, ...]:
    return (executable_name(name), *staged_pdb_names(name))


def staged_pdb_names(name: str) -> tuple[str, ...]:
    names = (pdb_name(name), cargo_pdb_name(name))
    return tuple(dict.fromkeys(names))


def release_pdb_path(executable: Path, name: str) -> Path | None:
    candidates = (
        executable.with_suffix(".pdb"),
        executable.with_name(cargo_pdb_name(name)),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def run(command: list[str], env: dict[str, str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
