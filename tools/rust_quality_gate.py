#!/usr/bin/env python3
"""Canonical Rust quality gates for emulebb-rust.

This script defines local and CI Rust validation. Tool and Python dependency
pins live in ci-toolchain.json and requirements-ci.txt. It invokes tools without
shell wrappers, so the same checks work on Windows, Linux, and macOS.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = json.loads((ROOT / "tools/ci-toolchain.json").read_text(encoding="utf-8"))

STATIC_CHECKS = ("policy", "policy-tests", "fmt")
COMPILE_CHECKS = ("clippy", "diagnostics", "webui-test")
QUICK_CHECKS = ("environment",) + STATIC_CHECKS + COMPILE_CHECKS
TEST_CHECKS = ("build", "test-workspace", "test-vpn-leak")
GATES = {name: (name,) for name in (
    "fmt", "clippy", "diagnostics", "webui-test", "build", "test-workspace",
    "test-kad-swarm", "test-vpn-leak", "workflow-lint", "supply-chain", "rest-openapi", "environment",
)}
GATES.update({
    "policy": ("policy", "policy-tests"),
    "branch-check": ("policy", "policy-tests", "fmt"),
    "branch-ci": ("environment", "workflow-lint", "policy", "policy-tests", "fmt"),
    "quick": QUICK_CHECKS,
    "ci-quality": ("environment",) + STATIC_CHECKS + ("webui-test",),
    "ci-test": ("clippy", "diagnostics") + TEST_CHECKS,
    "ci": QUICK_CHECKS + TEST_CHECKS,
    "pre-push": ("environment", "workflow-lint") + STATIC_CHECKS + ("supply-chain",) + COMPILE_CHECKS + TEST_CHECKS + ("rest-openapi",),
})
CI_JOBS = {
    "workflow-lint": "workflow-lint", "quality": "ci-quality", "build-linux": "ci-test",
    "build-test": "ci-test", "rest-openapi": "rest-openapi", "supply-chain": "supply-chain",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "gate",
        choices=sorted(GATES),
        help=(
            "quick=policy+fmt+clippy+diagnostics+webui-test; ci=quick+build+tests; "
            "ci-quality=environment+policy+fmt+webui-test; "
            "ci-test=clippy+diagnostics+build+full workspace tests+VPN leak test; "
            "test-kad-swarm=focused serialized Kad diagnostics"
        ),
    )
    parser.add_argument(
        "--describe", action="store_true", help="Print the resolved check commands as JSON without executing them."
    )
    parser.add_argument(
        "--force-rebuild",
        action="store_true",
        help="Clean the configured Cargo target before running build steps.",
    )
    args = parser.parse_args(argv)

    env = build_env()
    commands = commands_for_gate(args.gate, env, force_rebuild=args.force_rebuild)
    if args.describe:
        print(json.dumps([{"label": label, "command": command} for label, command in commands], indent=2))
        return 0
    execute_gate(args.gate, commands, env)
    return 0


def execute_gate(gate: str, commands: list[tuple[str, list[str]]], env: dict[str, str]) -> Path:
    """Retain per-check timings and failures without reusing prior pass results."""
    output = require_path_env(env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    directory = output / "reports" / "rust-quality-gate" / run_id
    directory.mkdir(parents=True)
    path = directory / "results.json"
    report = {"gate": gate, "started_at": datetime.now(timezone.utc).isoformat(), "status": "running", "checks": []}
    for label, command in commands:
        started = perf_counter()
        check = {"label": label, "command": command, "status": "failed"}
        try:
            run_step(label, command, env)
            check["status"] = "passed"
        except BaseException as exc:
            check["error"] = str(exc)
            raise
        finally:
            check["elapsed_seconds"] = round(perf_counter() - started, 3)
            report["checks"].append(check)
            report["status"] = "failed" if check["status"] == "failed" else "passed" if len(report["checks"]) == len(commands) else "running"
            report["elapsed_seconds"] = round(sum(item["elapsed_seconds"] for item in report["checks"]), 3)
            path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"{check['status']}: {label} ({check['elapsed_seconds']:.3f}s); report: {path}", flush=True)
    return path


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    workspace_root = require_workspace_root_env(env)
    output_root = require_path_env(env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    target = require_path_env(env, "CARGO_TARGET_DIR")
    assert_outside_workspace(output_root, workspace_root, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    assert_outside_workspace(target, workspace_root, "CARGO_TARGET_DIR")
    expected_target = output_root / "builds" / "rust" / "target"
    if target != expected_target:
        raise SystemExit(
            "CARGO_TARGET_DIR must be "
            f"{expected_target}, got {target}"
        )
    configure_output_scratch(env, output_root)
    return env


def configure_output_scratch(env: dict[str, str], output_root: Path) -> Path:
    """Route child-process temporary files into the canonical output root."""

    scratch = output_root / "cache" / "tmp"
    pycache = output_root / "cache" / "pycache"
    scratch.mkdir(parents=True, exist_ok=True)
    pycache.mkdir(parents=True, exist_ok=True)
    for name in ("TEMP", "TMP", "TMPDIR"):
        env[name] = str(scratch)
    env["PYTHONPYCACHEPREFIX"] = str(pycache)
    return scratch


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


def commands_for_gate(
    gate: str,
    env: dict[str, str] | None = None,
    *,
    force_rebuild: bool = False,
) -> list[tuple[str, list[str]]]:
    if env is None:
        env = os.environ.copy()
    factories = {
        "policy": policy_step, "policy-tests": policy_tests_step, "fmt": fmt_step,
        "clippy": clippy_step, "diagnostics": diagnostics_step, "webui-test": webui_test_step,
        "build": lambda: build_step(env, force_rebuild=force_rebuild),
        "test-workspace": test_workspace_step, "test-kad-swarm": test_kad_swarm_step,
        "test-vpn-leak": test_vpn_leak_step, "workflow-lint": workflow_lint_step,
        "supply-chain": supply_chain_step, "rest-openapi": lambda: rest_openapi_step(env),
        "environment": lambda: ("CI toolchain and input provenance", [sys.executable, "tools/ci_environment.py",
                                *(["--scope", "quality"] if gate == "ci-quality" else [])]),
    }
    result = []
    seen = set()
    for name in GATES[gate]:
        if name == "build" and "webui-test" in seen:
            from webui_workspace import webui_dist_path
            result.append(build_step(env, force_rebuild=force_rebuild, webui_dist=webui_dist_path("webui-test", env)))
        else:
            result.append(factories[name]())
        seen.add(name)
    return result


def workflow_lint_step() -> tuple[str, list[str]]:
    """Use the same immutable actionlint revision on every execution surface."""
    return ("GitHub Actions workflow lint", ["go", "run", f"github.com/rhysd/actionlint/cmd/actionlint@{TOOLCHAIN['actionlint']}"])


def supply_chain_step() -> tuple[str, list[str]]:
    """Keep advisory, license, and source checks identical locally and remotely."""
    return ("cargo-deny", ["cargo", "deny", "check", "advisories", "licenses", "sources"])


def rest_openapi_step(env: dict[str, str]) -> tuple[str, list[str]]:
    """Delegate loopback conformance to the persisted shared harness."""
    root = require_workspace_root_env(env)
    script = root / "repos" / "emulebb-build-tests" / "scripts" / "rust-rest-openapi-ci.py"
    return ("live REST/OpenAPI conformance", [sys.executable, str(script)])


def policy_step() -> tuple[str, list[str]]:
    return ("Rust client policy", [sys.executable, "tools/check_rust_client_policy.py"])


def policy_tests_step() -> tuple[str, list[str]]:
    return (
        "Rust client policy tests",
        [
            sys.executable,
            "-B",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tools/tests",
            "-p",
            "test_*.py",
        ],
    )


def fmt_step() -> tuple[str, list[str]]:
    return ("rustfmt check", ["cargo", "fmt", "--all", "--check"])


def clippy_step() -> tuple[str, list[str]]:
    return (
        "clippy",
        ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
    )


def diagnostics_step() -> tuple[str, list[str]]:
    return (
        "packet diagnostics binary",
        [
            "cargo",
            "check",
            "-p",
            "emulebb-daemon",
            "--bin",
            "emulebb-rust-diagnostics",
            "--features",
            "packet-diagnostics",
            "--locked",
        ],
    )


def webui_test_step() -> tuple[str, list[str]]:
    return ("WebUI SPA tests", [sys.executable, "tools/test_webui.py"])


def build_step(env: dict[str, str], *, force_rebuild: bool = False, webui_dist: Path | None = None) -> tuple[str, list[str]]:
    command = [
        sys.executable,
        "tools/fresh_rust_build.py",
        "--stage-bin-dir",
        str(release_stage_bin_dir(env)),
    ]
    if force_rebuild:
        command.append("--force-rebuild")
    if webui_dist is not None:
        command.extend(["--webui-dist", str(webui_dist)])
    return (
        "fresh debug/release workspace builds",
        command,
    )


def release_stage_bin_dir(env: dict[str, str]) -> Path:
    workspace_root = require_workspace_root_env(env)
    output_root = require_path_env(env, "EMULEBB_WORKSPACE_OUTPUT_ROOT")
    stage_dir = output_root / "tools" / "emulebb-rust" / "bin"
    assert_outside_repo(stage_dir, "release staging directory")
    assert_outside_workspace(stage_dir, workspace_root, "release staging directory")
    return stage_dir


def test_workspace_step() -> tuple[str, list[str]]:
    return (
        "workspace tests",
        ["cargo", "test", "--workspace", "--locked"],
    )


def test_kad_swarm_step() -> tuple[str, list[str]]:
    return (
        "focused kad_swarm tests",
        [
            "cargo",
            "test",
            "-p",
            "emulebb-core",
            "--test",
            "kad_swarm",
            "--locked",
            "--",
            "--test-threads=1",
        ],
    )


def test_vpn_leak_step() -> tuple[str, list[str]]:
    # RUST-FEAT-005 dynamic leak gate (release-blocking): observed-egress test
    # under the egress-audit feature. Serial: the 3 scenarios share the global
    # egress recorder. The feature is test-only and must never reach a release
    # build (enforced by check_rust_client_policy.py).
    return (
        "vpn leak-test (observed egress)",
        [
            "cargo",
            "test",
            "-p",
            "emulebb-core",
            "--features",
            "egress-audit",
            "--test",
            "vpn_leak_egress",
            "--locked",
            "--",
            "--test-threads=1",
        ],
    )


def run_step(label: str, command: list[str], env: dict[str, str]) -> None:
    from ci_environment import prepare_command
    print(f"==> {label}", flush=True)
    command = prepare_command(command, env)
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
