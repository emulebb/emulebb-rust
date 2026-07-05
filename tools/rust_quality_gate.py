#!/usr/bin/env python3
"""Canonical Rust quality gates for emulebb-rust.

This script is the single entrypoint for local and CI Rust validation. It uses
only the Python standard library and invokes cargo/rustfmt/clippy without shell
wrappers, so the same command works on Windows, Linux, and macOS.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "gate",
        choices=[
            "quick",
            "ci",
            "ci-test",
            "policy",
            "fmt",
            "clippy",
            "build",
            "test-workspace",
            "test-kad-swarm",
        ],
        help=(
            "quick=policy+fmt+clippy; ci=quick+build+tests; "
            "ci-test=build+workspace tests+isolated kad_swarm"
        ),
    )
    args = parser.parse_args(argv)

    env = build_env()
    # Socket-binding tests bind X_LOCAL_IP, never loopback (the operator's VPN
    # split tunnel breaks 127.0.0.1). Fail fast for the test gates if it is unset
    # so a run can never silently bind/connect a broken loopback. CI exports
    # X_LOCAL_IP=127.0.0.1 on its loopback-only runners.
    if args.gate in {"ci", "ci-test", "test-workspace", "test-kad-swarm"} and not env.get(
        "X_LOCAL_IP"
    ):
        raise SystemExit(
            "X_LOCAL_IP must be set for the socket-binding tests (loopback is broken "
            "under the VPN split tunnel; CI sets X_LOCAL_IP=127.0.0.1)."
        )
    commands = commands_for_gate(args.gate)
    for label, command in commands:
        run_step(label, command, env)
    return 0


def build_env() -> dict[str, str]:
    env = os.environ.copy()
    target_dir = env.get("CARGO_TARGET_DIR")
    if target_dir:
        assert_outside_repo(Path(target_dir), "CARGO_TARGET_DIR")
        return env

    output_root = env.get("EMULEBB_WORKSPACE_OUTPUT_ROOT")
    if output_root:
        target = Path(output_root) / "builds" / "rust" / "target"
    else:
        runner_temp = env.get("RUNNER_TEMP")
        target = Path(runner_temp) / "emulebb-rust-target" if runner_temp else Path(
            tempfile.gettempdir()
        ) / "emulebb-rust-target"
    assert_outside_repo(target, "derived CARGO_TARGET_DIR")
    env["CARGO_TARGET_DIR"] = str(target)
    return env


def assert_outside_repo(path: Path, label: str) -> None:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return
    raise SystemExit(f"{label} must be outside the source checkout: {resolved}")


def commands_for_gate(gate: str) -> list[tuple[str, list[str]]]:
    steps = {
        "policy": [policy_step()],
        "fmt": [fmt_step()],
        "clippy": [clippy_step()],
        "build": [build_step()],
        "test-workspace": [test_workspace_step()],
        "test-kad-swarm": [test_kad_swarm_step()],
        "test-vpn-leak": [test_vpn_leak_step()],
        "quick": [policy_step(), fmt_step(), clippy_step()],
        "ci-test": [
            build_step(),
            test_workspace_step(),
            test_kad_swarm_step(),
            test_vpn_leak_step(),
        ],
    }
    if gate == "ci":
        return [
            policy_step(),
            fmt_step(),
            clippy_step(),
            build_step(),
            test_workspace_step(),
            test_kad_swarm_step(),
            test_vpn_leak_step(),
        ]
    return steps[gate]


def policy_step() -> tuple[str, list[str]]:
    return ("Rust client policy", [sys.executable, "tools/check_rust_client_policy.py"])


def fmt_step() -> tuple[str, list[str]]:
    return ("rustfmt check", ["cargo", "fmt", "--all", "--check"])


def clippy_step() -> tuple[str, list[str]]:
    return ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])


def build_step() -> tuple[str, list[str]]:
    return ("workspace build", ["cargo", "build", "--workspace", "--locked"])


def test_workspace_step() -> tuple[str, list[str]]:
    return (
        "workspace tests",
        ["cargo", "test", "--workspace", "--locked", "--", "--skip", "local_kad_swarm"],
    )


def test_kad_swarm_step() -> tuple[str, list[str]]:
    return (
        "isolated kad_swarm tests",
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
    print(f"==> {label}", flush=True)
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    raise SystemExit(main())
