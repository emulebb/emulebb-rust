#!/usr/bin/env python3
"""Check local Rust-client policy guardrails."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "rust-client.toml"
OMISSIONS_PATH = ROOT / "policy" / "rust-client-omissions.toml"
P2P_BIND_FAIL_CLOSED_BOUNDARIES = (
    "crates/emulebb-core/src/lib.rs",
    "crates/emulebb-core/src/kad_hello.rs",
    "crates/emulebb-ed2k/src/ed2k_tcp/transport.rs",
    "crates/emulebb-ed2k/src/ed2k_tcp/listener/mod.rs",
    "crates/emulebb-ed2k/src/ed2k_server/session.rs",
    "crates/emulebb-ed2k/src/ed2k_server/udp_runtime.rs",
)


def main() -> int:
    policy = read_toml(POLICY_PATH)
    omissions = read_toml(OMISSIONS_PATH)
    errors: list[str] = []
    errors.extend(check_omission_registry(policy, omissions))
    errors.extend(check_review_reporting(policy, omissions))
    errors.extend(check_rust_file_sizes(policy))
    errors.extend(check_ipv4_only(policy))
    errors.extend(check_p2p_bind_fail_closed_boundaries())
    if errors:
        print("rust client policy check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("rust client policy check passed")
    return 0


def read_toml(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def tracked_files(pattern: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", pattern],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def count_lines(path: Path) -> int:
    with path.open("r", encoding="utf-8") as handle:
        return sum(1 for _ in handle)


def check_omission_registry(policy: dict, omissions: dict) -> list[str]:
    expected = policy["protocol"]["omission_registry"].replace("\\", "/")
    actual = str(OMISSIONS_PATH.relative_to(ROOT)).replace("\\", "/")
    errors = []
    if expected != actual:
        errors.append(f"protocol.omission_registry points to {expected}, expected {actual}")
    required_fields = {"id", "area", "stock_behavior", "rust_behavior", "reason", "compatibility"}
    seen_ids: set[str] = set()
    for index, entry in enumerate(omissions.get("omissions", []), start=1):
        missing = sorted(required_fields.difference(entry))
        if missing:
            errors.append(f"omission #{index} is missing fields: {', '.join(missing)}")
        entry_id = entry.get("id")
        if entry_id in seen_ids:
            errors.append(f"duplicate omission id: {entry_id}")
        if entry_id:
            seen_ids.add(entry_id)
    if not seen_ids:
        errors.append("omission registry must contain at least one entry")
    return errors


def check_review_reporting(policy: dict, omissions: dict) -> list[str]:
    reporting = policy.get("review_reporting", {})
    excluded = set(reporting.get("excluded_surface_ids", []))
    omission_ids = {entry.get("id") for entry in omissions.get("omissions", []) if entry.get("id")}
    errors = []
    missing = sorted(excluded.difference(omission_ids))
    for entry_id in missing:
        errors.append(f"review_reporting excluded surface is not in omission registry: {entry_id}")
    if reporting.get("intentional_omissions_are_not_gaps") and not excluded:
        errors.append("review_reporting excludes no surfaces while intentional omissions are not gaps")
    return errors


def check_rust_file_sizes(policy: dict) -> list[str]:
    structure = policy["structure"]
    max_rs_lines = int(structure["max_rs_lines"])
    max_test_rs_lines = int(structure["max_test_rs_lines"])
    allowlist = {
        entry["path"].replace("\\", "/"): int(entry["hard_limit_lines"])
        for entry in structure.get("large_file_allowlist", [])
    }
    errors = []
    for rel in tracked_files("*.rs"):
        normalized = rel.replace("\\", "/")
        lines = count_lines(ROOT / rel)
        budget = max_test_rs_lines if is_test_path(normalized) else max_rs_lines
        if normalized in allowlist:
            hard_limit = allowlist[normalized]
            if lines > hard_limit:
                errors.append(f"{normalized} has {lines} lines over hard allowlist cap {hard_limit}")
            continue
        if lines > budget:
            errors.append(f"{normalized} has {lines} lines over budget {budget}")
    return errors


def is_test_path(path: str) -> bool:
    return "/tests/" in path or path.endswith("/tests.rs")


def check_ipv4_only(policy: dict) -> list[str]:
    allowed = {
        path.replace("\\", "/")
        for path in policy.get("ipv4_only", {}).get("allowed_ipv6_mentions", [])
    }
    errors = []
    ipv6_true = re.compile(r"\bipv6\s*:\s*true\b")
    enabled_types = re.compile(r"\b(Ipv6Addr|SocketAddrV6)\b")
    for rel in tracked_files("*.rs"):
        normalized = rel.replace("\\", "/")
        text = (ROOT / rel).read_text(encoding="utf-8")
        if ipv6_true.search(text):
            errors.append(f"{normalized} enables IPv6; Rust client policy is IPv4-only")
        if normalized not in allowed and ("IpAddr::V6" in text or "ipv6" in text.lower()):
            errors.append(f"{normalized} mentions IPv6 outside the IPv4-only rejection allowlist")
        if normalized not in allowed and enabled_types.search(text):
            errors.append(f"{normalized} uses IPv6 address types outside the allowlist")
    missing_allowlist = sorted(path for path in allowed if not (ROOT / path).exists())
    for path in missing_allowlist:
        errors.append(f"IPv6 mention allowlist path does not exist: {path}")
    return errors


def check_p2p_bind_fail_closed_boundaries() -> list[str]:
    """Reject optional tunnel pinning in public P2P data-plane boundaries."""
    errors = []
    for rel in P2P_BIND_FAIL_CLOSED_BOUNDARIES:
        path = ROOT / rel
        if not path.exists():
            errors.append(f"P2P bind fail-closed boundary path does not exist: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        if "resolve_bind_if_index(" in text:
            errors.append(
                f"{rel} uses optional bind ifIndex resolution; use require_bind_if_index "
                "before opening public P2P sockets"
            )
        for call in function_calls(text, "pin_egress_to_interface"):
            if "None" in call:
                errors.append(f"{rel} pins public P2P egress with no interface index")
            if "resolve_bind_if_index(" in call:
                errors.append(f"{rel} pins public P2P egress from optional ifIndex resolution")
    return errors


def function_calls(text: str, name: str) -> list[str]:
    calls = []
    needle = f"{name}("
    start = 0
    while True:
        index = text.find(needle, start)
        if index == -1:
            return calls
        depth = 0
        for cursor in range(index + len(name), len(text)):
            char = text[cursor]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    calls.append(text[index : cursor + 1])
                    start = cursor + 1
                    break
        else:
            calls.append(text[index:])
            return calls


if __name__ == "__main__":
    raise SystemExit(main())
