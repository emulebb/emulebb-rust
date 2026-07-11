#!/usr/bin/env python3
"""Check local Rust-client policy guardrails."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "rust-client.toml"
OMISSIONS_PATH = ROOT / "policy" / "rust-client-omissions.toml"
TOOLCHAIN_PATH = ROOT / "rust-toolchain.toml"
P2P_BIND_FAIL_CLOSED_BOUNDARIES = (
    "crates/emulebb-core/src/lib.rs",
    "crates/emulebb-core/src/kad_hello.rs",
    "crates/emulebb-core/src/network_api.rs",
    "crates/emulebb-ed2k/src/ed2k_tcp/transport.rs",
    "crates/emulebb-ed2k/src/ed2k_tcp/listener/mod.rs",
    "crates/emulebb-ed2k/src/ed2k_server/session.rs",
    "crates/emulebb-ed2k/src/ed2k_server/udp_runtime.rs",
    "crates/emulebb-ed2k/src/stun.rs",
)
LARGEST_FILES_REPORTED_PER_KIND = 5
INLINE_TEST_MODULES_REPORTED = 10
INLINE_TEST_ADVISORY_LINES = 200


def main() -> int:
    policy = read_toml(POLICY_PATH)
    omissions = read_toml(OMISSIONS_PATH)
    errors: list[str] = []
    errors.extend(check_omission_registry(policy, omissions))
    errors.extend(check_review_reporting(policy, omissions))
    errors.extend(check_toolchain_pin())
    errors.extend(check_package_metadata())
    errors.extend(check_workspace_dependencies())
    errors.extend(check_tokio_features())
    errors.extend(check_release_output_paths())
    errors.extend(check_ipv4_only(policy))
    errors.extend(check_p2p_bind_fail_closed_boundaries())
    errors.extend(check_no_loopback_binds())
    errors.extend(check_egress_audit_is_test_only())
    if errors:
        print("rust client policy check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("rust client policy check passed")
    advisories = maintainability_advisories()
    if advisories:
        print("maintainability advisories (non-failing):")
        for advisory in advisories:
            print(f"- {advisory}")
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
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    # `git ls-files` retains paths deleted in the working tree until the deletion
    # is staged. Policy checks must support validating an intentional removal.
    return [rel for rel in files if (ROOT / rel).is_file()]


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


def check_toolchain_pin() -> list[str]:
    toolchain = read_toml(TOOLCHAIN_PATH).get("toolchain", {})
    channel = str(toolchain.get("channel", ""))
    components = set(toolchain.get("components", []))
    workspace = read_toml(ROOT / "Cargo.toml").get("workspace", {})
    rust_version = str(workspace.get("package", {}).get("rust-version", ""))
    errors = []
    if not toolchain_versions_match(channel, rust_version):
        errors.append(
            f"rust-toolchain channel {channel!r} does not match workspace rust-version "
            f"{rust_version!r}"
        )
    missing_components = sorted({"clippy", "rustfmt"}.difference(components))
    if missing_components:
        errors.append(
            "rust-toolchain is missing required components: " + ", ".join(missing_components)
        )
    for manifest_path in sorted(ROOT.glob("crates/*/Cargo.toml")):
        package = read_toml(manifest_path).get("package", {})
        if package.get("rust-version", {}).get("workspace") is not True:
            rel = manifest_path.relative_to(ROOT).as_posix()
            errors.append(f"{rel} must inherit package.rust-version from the workspace")
    expected_action = f"dtolnay/rust-toolchain@{channel}"
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        for action in re.findall(r"dtolnay/rust-toolchain@[^\s]+", text):
            if action != expected_action:
                rel = workflow.relative_to(ROOT).as_posix()
                errors.append(f"{rel} uses {action}, expected {expected_action}")
    return errors


def check_package_metadata() -> list[str]:
    workspace_package = read_toml(ROOT / "Cargo.toml").get("workspace", {}).get("package", {})
    errors = []
    if workspace_package.get("license") != "GPL-2.0-only":
        errors.append("workspace package license must be GPL-2.0-only")
    if workspace_package.get("publish") is not False:
        errors.append("workspace package publish must be false")
    for manifest_path in sorted(ROOT.glob("crates/*/Cargo.toml")):
        package = read_toml(manifest_path).get("package", {})
        rel = manifest_path.relative_to(ROOT).as_posix()
        if package.get("license", {}).get("workspace") is not True:
            errors.append(f"{rel} must inherit package.license from the workspace")
        if package.get("publish", {}).get("workspace") is not True:
            errors.append(f"{rel} must inherit package.publish from the workspace")
    return errors


def check_workspace_dependencies() -> list[str]:
    """Require registry dependency versions to have one workspace authority."""
    errors = []
    section_names = ("dependencies", "dev-dependencies", "build-dependencies")
    for manifest_path in sorted(ROOT.glob("crates/*/Cargo.toml")):
        manifest = read_toml(manifest_path)
        rel = manifest_path.relative_to(ROOT).as_posix()
        dependency_tables = [
            (section, manifest.get(section, {})) for section in section_names
        ]
        for target, target_config in manifest.get("target", {}).items():
            dependency_tables.extend(
                (f"target.{target}.{section}", target_config.get(section, {}))
                for section in section_names
            )
        for section, dependencies in dependency_tables:
            for name, declaration in dependencies.items():
                directly_versioned = isinstance(declaration, str) or (
                    isinstance(declaration, dict) and "version" in declaration
                )
                if directly_versioned:
                    errors.append(
                        f"{rel} {section}.{name} must inherit its registry version "
                        "from [workspace.dependencies]"
                    )
    return errors


def check_tokio_features() -> list[str]:
    """Prevent a broad Tokio feature set from silently returning."""
    errors = []
    manifests = [ROOT / "Cargo.toml", *sorted(ROOT.glob("crates/*/Cargo.toml"))]
    section_names = ("dependencies", "dev-dependencies", "build-dependencies")
    for manifest_path in manifests:
        manifest = read_toml(manifest_path)
        tables = [manifest.get("workspace", {}).get("dependencies", {})]
        tables.extend(manifest.get(section, {}) for section in section_names)
        tables.extend(
            target_config.get(section, {})
            for target_config in manifest.get("target", {}).values()
            for section in section_names
        )
        for dependencies in tables:
            declaration = dependencies.get("tokio", {})
            features = declaration.get("features", []) if isinstance(declaration, dict) else []
            if "full" in features:
                rel = manifest_path.relative_to(ROOT).as_posix()
                errors.append(f"{rel} must declare only the Tokio features it uses, not 'full'")
    return errors


def toolchain_versions_match(channel: str, rust_version: str) -> bool:
    channel_parts = channel.split(".")
    version_parts = rust_version.split(".")
    return (
        len(channel_parts) == 3
        and len(version_parts) == 2
        and channel_parts[:2] == version_parts
        and all(part.isdigit() for part in channel_parts + version_parts)
    )


def check_release_output_paths(workflow_text: str | None = None) -> list[str]:
    """Keep release build products and archives outside the source workspace."""
    workflow = ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "CARGO_TARGET_DIR: ${{ runner.temp }}/emulebb-rust-target": "external Cargo target",
        "RELEASE_OUT_DIR: ${{ runner.temp }}/emulebb-rust-dist": "external release archive",
        '--target-dir "$CARGO_TARGET_DIR/release"': "explicit external package target",
        '--out "$RELEASE_OUT_DIR"': "explicit external package output",
    }
    return [
        f".github/workflows/release.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]


def maintainability_advisories(files: list[str] | None = None) -> list[str]:
    """Report review signals without turning source length into a policy limit."""
    rust_files = tracked_files("*.rs") if files is None else files
    production: list[tuple[str, int]] = []
    tests: list[tuple[str, int]] = []
    inline_tests: list[tuple[str, int]] = []
    for rel in rust_files:
        normalized = rel.replace("\\", "/")
        path = ROOT / rel
        lines = count_lines(path)
        target = tests if is_test_path(normalized) else production
        target.append((normalized, lines))
        if target is production:
            text = path.read_text(encoding="utf-8")
            largest_inline = max(inline_test_module_line_counts(text), default=0)
            if largest_inline >= INLINE_TEST_ADVISORY_LINES:
                inline_tests.append((normalized, largest_inline))

    advisories = ranked_file_advisories("production", production)
    advisories.extend(ranked_file_advisories("test", tests))
    largest_inline_tests = sorted(inline_tests, key=lambda item: (-item[1], item[0]))[
        :INLINE_TEST_MODULES_REPORTED
    ]
    for path, lines in largest_inline_tests:
        advisories.append(
            f"{path} contains an inline test module of about {lines} lines; "
            "review whether it belongs in a sibling test module"
        )
    return advisories


def ranked_file_advisories(kind: str, files: list[tuple[str, int]]) -> list[str]:
    largest = sorted(files, key=lambda item: (-item[1], item[0]))[
        :LARGEST_FILES_REPORTED_PER_KIND
    ]
    return [
        f"large {kind} file: {path} ({lines} lines); review responsibility boundaries when touched"
        for path, lines in largest
    ]


def inline_test_module_line_counts(text: str) -> list[int]:
    """Estimate braced inline #[cfg(test)] module sizes for advisory output."""
    module = re.compile(
        r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{",
        re.MULTILINE,
    )
    counts = []
    for match in module.finditer(text):
        open_brace = text.find("{", match.start(), match.end())
        depth = 0
        for cursor in range(open_brace, len(text)):
            if text[cursor] == "{":
                depth += 1
            elif text[cursor] == "}":
                depth -= 1
                if depth == 0:
                    counts.append(text.count("\n", match.start(), cursor + 1) + 1)
                    break
    return counts


def is_test_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    pure_path = PurePosixPath(normalized)
    return (
        "/tests/" in f"/{normalized}"
        or pure_path.name == "tests.rs"
        or pure_path.stem.endswith("_tests")
    )


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


# A real socket bind (`.bind(` / `::bind(`) onto a loopback literal. Matches the
# bind call itself, not address-as-DATA (config fields `bind_addr: Some("127...")`,
# JSON bodies, contact IPs, MockTransport addresses) which never call `bind(`.
LOOPBACK_BIND = re.compile(
    r"\bbind\(\s*\(?\s*"
    r'(IpAddr::V4\(Ipv4Addr::LOCALHOST|Ipv4Addr::LOCALHOST|"127\.0\.0\.1|"localhost)'
)


def check_no_loopback_binds() -> list[str]:
    """Real socket binds must use X_LOCAL_IP, never a loopback literal.

    The operator's VPN split tunnel breaks 127.0.0.1 (os error 10049), so a
    hardcoded-loopback bind makes the gate flaky here. Tests bind X_LOCAL_IP via a
    `test_bind_ip()` helper (CI exports X_LOCAL_IP=127.0.0.1). Address-as-data
    usages are unaffected because they never call `bind(`.
    """
    errors = []
    for rel in tracked_files("*.rs"):
        normalized = rel.replace("\\", "/")
        text = (ROOT / rel).read_text(encoding="utf-8")
        if LOOPBACK_BIND.search(text):
            errors.append(
                f"{normalized} binds a socket to a loopback literal; bind X_LOCAL_IP "
                "via test_bind_ip() (loopback is broken on the VPN split tunnel)"
            )
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


def check_egress_audit_is_test_only() -> list[str]:
    """The `egress-audit` seam (RUST-FEAT-005 leak test) must never reach a
    release build: no crate may put it in a `default` feature set, and the daemon
    binary crate must not reference it at all (nor enable it on a dependency)."""
    errors: list[str] = []
    feature = "egress-audit"
    for cargo in sorted(ROOT.glob("crates/*/Cargo.toml")):
        try:
            manifest = read_toml(cargo)
        except Exception as exc:  # noqa: BLE001 - surface a bad manifest as an error
            errors.append(f"could not parse {cargo.relative_to(ROOT)}: {exc}")
            continue
        rel = str(cargo.relative_to(ROOT)).replace("\\", "/")
        name = manifest.get("package", {}).get("name", "")
        default = manifest.get("features", {}).get("default", [])
        if feature in default:
            errors.append(f"{rel} lists '{feature}' in [features].default (must be test-only)")
        if name == "emulebb-daemon" and feature in cargo.read_text(encoding="utf-8"):
            errors.append(
                f"{rel} references '{feature}'; the daemon binary must never enable the "
                "test-only egress-audit seam"
            )
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
