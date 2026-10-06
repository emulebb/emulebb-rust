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
OMISSIONS_HISTORY_PATH = ROOT / "policy" / "rust-client-omissions-history.toml"
TOOLCHAIN_PATH = ROOT / "rust-toolchain.toml"
OMISSION_DISPOSITIONS = {
    "protocol_defer",
    "protocol_drop_approved",
    "protocol_fix",
    "rust_native_remove",
    "rust_native_replace",
}
RESOLVED_OMISSION_DISPOSITIONS = {
    "fixed",
    "rust_native_remove",
    "rust_native_replace",
}
REVIEW_DISPOSITION_BY_DISPOSITION = {
    "protocol_defer": "defer",
    "protocol_drop_approved": "permanent-drop",
    "protocol_fix": "fix",
    "rust_native_remove": "remove",
    "rust_native_replace": "replace",
}
NON_GAP_DISPOSITIONS = {"fixed", "protocol_drop_approved", "rust_native_remove"}
FORBIDDEN_RUST_NATIVE_SURFACE = {
    "newAutoUp": "legacy GUI preference field",
    "newAutoDown": "legacy GUI preference field",
    "downloadAutoBroadbandIo": "legacy GUI preference toggle; broadband-optimized IO is not a compatibility switch",
    "/api/v1/transfers/{hash}/operations/preview": "fake transfer preview REST operation",
    "operations/preview": "fake transfer preview REST operation",
    "preview_transfer": "fake transfer preview implementation",
    "transfer_preview": "fake transfer preview handler",
    "reset_legacy_nat_backend_order": "retired NAT settings repair bridge",
}
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
CHANGED_FILES_REPORTED = 20
EXPECTED_BEHAVIOR_AUTHORITY = {
    "wire_protocol": "stock-community-emule",
    "operational_limits": "emulebb-mfc",
    "io_behavior": "emulebb-mfc",
    "implementation_model": "rust-native-async",
    "conflict_precedence": "stock-wire-protocol",
}


def main() -> int:
    policy = read_toml(POLICY_PATH)
    omissions = read_toml(OMISSIONS_PATH)
    omission_history = read_toml(OMISSIONS_HISTORY_PATH)
    errors: list[str] = []
    errors.extend(check_behavior_authority(policy))
    errors.extend(check_omission_registry(policy, omissions))
    errors.extend(check_omission_history(omissions, omission_history))
    errors.extend(check_review_reporting(policy, omissions))
    errors.extend(check_toolchain_pin())
    errors.extend(check_package_metadata())
    errors.extend(check_workspace_dependencies())
    errors.extend(check_tokio_features())
    errors.extend(check_logging_policy())
    errors.extend(check_supply_chain_policy())
    errors.extend(check_security_policy())
    errors.extend(check_github_action_pins())
    errors.extend(check_workflow_lint_ci())
    errors.extend(check_scheduled_fuzz_ci())
    errors.extend(check_live_rest_openapi_ci())
    errors.extend(check_release_ci_gate())
    errors.extend(check_release_build_identity())
    errors.extend(check_release_image_promotion())
    errors.extend(check_release_image_security())
    errors.extend(check_lint_suppressions())
    errors.extend(check_release_output_paths())
    errors.extend(check_ipv4_only(policy))
    errors.extend(check_p2p_bind_fail_closed_boundaries())
    errors.extend(check_egress_audit_is_test_only())
    errors.extend(check_no_legacy_rust_native_surface())
    errors.extend(check_current_only_metadata_schema())
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


def check_behavior_authority(policy: dict) -> list[str]:
    """Keep the stock-wire/MFC-operations authority split explicit."""
    authority = policy.get("behavior_authority", {})
    errors = []
    for key, expected in EXPECTED_BEHAVIOR_AUTHORITY.items():
        actual = authority.get(key)
        if actual != expected:
            errors.append(
                f"behavior_authority.{key} is {actual!r}; expected {expected!r}"
            )
    unknown = sorted(set(authority).difference(EXPECTED_BEHAVIOR_AUTHORITY))
    if unknown:
        errors.append(
            "behavior_authority contains unsupported fields: " + ", ".join(unknown)
        )
    return errors


def check_omission_registry(policy: dict, omissions: dict) -> list[str]:
    expected = policy["protocol"]["omission_registry"].replace("\\", "/")
    actual = str(OMISSIONS_PATH.relative_to(ROOT)).replace("\\", "/")
    errors = []
    if expected != actual:
        errors.append(f"protocol.omission_registry points to {expected}, expected {actual}")
    required_fields = {
        "id",
        "area",
        "stock_behavior",
        "rust_behavior",
        "reason",
        "compatibility",
        "disposition",
        "owner",
        "target",
        "beta_blocker",
    }
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
        disposition = entry.get("disposition")
        if disposition is not None and disposition not in OMISSION_DISPOSITIONS:
            errors.append(
                f"omission {entry_id or f'#{index}'} has unsupported disposition: {disposition}"
            )
        review_disposition = entry.get("review_disposition")
        expected_review = REVIEW_DISPOSITION_BY_DISPOSITION.get(str(disposition))
        if review_disposition is not None and review_disposition != expected_review:
            errors.append(
                f"omission {entry_id or f'#{index}'} review_disposition "
                f"{review_disposition!r} contradicts disposition {disposition!r}; "
                f"expected {expected_review!r}"
            )
        if "beta_blocker" in entry and not isinstance(entry["beta_blocker"], bool):
            errors.append(f"omission {entry_id or f'#{index}'} beta_blocker must be boolean")
        for field in ("owner", "target"):
            if field in entry and not str(entry[field]).strip():
                errors.append(f"omission {entry_id or f'#{index}'} {field} must not be empty")
    if not seen_ids:
        errors.append("omission registry must contain at least one entry")
    return errors


def check_omission_history(omissions: dict, history: dict) -> list[str]:
    """Keep resolved audit records outside the active beta omission board."""
    active_ids = {
        entry.get("id")
        for entry in omissions.get("omissions", [])
        if entry.get("id")
    }
    errors = []
    seen_ids: set[str] = set()
    for index, entry in enumerate(history.get("resolved_omissions", []), start=1):
        entry_id = entry.get("id")
        if not entry_id:
            errors.append(f"resolved omission #{index} is missing id")
            continue
        if entry_id in seen_ids:
            errors.append(f"duplicate resolved omission id: {entry_id}")
        seen_ids.add(entry_id)
        if entry_id in active_ids:
            errors.append(f"resolved omission {entry_id} also appears in active registry")
        disposition = entry.get("disposition")
        if disposition not in RESOLVED_OMISSION_DISPOSITIONS:
            errors.append(
                f"resolved omission {entry_id} has unresolved disposition: {disposition}"
            )
    return errors


def check_review_reporting(policy: dict, omissions: dict) -> list[str]:
    reporting = policy.get("review_reporting", {})
    excluded = set(reporting.get("excluded_surface_ids", []))
    omission_ids = {entry.get("id") for entry in omissions.get("omissions", []) if entry.get("id")}
    errors = []
    missing = sorted(excluded.difference(omission_ids))
    for entry_id in missing:
        errors.append(f"review_reporting excluded surface is not in omission registry: {entry_id}")
    by_id = {entry["id"]: entry for entry in omissions.get("omissions", []) if entry.get("id")}
    for entry_id in sorted(excluded.intersection(omission_ids)):
        disposition = by_id[entry_id].get("disposition")
        if disposition not in NON_GAP_DISPOSITIONS:
            errors.append(
                f"review_reporting excluded surface {entry_id} has disposition "
                f"{disposition!r}; expected one of {sorted(NON_GAP_DISPOSITIONS)}"
            )
    if reporting.get("intentional_omissions_are_not_gaps") and not excluded:
        errors.append("review_reporting excludes no surfaces while intentional omissions are not gaps")
    return errors


def check_no_legacy_rust_native_surface() -> list[str]:
    """Keep non-protocol Rust REST/settings/UI surface free of old GUI residue."""
    errors = []
    checked_roots = (
        "crates/emulebb-settings",
        "crates/emulebb-rest",
        "crates/emulebb-core",
    )
    files = [
        rel
        for root in checked_roots
        for rel in tracked_files(f"{root}/*")
        if rel.endswith((".rs", ".slint", ".toml", ".md", ".yaml", ".yml"))
    ]
    for rel in sorted(set(files)):
        text = (ROOT / rel).read_text(encoding="utf-8")
        normalized = rel.replace("\\", "/")
        for needle, reason in FORBIDDEN_RUST_NATIVE_SURFACE.items():
            if needle in text:
                errors.append(f"{normalized} contains {reason}: {needle}")
    return errors


METADATA_SCHEMA_FORBIDDEN_PATTERNS = (
    (
        re.compile(r"\bfn\s+reset_schema\b"),
        "Rust metadata reset helper; stale databases must fail and require a fresh profile",
    ),
    (
        re.compile(r"\breset_schema\s*\("),
        "Rust metadata schema reset call; stale databases must require a fresh profile",
    ),
    (
        re.compile(r"\bALTER\s+TABLE\b", re.IGNORECASE),
        "Rust metadata ALTER TABLE migration; schema changes must be current-only",
    ),
    (
        re.compile(r"\bDROP\s+(?:TABLE|VIEW|TRIGGER)\b", re.IGNORECASE),
        "Rust metadata drop/recreate migration; stale databases must require a fresh profile",
    ),
)


def check_current_only_metadata_schema(file_texts: dict[str, str] | None = None) -> list[str]:
    """Reject Rust-side metadata migrations and retired schema fields."""

    if file_texts is None:
        files = {
            rel.replace("\\", "/"): (ROOT / rel).read_text(encoding="utf-8")
            for rel in tracked_files("crates/emulebb-metadata/src/*")
            if rel.endswith((".rs", ".sql"))
        }
    else:
        files = {rel.replace("\\", "/"): text for rel, text in file_texts.items()}

    errors: list[str] = []
    for rel, text in files.items():
        if rel.endswith("schema.sql") and re.search(
            r"CREATE\s+TABLE\s+shared_directory_roots\b.*\brecursive\b",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            errors.append(
                f"{rel} contains retired shared_directory_roots.recursive; "
                "metadata schema must be current-only"
            )
        if not rel.endswith(".rs"):
            continue
        for pattern, reason in METADATA_SCHEMA_FORBIDDEN_PATTERNS:
            if pattern.search(text):
                errors.append(f"{rel} contains {reason}")
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
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        rel = workflow.relative_to(ROOT).as_posix()
        toolchain_lines = [line for line in text.splitlines() if "dtolnay/rust-toolchain@" in line]
        for line in toolchain_lines:
            match = re.search(
                r"dtolnay/rust-toolchain@([0-9a-f]{40})\s+#\s*([^\s]+)", line
            )
            if match is None or match.group(2) != channel:
                errors.append(
                    f"{rel} must pin dtolnay/rust-toolchain by commit and annotate # {channel}"
                )
    return errors


def check_package_metadata() -> list[str]:
    workspace = read_toml(ROOT / "Cargo.toml").get("workspace", {})
    workspace_package = workspace.get("package", {})
    errors = []
    if workspace_package.get("license") != "GPL-2.0-only":
        errors.append("workspace package license must be GPL-2.0-only")
    if workspace_package.get("publish") is not False:
        errors.append("workspace package publish must be false")
    if workspace.get("lints", {}).get("rust", {}).get("unsafe_op_in_unsafe_fn") != "deny":
        errors.append("workspace rust lint unsafe_op_in_unsafe_fn must be deny")
    if (
        workspace.get("lints", {}).get("clippy", {}).get("undocumented_unsafe_blocks")
        != "deny"
    ):
        errors.append("workspace Clippy lint undocumented_unsafe_blocks must be deny")
    for manifest_path in sorted(ROOT.glob("crates/*/Cargo.toml")):
        manifest = read_toml(manifest_path)
        package = manifest.get("package", {})
        rel = manifest_path.relative_to(ROOT).as_posix()
        if package.get("license", {}).get("workspace") is not True:
            errors.append(f"{rel} must inherit package.license from the workspace")
        if package.get("publish", {}).get("workspace") is not True:
            errors.append(f"{rel} must inherit package.publish from the workspace")
        if manifest.get("lints", {}).get("workspace") is not True:
            errors.append(f"{rel} must inherit workspace lints")
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


def check_logging_policy() -> list[str]:
    """Keep regular-daemon logging useful, bounded, and consistent by default."""
    errors = []
    workspace = read_toml(ROOT / "Cargo.toml")["workspace"]["dependencies"]
    daemon = read_toml(ROOT / "crates" / "emulebb-daemon" / "Cargo.toml")
    subscriber = workspace.get("tracing-subscriber", {})
    subscriber_features = set(subscriber.get("features", []))
    if not {"env-filter", "json"}.issubset(subscriber_features):
        errors.append(
            "tracing-subscriber must enable env-filter and json for regular logging"
        )
    if "tracing-appender" not in workspace:
        errors.append("workspace dependencies must include tracing-appender")
    if daemon.get("dependencies", {}).get("tracing-appender", {}).get("workspace") is not True:
        errors.append("emulebb-daemon must inherit tracing-appender from the workspace")

    source = (ROOT / "crates" / "emulebb-daemon" / "src" / "logging.rs").read_text(
        encoding="utf-8"
    )
    required_fragments = {
        "INFO default": "const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::INFO;",
        "daily rotation": ".rotation(Rotation::DAILY)",
        "eight-file retention": "const RETAINED_LOG_FILES: usize = 8;",
        "JSONL suffix": 'const LOG_FILE_SUFFIX: &str = "jsonl";',
        "bounded writer queue": "const FILE_BUFFERED_LINES: usize = 8192;",
        "non-blocking lossy writer": ".lossy(true)",
        "profile-local log directory": "profile_dir.join(LOG_DIRECTORY_NAME)",
    }
    for policy, fragment in required_fragments.items():
        if fragment not in source:
            errors.append(f"regular logging must retain its {policy}")
    if source.count(".with_filter(build_filter(&filter_spec))") != 3:
        errors.append("console, REST, and file logging must use the same RUST_LOG filter")

    rest_source = (ROOT / "crates" / "emulebb-rest" / "src" / "log_buffer.rs").read_text(
        encoding="utf-8"
    )
    if "const LOG_CAPACITY: usize = 2000;" not in rest_source:
        errors.append("REST recent logs must retain the 2000-entry bound")
    if "const MAX_LOG_MESSAGE_BYTES: usize = 4096;" not in rest_source:
        errors.append("REST recent log messages must retain the 4 KiB bound")
    return errors


def check_supply_chain_policy() -> list[str]:
    """Keep the audited cargo-deny gates enabled and immutable in CI."""
    deny = read_toml(ROOT / "deny.toml")
    errors = []
    for key in ("unknown-registry", "unknown-git"):
        if deny.get("sources", {}).get(key) != "deny":
            errors.append(f"deny.toml sources.{key} must be 'deny'")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    if not re.search(
        r"EmbarkStudios/cargo-deny-action@[0-9a-f]{40}\s+#\s*v2\b", workflow
    ):
        errors.append(".github/workflows/ci.yml must pin cargo-deny-action v2 by commit")
    command = "command: check advisories licenses sources"
    if command not in workflow:
        errors.append(f".github/workflows/ci.yml is missing cargo-deny guard: {command}")
    return errors


def check_security_policy(policy_text: str | None = None) -> list[str]:
    """Keep a private vulnerability path and honest support boundary public."""

    path = ROOT / "SECURITY.md"
    if policy_text is None and not path.is_file():
        return ["SECURITY.md is missing"]
    text = path.read_text(encoding="utf-8") if policy_text is None else policy_text
    required = {
        "0.1.0-beta.2": "current supported beta",
        "0.1.0-beta.1` and older": "unsupported older-release boundary",
        "https://github.com/emulebb/emulebb-rust/security/advisories/new":
            "private vulnerability reporting link",
        "Do not open a public issue": "public-disclosure warning",
        "no guaranteed response SLA": "honest response boundary",
        "fresh profile": "current-only schema security guidance",
    }
    return [
        f"SECURITY.md is missing {description}"
        for fragment, description in required.items()
        if fragment not in text
    ]


def check_github_action_pins() -> list[str]:
    """Require every external workflow action to use an immutable commit SHA."""
    errors = []
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        rel = workflow.relative_to(ROOT).as_posix()
        for action, reference in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", text):
            if not action_ref_is_immutable(reference):
                errors.append(f"{rel} uses mutable action ref {action}@{reference}")
    return errors


def action_ref_is_immutable(reference: str) -> bool:
    return re.fullmatch(r"[0-9a-f]{40}", reference) is not None


def check_workflow_lint_ci(workflow_text: str | None = None) -> list[str]:
    """Require GitHub-aware workflow validation in normal CI."""

    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "workflow-lint:": "workflow lint job",
        "name: GitHub Actions workflow lint": "named workflow lint check",
        'go-version: "1.27.1"': "pinned Go toolchain",
        "cache: false": "disabled Go cache for the tool-only job",
    }
    errors = [
        f".github/workflows/ci.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]
    setup_go = re.search(r"actions/setup-go@([^\s#]+)", text)
    if setup_go is None or not action_ref_is_immutable(setup_go.group(1)):
        errors.append(
            ".github/workflows/ci.yml must pin actions/setup-go by full commit SHA"
        )
    actionlint = re.search(
        r"go run github\.com/rhysd/actionlint/cmd/actionlint@([^\s]+)", text
    )
    if actionlint is None or not action_ref_is_immutable(actionlint.group(1)):
        errors.append(
            ".github/workflows/ci.yml must pin actionlint by full commit SHA"
        )
    return errors


def check_scheduled_fuzz_ci(workflow_text: str | None = None) -> list[str]:
    """Keep every untrusted protocol parser under bounded scheduled fuzzing."""

    workflow = ROOT / ".github" / "workflows" / "fuzz.yml"
    if workflow_text is None and not workflow.is_file():
        return [".github/workflows/fuzz.yml is missing"]
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "schedule:": "weekly schedule",
        "workflow_dispatch:": "manual dispatch",
        "FUZZ_TOOLCHAIN: nightly-2026-07-15": "pinned nightly toolchain",
        "cargo-fuzz --version 0.13.2 --locked": "pinned cargo-fuzz install",
        "CARGO_TARGET_DIR: ${{ runner.temp }}/": "external Cargo target",
        "FUZZ_OUTPUT: ${{ runner.temp }}/": "external fuzz output root",
        "-max_total_time=60": "bounded per-target runtime",
        "-timeout=10": "per-input timeout",
        '-artifact_prefix="$artifacts/"': "external crash artifact path",
        "if: always()": "failure evidence retention",
        "name: parser-fuzz-${{ github.sha }}": "commit-specific evidence artifact",
    }
    errors = [
        f".github/workflows/fuzz.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]
    for target in (
        "ed2k_server_parsers",
        "ed2k_peer_tcp_parsers",
        "ed2k_client_udp_parser",
        "kad_packet_parser",
    ):
        if target not in text:
            errors.append(f".github/workflows/fuzz.yml is missing target {target}")
    for repository in ("emulebb/emulebb-miniupnp", "emulebb/emulebb-libpcpnatpmp"):
        checkout = re.compile(
            rf"repository:\s*{re.escape(repository)}\s+ref:\s*\$\{{\{{\s*env\.([A-Z]+)_REF\s*\}}\}}",
            re.MULTILINE,
        ).search(text)
        if checkout is None:
            errors.append(
                f".github/workflows/fuzz.yml must check out pinned {repository} source"
            )
    refs = re.findall(r"(?m)^\s+(?:MINIUPNP|PCPNATPMP)_REF:\s*([^\s]+)\s*$", text)
    if len(refs) != 2 or any(not action_ref_is_immutable(ref) for ref in refs):
        errors.append(
            ".github/workflows/fuzz.yml must pin both native source revisions by full commit SHA"
        )
    return errors


def check_live_rest_openapi_ci(workflow_text: str | None = None) -> list[str]:
    """Keep the live Rust response/OpenAPI gate attached to tested Linux bytes."""

    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "rest-openapi:": "live REST/OpenAPI job",
        "needs: build-test": "dependency on the build/test matrix",
        "name: emulebb-rust-Linux-X64-${{ github.sha }}": "tested Linux daemon artifact",
        "EMULEBB_WORKSPACE_OUTPUT_ROOT: ${{ runner.temp }}/emulebb-rust-out": "external output root",
        "python scripts/rust-rest-openapi-ci.py": "live response conformance command",
        "name: rust-rest-openapi-${{ github.sha }}": "retained conformance evidence",
    }
    errors = [
        f".github/workflows/ci.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]
    for repository in ("emulebb/emulebb-build-tests", "emulebb/emulebb-tooling"):
        checkout = re.compile(
            rf"repository:\s*{re.escape(repository)}\s+ref:\s*([0-9a-f]+)",
            re.MULTILINE,
        ).search(text)
        if checkout is None or not action_ref_is_immutable(checkout.group(1)):
            errors.append(
                f".github/workflows/ci.yml must pin {repository} by full commit SHA"
            )
    return errors


def check_release_ci_gate(
    workflow_text: str | None = None,
    nightly_text: str | None = None,
) -> list[str]:
    """Require release packaging to depend on green CI for the exact source commit."""

    workflow = ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "verify-ci:": "source CI verification job",
        "name: Require green source CI": "named release CI gate",
        "checks: read": "check-run read permission",
        'echo "sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"': "immutable source resolution",
        'python tools/nightly_release.py verify-ci --sha "${{ steps.source.outputs.sha }}"':
            "exact-source CI verification command",
        "needs: verify-ci": "packaging dependency on the release CI gate",
    }
    errors = [
        f".github/workflows/release.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]
    nightly = ROOT / ".github" / "workflows" / "nightly.yml"
    nightly_source = (
        nightly.read_text(encoding="utf-8") if nightly_text is None else nightly_text
    )
    package_job = re.search(
        r"(?ms)^  package:\s*$\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
        nightly_source,
    )
    if package_job is None or not re.search(
        r"(?m)^      checks:\s*read\s*$",
        package_job.group("body"),
    ):
        errors.append(
            ".github/workflows/nightly.yml reusable release caller must grant checks: read"
        )
    return errors


def check_release_image_promotion(workflow_text: str | None = None) -> list[str]:
    """Require GHCR publication to promote the candidate that passed smoke testing."""

    workflow = ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    publish_job = re.search(
        r"(?ms)^  publish-image:\s*$\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
        text,
    )
    if publish_job is None:
        return [".github/workflows/release.yml is missing the image publishing job"]

    body = publish_job.group("body")
    required = {
        "name: emulebb-rust-image-candidate": "smoke-tested image artifact download",
        "regclient/actions/regctl-installer@": "pinned registry client installer",
        "release: v0.11.6": "pinned registry client release",
        'regctl image import "$VERSIONED_IMAGE" "$OCI_ARCHIVE"':
            "exact OCI archive import",
        'regctl image copy "$VERSIONED_IMAGE" "$CHANNEL_IMAGE"':
            "floating-channel retag from the immutable image",
        'regctl image digest "$CHANNEL_IMAGE"': "published-channel digest verification",
    }
    errors = [
        f".github/workflows/release.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in body
    ]
    installer = re.search(r"regclient/actions/regctl-installer@([^\s#]+)", body)
    if installer is None or not action_ref_is_immutable(installer.group(1)):
        errors.append(
            ".github/workflows/release.yml must pin the registry client installer by full commit SHA"
        )
    forbidden = {
        "package-emulebb-rust-image-ci": "rebuilds the image after smoke testing",
        "docker/setup-buildx-action": "sets up an unnecessary publishing rebuild",
        "pattern: emulebb-rust-package-*": "downloads native inputs instead of the tested image",
    }
    errors.extend(
        f".github/workflows/release.yml publish-image {description}"
        for fragment, description in forbidden.items()
        if fragment in body
    )
    return errors


def check_release_image_security(
    workflow_text: str | None = None,
    dockerfile_text: str | None = None,
    dependabot_text: str | None = None,
) -> list[str]:
    """Keep the exact release image digest-pinned, inventoried, and gated."""

    workflow = ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    image_job = re.search(
        r"(?ms)^  image-candidate:\s*$\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
        text,
    )
    errors: list[str] = []
    if image_job is None:
        errors.append(".github/workflows/release.yml is missing the image candidate job")
    else:
        body = image_job.group("body")
        required = {
            "aquasecurity/setup-trivy@": "Trivy installer",
            "version: v0.75.0": "pinned Trivy release",
            "--image-src docker": "scan of the loaded candidate image",
            '--platform "$platform"': "per-platform image inspection",
            "--format spdx-json": "SPDX JSON image SBOM generation",
            "--scanners vuln": "image vulnerability scanner",
            "--ignore-unfixed": "fixable-vulnerability filter",
            "--severity HIGH,CRITICAL": "high and critical severity gate",
            "--exit-code 1": "failing vulnerability result",
            "name: emulebb-rust-image-security": "retained image security evidence",
        }
        errors.extend(
            f".github/workflows/release.yml image-candidate is missing {description}"
            for fragment, description in required.items()
            if fragment not in body
        )
        installer = re.search(r"aquasecurity/setup-trivy@([^\s#]+)", body)
        if installer is None or not action_ref_is_immutable(installer.group(1)):
            errors.append(
                ".github/workflows/release.yml must pin the Trivy installer by full commit SHA"
            )

    publish_job = re.search(
        r"(?ms)^  publish-native:\s*$\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\s*$|\Z)",
        text,
    )
    if publish_job is None or "name: emulebb-rust-image-security" not in publish_job.group(
        "body"
    ):
        errors.append(
            ".github/workflows/release.yml must attach image security evidence to the release"
        )

    dockerfile = ROOT / "packaging" / "docker" / "Dockerfile"
    dockerfile_source = (
        dockerfile.read_text(encoding="utf-8")
        if dockerfile_text is None
        else dockerfile_text
    )
    if not re.search(
        r"(?m)^FROM\s+lscr\.io/linuxserver/baseimage-ubuntu:noble"
        r"@sha256:[0-9a-f]{64}\s*$",
        dockerfile_source,
    ):
        errors.append(
            "packaging/docker/Dockerfile must pin the LinuxServer Noble base by digest"
        )

    dependabot = ROOT / ".github" / "dependabot.yml"
    dependabot_source = (
        dependabot.read_text(encoding="utf-8")
        if dependabot_text is None
        else dependabot_text
    )
    docker_updates = re.search(
        r"(?ms)- package-ecosystem:\s*docker\s+directory:\s*/packaging/docker\b",
        dependabot_source,
    )
    if docker_updates is None:
        errors.append(
            ".github/dependabot.yml must monitor the packaging/docker base image"
        )
    return errors


def check_release_build_identity(workflow_text: str | None = None) -> list[str]:
    """Require release binaries to receive exact distribution provenance."""

    workflow = ROOT / ".github" / "workflows" / "release.yml"
    text = workflow.read_text(encoding="utf-8") if workflow_text is None else workflow_text
    required = {
        "RELEASE_CHANNEL: ${{ inputs.channel ||": "derived release channel",
        "source_sha: ${{ steps.source.outputs.sha }}": "resolved source output",
        "EMULEBB_RELEASE_VERSION: ${{ env.RELEASE_VERSION }}": "runtime distribution version",
        "EMULEBB_RELEASE_CHANNEL: ${{ env.RELEASE_CHANNEL }}": "runtime release channel",
        "EMULEBB_SOURCE_REVISION: ${{ needs.verify-ci.outputs.source_sha }}":
            "runtime source revision",
    }
    return [
        f".github/workflows/release.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]


def check_lint_suppressions() -> list[str]:
    """Reject permanent broad Rust/Clippy suppression in production and tests."""
    errors = []
    for rel in tracked_files("*.rs"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        if contains_permanent_lint_allow(text):
            errors.append(
                f"{rel.replace('\\', '/')} uses a permanent broad lint allow; "
                "use a scoped #[expect(..., reason = ...)] or fix the warning"
            )
    return errors


def contains_permanent_lint_allow(text: str) -> bool:
    """Match direct and conditional broad lint allows inside one attribute."""
    suppression = re.compile(
        r"#\s*!?\s*\[[^\]]*\ballow\s*\(\s*"
        r"(?:clippy::|dead_code\b|unused(?:_\w+)?\b)"
    )
    return suppression.search(text) is not None


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
        "EMULEBB_WORKSPACE_ROOT: ${{ github.workspace }}": "explicit workspace root",
        "EMULEBB_WORKSPACE_OUTPUT_ROOT: ${{ runner.temp }}/emulebb-rust-out": "external workspace output root",
        "CARGO_TARGET_DIR: ${{ runner.temp }}/emulebb-rust-out/builds/rust/target": "external Cargo target",
        "path: .ci/emulebb-tooling": "release scope checkout",
        "working-directory: .ci/emulebb-build": "workspace packaging owner",
        "package-emulebb-rust-ci --release-version": "orchestrated native packaging",
        "--target-os ${{ matrix.os }} --platform ${{ matrix.arch }}": "six-target package selection",
        "smoke-rust-release-package.py": "native package and WebUI smoke",
        "smoke-rust-container.py": "first-run LinuxServer image smoke",
        "${{ runner.temp }}/emulebb-rust-out/release/": "external release assets",
        "assemble-emulebb-rust-release-ci": "verified release assembly",
        "RELEASE-${RELEASE_VERSION}-NOTES.md": "versioned release notes asset",
        "RELEASE-${RELEASE_VERSION}-CHANGELOG.md": "versioned changelog asset",
        "nightly-release-notes.md": "generated nightly release notes body",
    }
    return [
        f".github/workflows/release.yml is missing {description} configuration"
        for fragment, description in required.items()
        if fragment not in text
    ]


def maintainability_advisories(
    files: list[str] | None = None,
    changed_files: list[str] | None = None,
) -> list[str]:
    """Report review signals without turning source length into a policy limit."""
    rust_files = tracked_files("*.rs") if files is None else files
    if changed_files is None:
        changed_files = changed_rust_files() if files is None else []
    changed = {path.replace("\\", "/") for path in changed_files}
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

    advisories = changed_file_advisories("production", production, changed)
    advisories.extend(changed_file_advisories("test", tests, changed))
    advisories.extend(
        ranked_file_advisories("production", [item for item in production if item[0] not in changed])
    )
    advisories.extend(ranked_file_advisories("test", [item for item in tests if item[0] not in changed]))
    largest_inline_tests = sorted(inline_tests, key=lambda item: (-item[1], item[0]))[
        :INLINE_TEST_MODULES_REPORTED
    ]
    for path, lines in largest_inline_tests:
        advisories.append(
            f"{path} contains an inline test module of about {lines} lines; "
            "review whether it belongs in a sibling test module"
        )
    return advisories


def changed_rust_files() -> list[str]:
    """Return working-tree Rust changes, or the latest commit when clean."""
    commands = (
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    )
    changed: set[str] = set()
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE)
        changed.update(result.stdout.splitlines())
    rust_changes = {
        normalized
        for path in changed
        if (normalized := path.strip().replace("\\", "/")).endswith(".rs")
        and (ROOT / normalized).is_file()
    }
    if not rust_changes:
        result = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        rust_changes.update(
            normalized
            for path in result.stdout.splitlines()
            if (normalized := path.strip().replace("\\", "/")).endswith(".rs")
            and (ROOT / normalized).is_file()
        )
    return sorted(rust_changes)


def changed_file_advisories(
    kind: str,
    files: list[tuple[str, int]],
    changed: set[str],
) -> list[str]:
    selected = sorted(
        (item for item in files if item[0] in changed),
        key=lambda item: (-item[1], item[0]),
    )[:CHANGED_FILES_REPORTED]
    return [
        f"changed {kind} file: {path} ({lines} lines); review responsibility boundaries"
        for path, lines in selected
    ]


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
