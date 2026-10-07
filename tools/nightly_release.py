#!/usr/bin/env python3
"""Prepare, document, verify, and prune immutable emulebb-rust nightlies."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPOSITORY = "emulebb/emulebb-rust"
PROMOTED_BETA_RE = re.compile(r"\d+\.\d+\.\d+-beta\.\d+")
NIGHTLY_VERSION_RE = re.compile(
    r"(?P<base>\d+\.\d+\.\d+-beta\.\d+)\.nightly\."
    r"(?P<date>\d{8})\.g(?P<sha>[0-9a-f]{7,40})"
)
NIGHTLY_TAG_RE = re.compile(
    r"rust-v(?P<version>\d+\.\d+\.\d+-beta\.\d+\.nightly\."
    r"(?P<date>\d{8})\.g(?P<sha>[0-9a-f]{7,40}))"
)
SAFE_REF_RE = re.compile(r"[A-Za-z0-9._/-]+")
METADATA_SCHEMA_PATH = "crates/emulebb-metadata/src/schema.rs"
METADATA_SCHEMA_RE = re.compile(r"^pub const SCHEMA_VERSION: i64 = (?P<version>\d+);$", re.MULTILINE)
REQUIRED_SOURCE_CHECKS = ("Required CI", "Required CodeQL")


@dataclass(frozen=True)
class Change:
    """One commit-derived nightly changelog entry."""

    sha: str
    subject: str
    category: str


def run(command: Sequence[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    """Runs one checked command and captures its text output."""

    return subprocess.run(
        list(command),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def git_output(*args: str) -> str:
    """Returns stripped output from git in the Rust repository."""

    return run(("git", *args)).stdout.strip()


def workspace_version(root: Path = ROOT) -> str:
    """Returns the promoted Cargo workspace beta version."""

    with (root / "Cargo.toml").open("rb") as stream:
        value = str(tomllib.load(stream)["workspace"]["package"]["version"])
    return validate_workspace_version(value)


def workspace_version_at_ref(ref: str) -> str:
    """Returns the promoted Cargo workspace beta version at one Git ref."""

    if not SAFE_REF_RE.fullmatch(ref):
        raise RuntimeError(f"unsafe Cargo version ref: {ref}")
    source = git_output("show", f"{ref}:Cargo.toml")
    value = str(tomllib.loads(source)["workspace"]["package"]["version"])
    return validate_workspace_version(value)


def validate_workspace_version(value: str) -> str:
    """Requires one promoted beta version suitable for nightly derivation."""

    if not PROMOTED_BETA_RE.fullmatch(value):
        raise RuntimeError(f"nightly builds require a promoted beta Cargo version, got {value!r}")
    return value


def nightly_version(base_version: str, date: str, sha: str) -> str:
    """Builds the SemVer-ordered nightly version derived from one beta."""

    if not PROMOTED_BETA_RE.fullmatch(base_version):
        raise ValueError(f"invalid promoted beta version: {base_version}")
    if not re.fullmatch(r"\d{8}", date):
        raise ValueError(f"invalid nightly date: {date}")
    normalized_sha = sha.lower()
    if not re.fullmatch(r"[0-9a-f]{7,40}", normalized_sha):
        raise ValueError(f"invalid source commit: {sha}")
    return f"{base_version}.nightly.{date}.g{normalized_sha}"


def metadata_schema_version(source: str) -> int:
    """Extracts the single current-only metadata schema version declaration."""

    matches = METADATA_SCHEMA_RE.findall(source)
    if len(matches) != 1:
        raise RuntimeError("metadata schema source must declare exactly one SCHEMA_VERSION")
    return int(matches[0])


def metadata_schema_version_at_ref(ref: str) -> int:
    """Reads the metadata schema version from one validated Git ref."""

    if not SAFE_REF_RE.fullmatch(ref):
        raise RuntimeError(f"unsafe metadata schema ref: {ref}")
    source = git_output("show", f"{ref}:{METADATA_SCHEMA_PATH}")
    return metadata_schema_version(source)


def matching_nightly_tags(base_version: str, tags: Sequence[str]) -> list[str]:
    """Returns well-formed nightly tags for the selected promoted beta."""

    prefix = f"{base_version}.nightly."
    matched: list[str] = []
    for tag in tags:
        parsed = NIGHTLY_TAG_RE.fullmatch(tag)
        if parsed and parsed.group("version").startswith(prefix):
            matched.append(tag)
    return matched


def latest_nightly_tag(base_version: str, tags: Sequence[str]) -> str | None:
    """Returns the first matching tag from a newest-first tag sequence."""

    matched = matching_nightly_tags(base_version, tags)
    return matched[0] if matched else None


def successful_ci_shas(payload: dict[str, object], branch: str) -> list[str]:
    """Returns newest-first successful push CI SHAs for one branch."""

    runs = payload.get("workflow_runs", [])
    if not isinstance(runs, list):
        return []
    shas: list[str] = []
    for run_data in runs:
        if not isinstance(run_data, dict):
            continue
        sha = str(run_data.get("head_sha", "")).lower()
        if (
            run_data.get("head_branch") == branch
            and run_data.get("event") == "push"
            and run_data.get("status") == "completed"
            and run_data.get("conclusion") == "success"
            and re.fullmatch(r"[0-9a-f]{40}", sha)
        ):
            shas.append(sha)
    return shas


def is_ancestor(ancestor: str, descendant: str) -> bool:
    """Reports whether one validated commit is an ancestor of another."""

    for ref in (ancestor, descendant):
        if not SAFE_REF_RE.fullmatch(ref):
            raise RuntimeError(f"unsafe ancestry ref: {ref}")
    try:
        run(("git", "merge-base", "--is-ancestor", ancestor, descendant))
    except subprocess.CalledProcessError:
        return False
    return True


def latest_green_main_sha(repository: str, branch: str = "main") -> str:
    """Selects the newest successful normal-CI commit in the checkout lineage."""

    response = run(
        (
            "gh",
            "api",
            f"repos/{repository}/actions/workflows/ci.yml/runs"
            f"?branch={branch}&event=push&status=success&per_page=20",
        )
    )
    candidates = successful_ci_shas(json.loads(response.stdout), branch)
    for candidate in candidates:
        if is_ancestor(candidate, "HEAD"):
            return candidate
    raise RuntimeError(f"no successful {branch} CI commit is available in the current checkout lineage")


def published_nightly_releases(
    base_version: str,
    releases: Sequence[dict[str, object]],
) -> list[dict[str, object]]:
    """Returns newest-first published nightly prereleases for one beta."""

    matching = [
        release
        for release in releases
        if release.get("isPrerelease") is True
        and release.get("isDraft") is False
        and isinstance(release.get("publishedAt"), str)
        and NIGHTLY_TAG_RE.fullmatch(str(release.get("tagName", "")))
        and str(release["tagName"]).startswith(f"rust-v{base_version}.nightly.")
    ]
    matching.sort(key=lambda release: str(release["publishedAt"]), reverse=True)
    return matching


def published_nightly_for_date(
    base_version: str,
    release_date: str,
    releases: Sequence[dict[str, object]],
) -> bool:
    """Reports whether one beta already has a published nightly for a UTC date."""

    return any(
        NIGHTLY_TAG_RE.fullmatch(str(release["tagName"])).group("date") == release_date
        for release in published_nightly_releases(base_version, releases)
    )


def github_releases(repository: str) -> list[dict[str, object]]:
    """Loads the bounded release history used by nightly coordination."""

    response = run(
        (
            "gh",
            "release",
            "list",
            "--repo",
            repository,
            "--limit",
            "100",
            "--json",
            "tagName,publishedAt,isPrerelease,isDraft",
        )
    )
    payload = json.loads(response.stdout)
    if not isinstance(payload, list) or not all(isinstance(item, dict) for item in payload):
        raise RuntimeError("GitHub release history returned an invalid payload")
    return payload


def should_build_nightly(
    *,
    force: bool,
    publish: bool,
    scheduled: bool,
    tag_exists: bool,
    published_for_date: bool,
    source_changed: bool,
    version: str,
) -> bool:
    """Applies retry, daily publication, and immutable-version rules."""

    if publish and force and tag_exists:
        raise RuntimeError(f"refusing to republish existing nightly version {version}")
    return (force or source_changed) and not (scheduled and published_for_date)


def parse_bool(value: str) -> bool:
    """Parses a workflow-friendly boolean string."""

    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise argparse.ArgumentTypeError(f"expected a boolean value, got {value!r}")


def metadata(
    *,
    date: str | None = None,
    force: bool = False,
    publish: bool = False,
    scheduled: bool = False,
    repository: str = DEFAULT_REPOSITORY,
) -> dict[str, str]:
    """Computes immutable nightly metadata from the current checkout and tags."""

    source_sha = (
        latest_green_main_sha(repository)
        if scheduled
        else git_output("rev-parse", "HEAD").lower()
    )
    base_version = workspace_version_at_ref(source_sha)
    short_sha = source_sha[:8]
    release_date = date or datetime.now(timezone.utc).strftime("%Y%m%d")
    version = nightly_version(base_version, release_date, short_sha)
    tag = f"rust-v{version}"
    tags = git_output(
        "tag",
        "--list",
        "--sort=-creatordate",
        f"rust-v{base_version}.nightly.*",
    ).splitlines()
    releases = github_releases(repository)
    published_releases = published_nightly_releases(base_version, releases)
    previous_ref = (
        str(published_releases[0]["tagName"])
        if published_releases
        else f"rust-v{base_version}"
    )
    if not SAFE_REF_RE.fullmatch(previous_ref):
        raise RuntimeError(f"unsafe previous nightly ref: {previous_ref}")
    try:
        run(("git", "merge-base", "--is-ancestor", previous_ref, source_sha))
    except subprocess.CalledProcessError:
        previous_ref = f"rust-v{base_version}"
        run(("git", "merge-base", "--is-ancestor", previous_ref, source_sha))
    previous_sha = git_output("rev-parse", f"{previous_ref}^{{commit}}").lower()
    schema_version = metadata_schema_version_at_ref(source_sha)
    previous_schema_version = metadata_schema_version_at_ref(previous_ref)
    tag_exists = tag in tags
    already_published_today = published_nightly_for_date(
        base_version,
        release_date,
        releases,
    )
    should_build = should_build_nightly(
        force=force,
        publish=publish,
        scheduled=scheduled,
        tag_exists=tag_exists,
        published_for_date=already_published_today,
        source_changed=previous_sha != source_sha,
        version=version,
    )
    if scheduled and should_build:
        verify_source_checks(repository, source_sha)
    compare_url = f"https://github.com/{repository}/compare/{previous_ref}...{source_sha}"
    return {
        "base_version": base_version,
        "version": version,
        "tag": tag,
        "sha": source_sha,
        "short_sha": short_sha,
        "release_date": release_date,
        "previous_ref": previous_ref,
        "schema_version": str(schema_version),
        "previous_schema_version": str(previous_schema_version),
        "schema_changed": str(schema_version != previous_schema_version).lower(),
        "published_for_date": str(already_published_today).lower(),
        "tag_exists": str(tag_exists).lower(),
        "should_build": str(should_build).lower(),
        "compare_url": compare_url,
    }


def write_github_output(path: Path, values: dict[str, str]) -> None:
    """Appends simple scalar outputs for later GitHub Actions jobs."""

    with path.open("a", encoding="utf-8", newline="\n") as stream:
        for name, value in values.items():
            if "\n" in value or "\r" in value:
                raise ValueError(f"GitHub output {name!r} must be a scalar")
            stream.write(f"{name}={value}\n")


def normalize_subject(subject: str) -> tuple[str | None, str, str]:
    """Extracts an item id, conventional kind, and readable commit subject."""

    item_id: str | None = None
    item_match = re.match(r"^(RUST-(?:BUG|FEAT|REF|CI)-\d+)(?::|\s+)\s*(.*)$", subject)
    if item_match:
        item_id = item_match.group(1)
        subject = item_match.group(2)
    else:
        freeform_prefix = re.match(r"^[A-Z][A-Z0-9_-]*:\s*(.*)$", subject)
        if freeform_prefix:
            subject = freeform_prefix.group(1)
    kind = ""
    kind_match = re.match(r"^(feat|fix|ci|docs|test|build|chore|refactor|release)(?:\([^)]*\))?!?:\s*(.*)$", subject)
    if kind_match:
        kind = kind_match.group(1)
        subject = kind_match.group(2)
    readable = subject.strip()
    if readable:
        readable = readable[0].upper() + readable[1:]
    if readable and readable[-1] not in ".!?":
        readable += "."
    return item_id, kind, readable


def categorize_change(item_id: str | None, kind: str, subject: str) -> str:
    """Assigns one stable user-facing nightly notes section."""

    lowered = subject.lower()
    if kind == "fix" or (item_id and "-BUG-" in item_id):
        return "Fixed"
    if kind == "feat" or (item_id and "-FEAT-" in item_id) or lowered.startswith(("add ", "enable ")):
        return "Added"
    if kind in {"ci", "docs", "test", "build", "chore", "release"} or (item_id and "-CI-" in item_id):
        return "Engineering"
    return "Changed"


def changes_from_log(raw_log: str) -> list[Change]:
    """Converts a tab-delimited git log into changelog entries."""

    changes: list[Change] = []
    for line in raw_log.splitlines():
        if not line.strip():
            continue
        sha, subject = line.split("\t", 1)
        item_id, kind, readable = normalize_subject(subject)
        if not readable:
            continue
        prefix = f"{item_id}: " if item_id else ""
        changes.append(
            Change(
                sha=sha,
                subject=f"{prefix}{readable}",
                category=categorize_change(item_id, kind, readable),
            )
        )
    return changes


def render_notes(
    *,
    version: str,
    previous_ref: str,
    source_sha: str,
    schema_version: int,
    previous_schema_version: int,
    changes: Sequence[Change],
    repository: str = DEFAULT_REPOSITORY,
) -> str:
    """Renders deterministic user-facing notes plus exact source comparison."""

    parsed = NIGHTLY_VERSION_RE.fullmatch(version)
    if not parsed:
        raise ValueError(f"invalid nightly version: {version}")
    if not SAFE_REF_RE.fullmatch(previous_ref) or not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("invalid nightly comparison ref or source SHA")
    lines = [
        f"# eMuleBB Rust {version}",
        "",
        "> Automated experimental nightly. It is unsigned, may be unstable, and is not a promoted beta.",
        "",
        f"- Base beta: `{parsed.group('base')}`",
        f"- Source: [`{source_sha[:8]}`](https://github.com/{repository}/commit/{source_sha})",
        f"- Previous successful nightly: `{previous_ref}`",
        "",
        "## Profile compatibility",
        "",
    ]
    if schema_version == previous_schema_version:
        lines.extend(
            (
                f"- Metadata schema: `{schema_version}` (unchanged from `{previous_ref}`).",
                "- Profile schema status: unchanged. Back up the profile before testing this experimental build.",
                "",
            )
        )
    else:
        lines.extend(
            (
                f"- Metadata schema: `{schema_version}` (changed from `{previous_schema_version}` at `{previous_ref}`).",
                "- Profile schema status: incompatible with the previous build.",
                "",
                "> Use a fresh profile. This build does not migrate, repair, or reset incompatible databases. Back up an existing profile before testing.",
                "",
            )
        )
    for category in ("Added", "Fixed", "Changed", "Engineering"):
        entries = [change for change in changes if change.category == category]
        if not entries:
            continue
        lines.extend((f"## {category}", ""))
        for change in entries:
            lines.append(
                f"- {change.subject} ([`{change.sha[:8]}`](https://github.com/{repository}/commit/{change.sha}))"
            )
        lines.append("")
    compare_url = f"https://github.com/{repository}/compare/{previous_ref}...{source_sha}"
    lines.extend((f"[Full source comparison]({compare_url})", ""))
    return "\n".join(lines)


def successful_required_checks(payload: dict[str, object]) -> tuple[str, ...]:
    """Returns required check names without a successful completed run."""

    runs = payload.get("check_runs", [])
    if not isinstance(runs, list):
        return REQUIRED_SOURCE_CHECKS
    successes = {
        str(run.get("name"))
        for run in runs
        if isinstance(run, dict) and run.get("status") == "completed" and run.get("conclusion") == "success"
    }
    return tuple(name for name in REQUIRED_SOURCE_CHECKS if name not in successes)


def verify_source_checks(repository: str, sha: str) -> None:
    """Require build, conformance, policy, and CodeQL checks for the source SHA."""

    response = run(("gh", "api", f"repos/{repository}/commits/{sha}/check-runs?per_page=100"))
    missing = successful_required_checks(json.loads(response.stdout))
    if missing:
        raise RuntimeError("required source checks are not successful: " + ", ".join(missing))


def nightly_tags_to_prune(releases: Sequence[dict[str, object]], keep: int) -> list[str]:
    """Selects only old immutable nightly prereleases for deletion."""

    if keep < 1:
        raise ValueError("nightly retention must keep at least one release")
    candidates = [
        release
        for release in releases
        if release.get("isPrerelease") is True
        and isinstance(release.get("tagName"), str)
        and NIGHTLY_TAG_RE.fullmatch(str(release["tagName"]))
    ]
    candidates.sort(key=lambda release: str(release.get("createdAt", "")), reverse=True)
    return [str(release["tagName"]) for release in candidates[keep:]]


def prune(repository: str, keep: int, *, dry_run: bool) -> list[str]:
    """Deletes old nightly releases and their matching tags after strict filtering."""

    response = run(
        (
            "gh",
            "release",
            "list",
            "--repo",
            repository,
            "--limit",
            "100",
            "--json",
            "tagName,createdAt,isPrerelease",
        )
    )
    selected = nightly_tags_to_prune(json.loads(response.stdout), keep)
    if not dry_run:
        for tag in selected:
            run(("gh", "release", "delete", tag, "--repo", repository, "--cleanup-tag", "--yes"))
    return selected


def build_parser() -> argparse.ArgumentParser:
    """Builds the command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata_parser = subparsers.add_parser("metadata", help="Compute the nightly version and source range.")
    metadata_parser.add_argument("--date", help="UTC YYYYMMDD override used by deterministic tests.")
    metadata_parser.add_argument("--force", type=parse_bool, default=False)
    metadata_parser.add_argument("--publish", type=parse_bool, default=False)
    metadata_parser.add_argument("--scheduled", type=parse_bool, default=False)
    metadata_parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    metadata_parser.add_argument("--github-output", type=Path)

    notes_parser = subparsers.add_parser("notes", help="Write compact nightly release notes.")
    notes_parser.add_argument("--version", required=True)
    notes_parser.add_argument("--previous-ref", required=True)
    notes_parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    notes_parser.add_argument("--output", type=Path, required=True)

    verify_parser = subparsers.add_parser(
        "verify-source",
        help="Require build, conformance, policy, and CodeQL checks for one commit.",
    )
    verify_parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    verify_parser.add_argument("--sha", required=True)

    prune_parser = subparsers.add_parser("prune", help="Keep only the newest immutable nightly releases.")
    prune_parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    prune_parser.add_argument("--keep", type=int, default=14)
    prune_parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Runs one nightly-release helper command."""

    args = build_parser().parse_args(argv)
    if args.command == "metadata":
        values = metadata(
            date=args.date,
            force=args.force,
            publish=args.publish,
            scheduled=args.scheduled,
            repository=args.repository,
        )
        if args.github_output:
            write_github_output(args.github_output, values)
        print(json.dumps(values, indent=2))
        return 0
    if args.command == "notes":
        if not SAFE_REF_RE.fullmatch(args.previous_ref):
            raise RuntimeError(f"unsafe previous nightly ref: {args.previous_ref}")
        source_sha = git_output("rev-parse", "HEAD").lower()
        raw_log = git_output("log", "--reverse", "--format=%H%x09%s", f"{args.previous_ref}..{source_sha}")
        schema_version = metadata_schema_version_at_ref(source_sha)
        previous_schema_version = metadata_schema_version_at_ref(args.previous_ref)
        rendered = render_notes(
            version=args.version,
            previous_ref=args.previous_ref,
            source_sha=source_sha,
            schema_version=schema_version,
            previous_schema_version=previous_schema_version,
            changes=changes_from_log(raw_log),
            repository=args.repository,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        print(args.output)
        return 0
    if args.command == "verify-source":
        verify_source_checks(args.repository, args.sha)
        print(f"required source checks passed for {args.sha}")
        return 0
    if args.command == "prune":
        selected = prune(args.repository, args.keep, dry_run=args.dry_run)
        print(json.dumps({"deleted" if not args.dry_run else "selected": selected}, indent=2))
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"nightly release error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
