#!/usr/bin/env python3
"""Validate release publication inputs before they become externally visible."""

from __future__ import annotations

import argparse
import importlib
import os
import hashlib
import json
import re
import runpy
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path
from typing import Sequence


sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:"
    r"(?:0|[1-9][0-9]*)|"
    r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r")(?:\.(?:"
    r"(?:0|[1-9][0-9]*)|"
    r"(?:[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
BETA_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)-beta\.(?:0|[1-9][0-9]*)"
)
NIGHTLY_SUFFIX_RE = re.compile(r"nightly\.[0-9]{8}\.g[0-9a-f]{7,40}")
MAX_INDEX_BYTES = 1024 * 1024


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_workflow_source(
    workflow_sha: str, *, source_ref: str = "", candidate_ref: str = "",
) -> str:
    """Bind release source to the immutable revision owning its workflow.

    Independently selected source can execute build code with access to the
    default branch's cache scope, even when contents permissions are read-only.
    """
    if COMMIT_SHA_RE.fullmatch(workflow_sha) is None:
        raise RuntimeError("workflow revision must be a full lowercase commit SHA")
    for requested in (source_ref, candidate_ref):
        if not requested:
            continue
        if COMMIT_SHA_RE.fullmatch(requested) is None:
            raise RuntimeError("release source assertion must be a full lowercase commit SHA")
        if requested != workflow_sha:
            raise RuntimeError(
                "release source must match the workflow revision; select its branch or tag "
                "when dispatching the workflow"
            )
    return workflow_sha


def resolve_platform_profile(profile: str, *, event_name: str, channel: str, publish: str) -> str:
    """Allow a reduced inventory only for explicitly unpublished manual candidates."""
    if profile not in {"full", "windows-linux"} or publish not in {"true", "false"}:
        raise RuntimeError("Invalid release platform profile or publish assertion")
    if profile != "full" and (event_name != "workflow_dispatch" or channel != "candidate" or publish != "false"):
        raise RuntimeError("Windows/Linux profile requires an unpublished manual candidate")
    return profile


def native_matrix(platform_profile: str) -> list[dict[str, str]]:
    """Bind native package and smoke matrices to the validated caller profile."""
    if platform_profile not in {"full", "windows-linux"}:
        raise RuntimeError("Invalid release platform profile")
    targets = [
        {"os": "windows", "arch": "x64", "slug": "windows-x64", "runner": "windows-latest"},
        {"os": "windows", "arch": "ARM64", "slug": "windows-arm64", "runner": "windows-11-arm"},
        {"os": "linux", "arch": "x64", "slug": "linux-x64", "runner": "ubuntu-24.04"},
        {"os": "linux", "arch": "ARM64", "slug": "linux-arm64", "runner": "ubuntu-24.04-arm"},
    ]
    if platform_profile == "full":
        targets.extend([
            {"os": "macos", "arch": "x64", "slug": "macos-x64", "runner": "macos-15-intel"},
            {"os": "macos", "arch": "ARM64", "slug": "macos-arm64", "runner": "macos-15"},
        ])
    return targets


def workspace_version(root: Path = ROOT) -> str:
    """Return the validated Cargo workspace package version."""

    try:
        with (root / "Cargo.toml").open("rb") as stream:
            value = tomllib.load(stream)["workspace"]["package"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise RuntimeError(f"could not read Cargo workspace version: {error}") from error
    if not isinstance(value, str) or SEMVER_RE.fullmatch(value) is None:
        raise RuntimeError(f"Cargo workspace version is not valid SemVer: {value!r}")
    return value


def resolve_release_version(
    *,
    requested_version: str,
    channel: str,
    ref_name: str,
    ref_type: str,
    cargo_version: str,
) -> str:
    """Resolve one release version and bind it to its authoritative source."""

    if SEMVER_RE.fullmatch(cargo_version) is None:
        raise RuntimeError(f"Cargo workspace version is not valid SemVer: {cargo_version!r}")
    requested = requested_version.strip()

    if channel == "beta":
        if ref_type != "tag":
            raise RuntimeError("beta releases require a rust-v* tag")
        tag = re.fullmatch(r"rust-v(?P<version>.+)", ref_name)
        if tag is None or SEMVER_RE.fullmatch(tag.group("version")) is None:
            raise RuntimeError(f"invalid beta release tag: {ref_name!r}")
        version = tag.group("version")
        if requested and requested != version:
            raise RuntimeError(
                f"requested version {requested!r} does not match release tag {ref_name!r}"
            )
        if version != cargo_version:
            raise RuntimeError(
                f"release tag version {version!r} does not match Cargo version "
                f"{cargo_version!r}"
            )
        return version

    if channel == "nightly":
        if BETA_VERSION_RE.fullmatch(cargo_version) is None:
            raise RuntimeError(
                f"nightly releases require a beta Cargo version, got {cargo_version!r}"
            )
        prefix = f"{cargo_version}."
        suffix = requested.removeprefix(prefix)
        if not requested.startswith(prefix) or NIGHTLY_SUFFIX_RE.fullmatch(suffix) is None:
            raise RuntimeError(
                f"nightly version {requested!r} is not derived from Cargo version "
                f"{cargo_version!r}"
            )
        return requested

    if channel == "candidate":
        if ref_type == "tag":
            raise RuntimeError("tagged releases must use the beta channel")
        if requested and requested != cargo_version:
            raise RuntimeError(
                f"candidate version {requested!r} does not match Cargo version "
                f"{cargo_version!r}"
            )
        return cargo_version

    raise RuntimeError(f"unsupported release channel: {channel!r}")


def _read_unique_regular_member(
    archive: tarfile.TarFile,
    name: str,
    *,
    max_bytes: int | None = None,
) -> bytes:
    """Read one exact regular-file member and reject ambiguous archives."""

    matches = [member for member in archive.getmembers() if member.name == name]
    if len(matches) != 1:
        raise RuntimeError(f"OCI archive must contain exactly one {name!r}")
    member = matches[0]
    if not member.isfile():
        raise RuntimeError(f"OCI archive member {name!r} is not a regular file")
    if max_bytes is not None and member.size > max_bytes:
        raise RuntimeError(f"OCI archive member {name!r} exceeds {max_bytes} bytes")
    stream = archive.extractfile(member)
    if stream is None:
        raise RuntimeError(f"could not read OCI archive member {name!r}")
    return stream.read()


def oci_archive_digest(path: Path) -> str:
    """Return the verified manifest digest represented by one OCI archive."""

    try:
        with tarfile.open(path, mode="r:*") as archive:
            index_bytes = _read_unique_regular_member(
                archive,
                "index.json",
                max_bytes=MAX_INDEX_BYTES,
            )
            try:
                index = json.loads(index_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise RuntimeError("OCI archive index.json is not valid JSON") from error

            if not isinstance(index, dict) or index.get("schemaVersion") != 2:
                raise RuntimeError("OCI archive index.json must use schemaVersion 2")
            manifests = index.get("manifests")
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise RuntimeError("OCI archive index.json must describe exactly one manifest")
            descriptor = manifests[0]
            if not isinstance(descriptor, dict):
                raise RuntimeError("OCI archive manifest descriptor must be an object")
            digest = descriptor.get("digest")
            if not isinstance(digest, str) or OCI_DIGEST_RE.fullmatch(digest) is None:
                raise RuntimeError("OCI archive manifest has an invalid sha256 digest")

            algorithm, hex_digest = digest.split(":", maxsplit=1)
            blob = _read_unique_regular_member(
                archive,
                f"blobs/{algorithm}/{hex_digest}",
                max_bytes=MAX_INDEX_BYTES,
            )
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError(f"could not read OCI archive {path}: {error}") from error

    actual_digest = f"sha256:{hashlib.sha256(blob).hexdigest()}"
    if actual_digest != digest:
        raise RuntimeError(
            f"OCI archive manifest digest mismatch: expected {digest}, got {actual_digest}"
        )
    return digest


def checked_checkout(root: Path, expected_sha: str, *, label: str) -> Path:
    """Require a clean Git root at the caller's immutable revision before loading code."""
    if COMMIT_SHA_RE.fullmatch(expected_sha) is None:
        raise RuntimeError(f"{label} requires a full lowercase commit SHA")
    root = root.resolve()
    if not root.is_dir():
        raise RuntimeError(f"{label} checkout does not exist")

    def git(*arguments: str) -> str:
        return subprocess.check_output(["git", "-C", str(root), *arguments], text=True, timeout=30).strip()

    if (Path(git("rev-parse", "--show-toplevel")).resolve() != root
            or git("rev-parse", "HEAD") != expected_sha
            or git("status", "--porcelain", "--untracked-files=all")):
        raise RuntimeError(f"{label} must be a clean Git root at the required revision")
    return root


def candidate_owner(args: argparse.Namespace):
    """Load packaging code only after verifying its clean, pinned checkout."""
    expected = {"GITHUB_REPOSITORY": args.repository, "GITHUB_RUN_ID": args.run_id,
                "GITHUB_RUN_ATTEMPT": args.run_attempt, "GITHUB_WORKFLOW_SHA": args.workflow_sha}
    if os.environ.get("GITHUB_ACTIONS") != "true" or any(
        os.environ.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("Candidate control requires the actual GitHub run and workflow identities")
    checked_checkout(ROOT, args.workflow_sha, label="Release control")
    build_root = checked_checkout(args.build_repo, args.emulebb_build_ref, label="Packaging owner")
    for name, module in tuple(sys.modules.items()):
        if name == "emule_workspace" or name.startswith("emule_workspace."):
            filename = getattr(module, "__file__", None)
            if filename is None or not Path(filename).resolve().is_relative_to(build_root):
                raise RuntimeError("A different packaging owner is already loaded")
    # WHY: candidate metadata selects no executable code. The explicit checkout
    # must pass its source fence before Python imports any packaging helper.
    sys.path.insert(0, str(build_root))
    try:
        owner = importlib.import_module("emule_workspace.release_candidate")
    finally:
        sys.path.pop(0)
    if Path(owner.__file__).resolve() != build_root / "emule_workspace/release_candidate.py":
        raise RuntimeError("Candidate verification loaded a different packaging owner")
    return owner


def candidate_context(args: argparse.Namespace, owner):
    return owner.CandidateContext(
        version=args.release_version, channel=args.channel,
        source={"emulebbRust": args.source_sha, "emulebbBuild": args.emulebb_build_ref,
                "emulebbBuildTests": args.emulebb_build_tests_ref, "emulebbTooling": args.emulebb_tooling_ref,
                "emulebbMiniupnp": args.emulebb_miniupnp_ref, "emulebbLibpcpnatpmp": args.emulebb_libpcpnatpmp_ref},
        workflow={"repository": args.repository, "runId": args.run_id,
                  "runAttempt": args.run_attempt, "workflowSha": args.workflow_sha},
        platform_profile=args.platform_profile,
    ).checked()


def archive_identity_reader(args: argparse.Namespace):
    harness = checked_checkout(args.harness_repo, args.emulebb_build_tests_ref, label="OCI reader")
    identities = runpy.run_path(str(harness / "scripts/smoke-rust-container.py"))["oci_platform_identities"]

    def read(archive: Path):
        return oci_archive_digest(archive), identities(archive)

    return read


def candidate_outputs(path: Path, data: dict, output: Path | None) -> None:
    """Expose only verified scalar identities to dependent publishing jobs."""
    values = {"candidate_sha256": _sha256(path),
              "ubuntu_digest": data["images"]["ubuntu"]["ociManifestDigest"],
              "alpine_digest": data["images"]["alpine"]["ociManifestDigest"]}
    if output is not None:
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            for name, value in values.items():
                stream.write(f"{name}={value}\n")
    print(json.dumps(values, sort_keys=True))


def registry(*arguments: str) -> str:
    """Use the pinned registry client; transport errors never mean a missing tag."""
    return subprocess.check_output(["regctl", *arguments], text=True, timeout=600).strip()


def _image_targets(version: str, digests: dict[str, str]) -> dict[str, str]:
    if (SEMVER_RE.fullmatch(version) is None or set(digests) != {"ubuntu", "alpine"}
            or any(not isinstance(value, str) or OCI_DIGEST_RE.fullmatch(value) is None
                   for value in digests.values())):
        raise RuntimeError("Image publication requires a valid version and both bound OCI digests")
    return {version + "-ubuntu": digests["ubuntu"], version + "-alpine": digests["alpine"],
            version: digests["ubuntu"]}


def publish_verified_images(*, repository: str, version: str, digests: dict[str, str],
                            archives: dict[str, Path], client=registry) -> None:
    """Preflight every immutable ref before importing either already-verified archive."""
    targets = _image_targets(version, digests)
    if set(archives) != {"ubuntu", "alpine"}:
        raise RuntimeError("Image publication requires both verified archives")
    tags = set(client("tag", "ls", repository).splitlines())
    for tag, expected in targets.items():
        if tag in tags and client("image", "digest", repository + ":" + tag) != expected:
            raise RuntimeError(f"Immutable image tag conflicts with the verified candidate: {tag}")
    for variant in ("ubuntu", "alpine"):
        tag = version + "-" + variant
        reference = repository + ":" + tag
        if tag not in tags:
            client("image", "import", reference, str(archives[variant]))
        if client("image", "digest", reference) != digests[variant]:
            raise RuntimeError(f"Imported image differs from the verified candidate: {variant}")
    if version not in tags:
        client("image", "copy", repository + "@" + digests["ubuntu"], repository + ":" + version)
    if client("image", "digest", repository + ":" + version) != digests["ubuntu"]:
        raise RuntimeError("Default image tag differs from the verified Ubuntu candidate")


def promote_nightly(*, repository: str, version: str, digests: dict[str, str], client=registry) -> None:
    """Preflight all versioned refs, then copy only the bound digest to each alias."""
    targets = _image_targets(version, digests)
    for tag, expected in targets.items():
        if client("image", "digest", repository + ":" + tag) != expected:
            raise RuntimeError(f"Versioned image changed before nightly promotion: {tag}")
    channels = {"nightly-ubuntu": digests["ubuntu"], "nightly-alpine": digests["alpine"],
                "nightly": digests["ubuntu"]}
    for tag, expected in channels.items():
        client("image", "copy", repository + "@" + expected, repository + ":" + tag)
        if client("image", "digest", repository + ":" + tag) != expected:
            raise RuntimeError(f"Nightly channel differs from its bound digest: {tag}")


def require_publication_source(repository: str, sha: str) -> None:
    """Recheck the latest CI and CodeQL attempts through this trusted checkout."""
    helper = runpy.run_path(str(ROOT / "tools/nightly_release.py"))
    helper["verify_source_checks"](repository, sha)


def gh_rows(endpoint: str) -> list[dict]:
    """Read every API page; auth, transport and malformed responses fail closed."""
    response = subprocess.check_output(["gh", "api", "--paginate", "--slurp", endpoint], text=True, timeout=120)
    try:
        pages = json.loads(response)
    except json.JSONDecodeError as error:
        raise RuntimeError("GitHub returned malformed release metadata") from error
    if (not isinstance(pages, list) or any(not isinstance(page, list) for page in pages)
            or any(not isinstance(row, dict) for page in pages for row in page)):
        raise RuntimeError("GitHub returned malformed release metadata pages")
    return [row for page in pages for row in page]


def validate_draft_assets(*, release: dict | None, assets: list[dict], expected: list[dict],
                          tag: str, source_sha: str, complete: bool, release_id: str | None = None) -> int | None:
    """Allow a draft retry only when existing uploaded bytes match the candidate."""
    if release is None:
        if complete:
            raise RuntimeError("The uploaded draft release is missing")
        return None
    identifier = release.get("id")
    if (type(identifier) is not int or identifier <= 0
            or release.get("draft") is not True or release.get("prerelease") is not True
            or release.get("tag_name") != tag or release.get("target_commitish") != source_sha):
        raise RuntimeError("Release version already exists outside the expected source-bound prerelease draft")
    if release_id is not None and (re.fullmatch(r"[1-9][0-9]*", release_id) is None or int(release_id) != identifier):
        raise RuntimeError("Uploaded draft identity changed during publication")
    expected_by_name = {item["name"]: item for item in expected}
    if len(expected_by_name) != len(expected):
        raise RuntimeError("Candidate repeats a public asset")
    seen = set()
    for asset in assets:
        name = asset.get("name")
        if not isinstance(name, str) or name not in expected_by_name or name in seen:
            raise RuntimeError("Draft contains an unexpected or repeated asset")
        seen.add(name)
        record = expected_by_name[name]
        if (type(asset.get("size")) is not int or asset["size"] != record["sizeBytes"]
                or asset.get("state") != "uploaded"
                or asset.get("digest") != "sha256:" + record["sha256"]):
            raise RuntimeError(f"Draft asset bytes differ from the verified candidate: {name}")
    if complete and seen != set(expected_by_name):
        raise RuntimeError("Uploaded draft does not contain the complete verified candidate")
    return identifier


def verify_release_assets(args: argparse.Namespace, data: dict, candidate: Path) -> None:
    """Check existing draft assets before upload and the full set before finalizing."""
    tag = "rust-v" + args.release_version
    releases = [row for row in gh_rows(f"repos/{args.repository}/releases?per_page=100")
                if row.get("tag_name") == tag]
    if len(releases) > 1:
        raise RuntimeError("GitHub returned more than one release for the candidate tag")
    release = releases[0] if releases else None
    assets = []
    if release is not None:
        identifier = release.get("id")
        if type(identifier) is not int or identifier <= 0:
            raise RuntimeError("GitHub returned an invalid release identity")
        assets = gh_rows(f"repos/{args.repository}/releases/{identifier}/assets?per_page=100")
    if args.phase == "after-upload" and args.release_id is None:
        raise RuntimeError("Final draft verification requires the uploader's release ID")
    expected = [*data["artifacts"], {"name": candidate.name, "sha256": _sha256(candidate),
                                    "sizeBytes": candidate.stat().st_size}]
    identifier = validate_draft_assets(
        release=release, assets=assets, expected=expected, tag=tag,
        source_sha=args.source_sha, complete=args.phase == "after-upload", release_id=args.release_id,
    )
    require_publication_source(args.repository, args.source_sha)
    print(json.dumps({"phase": args.phase, "releaseId": identifier, "verifiedAssets": len(assets)}, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser(
        "oci-digest",
        help="validate an OCI archive and write its manifest digest",
    )
    digest.add_argument("--archive", required=True, type=Path)
    digest.add_argument("--output", required=True, type=Path)
    source = subparsers.add_parser(
        "workflow-source", help="require release source and workflow to share one revision",
    )
    source.add_argument("--workflow-sha", required=True)
    source.add_argument("--source-ref", default="")
    source.add_argument("--candidate-ref", default="")
    source.add_argument("--github-output", required=True, type=Path)
    profile = subparsers.add_parser("platform-profile", help="bind the target inventory before any producer runs")
    profile.add_argument("--profile", default="full")
    profile.add_argument("--event-name", required=True)
    profile.add_argument("--channel", required=True)
    profile.add_argument("--publish", required=True)
    profile.add_argument("--github-output", type=Path, required=True)
    identity = subparsers.add_parser(
        "release-identity",
        help="derive and validate the release version against Cargo metadata",
    )
    identity.add_argument("--requested-version", default="")
    identity.add_argument("--channel", required=True)
    identity.add_argument("--ref-name", required=True)
    identity.add_argument("--ref-type", required=True)
    identity.add_argument("--github-output", required=True, type=Path)
    identity.add_argument("--source-root", type=Path, default=ROOT,
                         help="Read Cargo metadata from this candidate directory as data.")
    for command in ("candidate-manifest", "verify-candidate", "verify-public-candidate", "release-assets", "publish-images"):
        candidate = subparsers.add_parser(command, help="strict source-bound release evidence control")
        candidate.add_argument("--release-dir", required=True, type=Path)
        candidate.add_argument("--platform-profile", choices=("full", "windows-linux"),
                               default=os.environ.get("RELEASE_PLATFORM_PROFILE", "full"))
        expected_arguments = {
            "release-version": "RELEASE_VERSION", "channel": "RELEASE_CHANNEL",
            "source-sha": "EMULEBB_SOURCE_REVISION", "emulebb-build-ref": "EMULEBB_BUILD_REF",
            "emulebb-build-tests-ref": "EMULEBB_BUILD_TESTS_REF", "emulebb-tooling-ref": "EMULEBB_TOOLING_REF",
            "emulebb-miniupnp-ref": "MINIUPNP_REF", "emulebb-libpcpnatpmp-ref": "PCPNATPMP_REF",
            "repository": "GITHUB_REPOSITORY", "run-id": "GITHUB_RUN_ID",
            "run-attempt": "GITHUB_RUN_ATTEMPT", "workflow-sha": "GITHUB_WORKFLOW_SHA",
        }
        for flag, environment in expected_arguments.items():
            default = os.environ.get(environment)
            candidate.add_argument("--" + flag, default=default, required=not default,
                                   help=f"Expected identity; defaults to the caller's {environment}.")
        candidate.add_argument("--build-repo", required=True, type=Path)
        candidate.add_argument("--github-output", type=Path)
        if command in {"candidate-manifest", "verify-candidate", "publish-images"}:
            candidate.add_argument("--archives-dir", required=True, type=Path)
            candidate.add_argument("--harness-repo", required=True, type=Path)
        else:
            candidate.add_argument("--verified-candidate-sha256", required=True)
        if command == "candidate-manifest":
            candidate.add_argument("--output", required=True, type=Path)
        if command == "publish-images":
            candidate.add_argument("--assembled-candidate-sha256", required=True)
        if command == "release-assets":
            candidate.add_argument("--phase", required=True, choices=("before-upload", "after-upload"))
            candidate.add_argument("--release-id")
    channel = subparsers.add_parser("promote-nightly", help="advance only verified nightly image digests")
    for flag, environment in {
        "release-version": "RELEASE_VERSION", "source-sha": "EMULEBB_SOURCE_REVISION",
        "repository": "GITHUB_REPOSITORY", "workflow-sha": "GITHUB_WORKFLOW_SHA",
        "ubuntu-digest": "UBUNTU_DIGEST", "alpine-digest": "ALPINE_DIGEST",
    }.items():
        default = os.environ.get(environment)
        channel.add_argument("--" + flag, default=default, required=not default)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "platform-profile":
        profile = resolve_platform_profile(args.profile, event_name=args.event_name,
                                           channel=args.channel, publish=args.publish)
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"platform_profile={profile}\n")
            stream.write("native_matrix=" + json.dumps(native_matrix(profile), separators=(",", ":")) + "\n")
        return 0
    if args.command == "workflow-source":
        sha = resolve_workflow_source(
            args.workflow_sha, source_ref=args.source_ref, candidate_ref=args.candidate_ref,
        )
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"sha={sha}\n")
        print(sha)
        return 0
    if args.command == "oci-digest":
        digest = oci_archive_digest(args.archive)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{digest}\n", encoding="utf-8")
        print(digest)
        return 0
    if args.command == "release-identity":
        version = resolve_release_version(
            requested_version=args.requested_version,
            channel=args.channel,
            ref_name=args.ref_name,
            ref_type=args.ref_type,
            cargo_version=workspace_version(args.source_root),
        )
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"version={version}\n")
        print(version)
        return 0
    if args.command in {"candidate-manifest", "verify-candidate", "verify-public-candidate", "release-assets", "publish-images"}:
        if args.command in {"release-assets", "publish-images"} and args.platform_profile != "full":
            raise RuntimeError("Publication requires the full platform profile")
        owner = candidate_owner(args)
        context = candidate_context(args, owner)
        release_dir = args.release_dir.resolve()
        path = owner.candidate_path(release_dir, context)
        common = {"release_dir": release_dir, "context": context}
        if args.command in {"candidate-manifest", "verify-candidate", "publish-images"}:
            common.update(archives_dir=args.archives_dir.resolve(), archive_identity=archive_identity_reader(args))
            if args.command == "candidate-manifest":
                if args.output.resolve() != path.resolve():
                    raise RuntimeError("Candidate output must use its canonical release filename")
                owner.write_candidate(**common)
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                data = owner.verify_candidate(**common)
        else:
            data = owner.verify_public_candidate(
                **common, verified_candidate_sha256=args.verified_candidate_sha256,
            )
        if args.command == "release-assets":
            verify_release_assets(args, data, path)
        else:
            if args.command == "publish-images":
                if (SHA256_RE.fullmatch(args.assembled_candidate_sha256) is None
                        or _sha256(path) != args.assembled_candidate_sha256):
                    raise RuntimeError("Image publisher candidate differs from the assembled candidate")
                require_publication_source(args.repository, args.source_sha)
                publish_verified_images(
                    repository="ghcr.io/emulebb/emulebb-rust", version=args.release_version,
                    digests={variant: data["images"][variant]["ociManifestDigest"] for variant in ("ubuntu", "alpine")},
                    archives={variant: args.archives_dir.resolve() / data["images"][variant]["archive"]
                              for variant in ("ubuntu", "alpine")},
                )
            candidate_outputs(path, data, args.github_output)
        return 0
    if args.command == "promote-nightly":
        if (os.environ.get("GITHUB_ACTIONS") != "true"
                or args.repository != os.environ.get("GITHUB_REPOSITORY")
                or args.workflow_sha != os.environ.get("GITHUB_WORKFLOW_SHA")):
            raise RuntimeError("Nightly promotion requires the actual GitHub workflow")
        checked_checkout(ROOT, args.workflow_sha, label="Nightly control")
        digests = {"ubuntu": args.ubuntu_digest, "alpine": args.alpine_digest}
        _image_targets(args.release_version, digests)
        require_publication_source(args.repository, args.source_sha)
        promote_nightly(repository="ghcr.io/emulebb/emulebb-rust", version=args.release_version, digests=digests)
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
