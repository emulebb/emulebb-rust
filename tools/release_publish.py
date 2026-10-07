#!/usr/bin/env python3
"""Validate release publication inputs before they become externally visible."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tomllib
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
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
            )
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError(f"could not read OCI archive {path}: {error}") from error

    actual_digest = f"sha256:{hashlib.sha256(blob).hexdigest()}"
    if actual_digest != digest:
        raise RuntimeError(
            f"OCI archive manifest digest mismatch: expected {digest}, got {actual_digest}"
        )
    return digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser(
        "oci-digest",
        help="validate an OCI archive and write its manifest digest",
    )
    digest.add_argument("--archive", required=True, type=Path)
    digest.add_argument("--output", required=True, type=Path)
    identity = subparsers.add_parser(
        "release-identity",
        help="derive and validate the release version against Cargo metadata",
    )
    identity.add_argument("--requested-version", default="")
    identity.add_argument("--channel", required=True)
    identity.add_argument("--ref-name", required=True)
    identity.add_argument("--ref-type", required=True)
    identity.add_argument("--github-output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
            cargo_version=workspace_version(),
        )
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"version={version}\n")
        print(version)
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
