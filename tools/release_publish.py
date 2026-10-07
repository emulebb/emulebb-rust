#!/usr/bin/env python3
"""Validate release publication inputs before they become externally visible."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from typing import Sequence


OCI_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
MAX_INDEX_BYTES = 1024 * 1024


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "oci-digest":
        digest = oci_archive_digest(args.archive)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(f"{digest}\n", encoding="utf-8")
        print(digest)
        return 0
    raise AssertionError(f"unhandled command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
