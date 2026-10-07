from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "release_publish.py"
SPEC = importlib.util.spec_from_file_location("release_publish", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
PUBLISH = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PUBLISH
SPEC.loader.exec_module(PUBLISH)


def add_bytes(archive: tarfile.TarFile, name: str, value: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(value)
    archive.addfile(member, io.BytesIO(value))


def write_oci_archive(path: Path, blob: bytes, *, digest: str, manifests: int = 1) -> None:
    descriptors = [{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": digest}]
    index = {"schemaVersion": 2, "manifests": descriptors * manifests}
    with tarfile.open(path, mode="w") as archive:
        add_bytes(archive, "index.json", json.dumps(index).encode("utf-8"))
        add_bytes(archive, f"blobs/sha256/{digest.removeprefix('sha256:')}", blob)


class TestReleaseIdentity(unittest.TestCase):
    def test_formal_release_is_derived_from_tag_and_matches_cargo(self) -> None:
        self.assertEqual(
            PUBLISH.resolve_release_version(
                requested_version="",
                channel="beta",
                ref_name="rust-v0.1.0-beta.2",
                ref_type="tag",
                cargo_version="0.1.0-beta.2",
            ),
            "0.1.0-beta.2",
        )

    def test_formal_release_rejects_tag_cargo_mismatch(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "does not match Cargo version"):
            PUBLISH.resolve_release_version(
                requested_version="",
                channel="beta",
                ref_name="rust-v0.1.0-beta.3",
                ref_type="tag",
                cargo_version="0.1.0-beta.2",
            )

    def test_nightly_must_be_derived_from_cargo_beta(self) -> None:
        version = "0.1.0-beta.2.nightly.20261007.g0123abcd"
        self.assertEqual(
            PUBLISH.resolve_release_version(
                requested_version=version,
                channel="nightly",
                ref_name="main",
                ref_type="branch",
                cargo_version="0.1.0-beta.2",
            ),
            version,
        )
        with self.assertRaisesRegex(RuntimeError, "not derived from Cargo version"):
            PUBLISH.resolve_release_version(
                requested_version="0.1.0-beta.1.nightly.20261007.g0123abcd",
                channel="nightly",
                ref_name="main",
                ref_type="branch",
                cargo_version="0.1.0-beta.2",
            )

    def test_candidate_defaults_to_exact_cargo_version(self) -> None:
        self.assertEqual(
            PUBLISH.resolve_release_version(
                requested_version="",
                channel="candidate",
                ref_name="main",
                ref_type="branch",
                cargo_version="0.1.0-beta.2",
            ),
            "0.1.0-beta.2",
        )
        with self.assertRaisesRegex(RuntimeError, "does not match Cargo version"):
            PUBLISH.resolve_release_version(
                requested_version="0.1.0-beta.1",
                channel="candidate",
                ref_name="main",
                ref_type="branch",
                cargo_version="0.1.0-beta.2",
            )

    def test_command_writes_prepared_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "github-output"

            self.assertEqual(
                PUBLISH.main(
                    [
                        "release-identity",
                        "--channel",
                        "candidate",
                        "--ref-name",
                        "main",
                        "--ref-type",
                        "branch",
                        "--github-output",
                        str(output),
                    ]
                ),
                0,
            )
            self.assertEqual(output.read_text(encoding="utf-8"), "version=0.1.0-beta.2\n")


class TestOciArchiveDigest(unittest.TestCase):
    def test_returns_digest_after_verifying_referenced_blob(self) -> None:
        blob = b'{"schemaVersion":2,"manifests":[]}'
        digest = f"sha256:{hashlib.sha256(blob).hexdigest()}"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "candidate.oci.tar"
            write_oci_archive(archive, blob, digest=digest)

            self.assertEqual(PUBLISH.oci_archive_digest(archive), digest)

    def test_rejects_tampered_manifest_blob(self) -> None:
        expected_blob = b"expected"
        digest = f"sha256:{hashlib.sha256(expected_blob).hexdigest()}"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "candidate.oci.tar"
            write_oci_archive(archive, b"tampered", digest=digest)

            with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                PUBLISH.oci_archive_digest(archive)

    def test_rejects_ambiguous_manifest_descriptor(self) -> None:
        blob = b"manifest"
        digest = f"sha256:{hashlib.sha256(blob).hexdigest()}"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "candidate.oci.tar"
            write_oci_archive(archive, blob, digest=digest, manifests=2)

            with self.assertRaisesRegex(RuntimeError, "exactly one manifest"):
                PUBLISH.oci_archive_digest(archive)

    def test_command_writes_verified_digest(self) -> None:
        blob = b"manifest"
        digest = f"sha256:{hashlib.sha256(blob).hexdigest()}"
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "candidate.oci.tar"
            output = Path(temp_dir) / "candidate.digest"
            write_oci_archive(archive, blob, digest=digest)

            self.assertEqual(
                PUBLISH.main(
                    ["oci-digest", "--archive", str(archive), "--output", str(output)]
                ),
                0,
            )
            self.assertEqual(output.read_text(encoding="utf-8"), f"{digest}\n")


if __name__ == "__main__":
    unittest.main()
