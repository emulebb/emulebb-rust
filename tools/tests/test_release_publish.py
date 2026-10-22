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


def write_candidate_evidence(release_dir: Path, version: str) -> str:
    stem = f"emulebb-rust-v{version}"
    names = (
        "SHA256SUMS",
        f"{stem}-image-security-SHA256SUMS",
        f"{stem}-windows-x64.zip",
        f"{stem}-windows-arm64.zip",
        f"{stem}-linux-amd64.deb",
        f"{stem}-linux-x86_64.AppImage",
        f"{stem}-linux-arm64.deb",
        f"{stem}-linux-aarch64.AppImage",
        f"{stem}-macos-x64.dmg",
        f"{stem}-macos-arm64.dmg",
    )
    for name in names:
        (release_dir / name).write_bytes(f"payload:{name}".encode("ascii"))
    package_smoke_assets = {
        "windows-x64": [f"{stem}-windows-x64.zip"],
        "windows-arm64": [f"{stem}-windows-arm64.zip"],
        "linux-x64": [
            f"{stem}-linux-amd64.deb",
            f"{stem}-linux-x86_64.AppImage",
        ],
        "linux-arm64": [
            f"{stem}-linux-arm64.deb",
            f"{stem}-linux-aarch64.AppImage",
        ],
        "macos-x64": [f"{stem}-macos-x64.dmg"],
        "macos-arm64": [f"{stem}-macos-arm64.dmg"],
    }
    for platform, assets in package_smoke_assets.items():
        write_package_smoke_report(release_dir, version, platform, assets)
    digest = f"sha256:{'a' * 64}"
    (release_dir / f"{stem}-multiarch.oci.digest").write_text(f"{digest}\n", encoding="utf-8")
    return digest


def write_package_smoke_report(
    release_dir: Path,
    version: str,
    platform: str,
    assets: list[str],
) -> Path:
    payload_sha256 = "b" * 64
    payload_size = 262_144
    report = {
        "schema": "emulebb.rust.package-smoke/2",
        "platform": platform,
        "results": [
            {
                "asset": asset,
                "status": "passed",
                "localTransfer": {
                    "payload": {
                        "name": "emulebb-package-smoke.bin",
                        "sizeBytes": payload_size,
                        "sha256": payload_sha256,
                    },
                    "sharedFile": {
                        "hash": "c" * 32,
                        "name": "emulebb-package-smoke.bin",
                        "sizeBytes": payload_size,
                    },
                    "transferAccepted": True,
                    "delivery": {
                        "hash": "c" * 32,
                        "state": "completed",
                        "completedBytes": payload_size,
                        "deliveredPathWithinIncoming": True,
                        "deliveredSha256": payload_sha256,
                        "observations": [],
                    },
                    "sourceDiscovery": "ed2k-link-direct-source",
                    "publicDiscoveryDisabled": True,
                    "gracefulShutdowns": 2,
                },
            }
            for asset in assets
        ],
    }
    path = release_dir / f"emulebb-rust-v{version}-package-smoke-{platform}.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


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


class TestCandidateManifest(unittest.TestCase):
    def test_records_exact_revisions_and_release_evidence(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            expected_digest = write_candidate_evidence(release_dir, version)
            output = release_dir / f"emulebb-rust-v{version}-candidate-manifest.json"
            manifest = PUBLISH.write_candidate_manifest(
                release_dir=release_dir,
                output=output,
                release_version=version,
                channel="candidate",
                source_sha="1" * 40,
                support_refs={
                    "emulebbBuild": "2" * 40,
                    "emulebbBuildTests": "3" * 40,
                    "emulebbTooling": "4" * 40,
                    "emulebbMiniupnp": "5" * 40,
                    "emulebbLibpcpnatpmp": "6" * 40,
                },
                repository="emulebb/emulebb-rust",
                run_id="123",
                run_attempt="2",
            )

            self.assertEqual(manifest["source"]["emulebbRust"], "1" * 40)
            self.assertEqual(manifest["ociManifestDigest"], expected_digest)
            self.assertEqual(manifest["formatVersion"], 2)
            self.assertEqual(
                {evidence["platform"] for evidence in manifest["packageSmoke"]},
                {
                    "windows-x64",
                    "windows-arm64",
                    "linux-x64",
                    "linux-arm64",
                    "macos-x64",
                    "macos-arm64",
                },
            )
            artifact_names = {artifact["name"] for artifact in manifest["artifacts"]}
            self.assertIn(f"emulebb-rust-v{version}-windows-x64.zip", artifact_names)
            self.assertIn(
                f"emulebb-rust-v{version}-package-smoke-windows-x64.json",
                artifact_names,
            )
            self.assertNotIn(output.name, artifact_names)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), manifest)

    def test_rejects_missing_package_smoke_report(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)
            (release_dir / f"emulebb-rust-v{version}-package-smoke-macos-arm64.json").unlink()

            with self.assertRaisesRegex(RuntimeError, "candidate release evidence is missing"):
                PUBLISH.write_candidate_manifest(
                    release_dir=release_dir,
                    output=release_dir / "candidate.json",
                    release_version=version,
                    channel="candidate",
                    source_sha="1" * 40,
                    support_refs={"emulebbBuild": "2" * 40},
                    repository="emulebb/emulebb-rust",
                    run_id="123",
                    run_attempt="1",
                )

    def test_rejects_failed_package_transfer(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)
            report_path = release_dir / f"emulebb-rust-v{version}-package-smoke-windows-x64.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["results"][0]["status"] = "failed"
            report_path.write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "result 0 did not pass"):
                PUBLISH.write_candidate_manifest(
                    release_dir=release_dir,
                    output=release_dir / "candidate.json",
                    release_version=version,
                    channel="candidate",
                    source_sha="1" * 40,
                    support_refs={"emulebbBuild": "2" * 40},
                    repository="emulebb/emulebb-rust",
                    run_id="123",
                    run_attempt="1",
                )

    def test_rejects_malformed_package_smoke_report(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)
            report_path = release_dir / f"emulebb-rust-v{version}-package-smoke-macos-x64.json"
            report_path.write_text("{not-json", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "could not read package smoke report"):
                PUBLISH.write_candidate_manifest(
                    release_dir=release_dir,
                    output=release_dir / "candidate.json",
                    release_version=version,
                    channel="candidate",
                    source_sha="1" * 40,
                    support_refs={"emulebbBuild": "2" * 40},
                    repository="emulebb/emulebb-rust",
                    run_id="123",
                    run_attempt="1",
                )

    def test_rejects_package_transfer_digest_mismatch(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)
            report_path = release_dir / f"emulebb-rust-v{version}-package-smoke-linux-x64.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["results"][0]["localTransfer"]["delivery"]["deliveredSha256"] = "d" * 64
            report_path.write_text(json.dumps(report), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "delivered SHA-256 does not match"):
                PUBLISH.write_candidate_manifest(
                    release_dir=release_dir,
                    output=release_dir / "candidate.json",
                    release_version=version,
                    channel="candidate",
                    source_sha="1" * 40,
                    support_refs={"emulebbBuild": "2" * 40},
                    repository="emulebb/emulebb-rust",
                    run_id="123",
                    run_attempt="1",
                )

    def test_rejects_mutable_support_ref(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)

            with self.assertRaisesRegex(RuntimeError, "full lowercase commit SHAs"):
                PUBLISH.write_candidate_manifest(
                    release_dir=release_dir,
                    output=release_dir / "candidate.json",
                    release_version=version,
                    channel="candidate",
                    source_sha="1" * 40,
                    support_refs={"emulebbBuild": "main"},
                    repository="emulebb/emulebb-rust",
                    run_id="123",
                    run_attempt="1",
                )

    def test_command_writes_candidate_manifest(self) -> None:
        version = "0.1.0-beta.2"
        with tempfile.TemporaryDirectory() as temp_dir:
            release_dir = Path(temp_dir)
            write_candidate_evidence(release_dir, version)
            output = release_dir / "candidate.json"

            self.assertEqual(
                PUBLISH.main(
                    [
                        "candidate-manifest",
                        "--release-dir",
                        str(release_dir),
                        "--output",
                        str(output),
                        "--release-version",
                        version,
                        "--channel",
                        "candidate",
                        "--source-sha",
                        "1" * 40,
                        "--emulebb-build-ref",
                        "2" * 40,
                        "--emulebb-build-tests-ref",
                        "3" * 40,
                        "--emulebb-tooling-ref",
                        "4" * 40,
                        "--emulebb-miniupnp-ref",
                        "5" * 40,
                        "--emulebb-libpcpnatpmp-ref",
                        "6" * 40,
                        "--repository",
                        "emulebb/emulebb-rust",
                        "--run-id",
                        "123",
                        "--run-attempt",
                        "1",
                    ]
                ),
                0,
            )
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["formatVersion"],
                2,
            )


if __name__ == "__main__":
    unittest.main()
