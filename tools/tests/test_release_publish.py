from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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


class TestWorkflowSource(unittest.TestCase):
    def test_default_and_matching_assertions_use_the_workflow_revision(self) -> None:
        sha = "a" * 40
        self.assertEqual(PUBLISH.resolve_workflow_source(sha), sha)
        self.assertEqual(
            PUBLISH.resolve_workflow_source(sha, source_ref=sha, candidate_ref=sha), sha,
        )

    def test_each_input_independently_rejects_another_revision(self) -> None:
        sha = "a" * 40
        for requested in (
            {"source_ref": "b" * 40},
            {"candidate_ref": "b" * 40},
            {"source_ref": sha, "candidate_ref": "b" * 40},
        ):
            with self.subTest(requested=requested):
                with self.assertRaisesRegex(RuntimeError, "must match the workflow revision"):
                    PUBLISH.resolve_workflow_source(sha, **requested)

    def test_only_full_lowercase_commit_assertions_are_accepted(self) -> None:
        for value in ("", "main", "a" * 39, "A" * 40, "a" * 40 + "\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "full lowercase commit SHA"):
                    PUBLISH.resolve_workflow_source(value)
                if value:
                    with self.assertRaisesRegex(RuntimeError, "full lowercase commit SHA"):
                        PUBLISH.resolve_workflow_source("a" * 40, candidate_ref=value)

    def test_rejected_source_cannot_write_a_success_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            output.write_text("existing=value\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "must match the workflow revision"):
                PUBLISH.main([
                    "workflow-source", "--workflow-sha", "a" * 40,
                    "--candidate-ref", "b" * 40, "--github-output", str(output),
                ])
            self.assertEqual(output.read_text(encoding="utf-8"), "existing=value\n")

    def test_command_records_only_the_verified_workflow_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            sha = "a" * 40
            self.assertEqual(PUBLISH.main([
                "workflow-source", "--workflow-sha", sha,
                "--source-ref", sha, "--github-output", str(output),
            ]), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), f"sha={sha}\n")


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

    def test_command_reads_candidate_metadata_without_executing_candidate_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            candidate = Path(temp_dir) / "candidate"
            candidate.mkdir()
            (candidate / "Cargo.toml").write_text(
                '[workspace.package]\nversion = "2.3.4-beta.5"\n', encoding="utf-8"
            )
            (candidate / "tools").mkdir()
            (candidate / "tools" / "release_publish.py").write_text(
                'raise AssertionError("candidate code must not run")\n', encoding="utf-8"
            )
            output = Path(temp_dir) / "github-output"
            self.assertEqual(PUBLISH.main([
                "release-identity", "--channel", "candidate", "--ref-name", "topic",
                "--ref-type", "branch", "--github-output", str(output),
                "--source-root", str(candidate),
            ]), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "version=2.3.4-beta.5\n")


class TestOciArchiveDigest(unittest.TestCase):
    def test_oversized_manifest_is_rejected_before_reading_the_blob(self) -> None:
        blob = b"x" * (PUBLISH.MAX_INDEX_BYTES + 1)
        digest = "sha256:" + hashlib.sha256(blob).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "oversized.oci.tar"
            write_oci_archive(archive, blob, digest=digest)
            with self.assertRaisesRegex(RuntimeError, "exceeds"):
                PUBLISH.oci_archive_digest(archive)

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


class TestDraftAssetValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.source = "1" * 40
        self.tag = "rust-v0.1.0-beta.2"
        self.release = {"id": 42, "draft": True, "prerelease": True,
                        "tag_name": self.tag, "target_commitish": self.source}
        self.expected = [{"name": "alpha.zip", "sha256": "a" * 64, "sizeBytes": 1},
                         {"name": "beta.json", "sha256": "b" * 64, "sizeBytes": 5}]
        self.assets = [{"name": row["name"], "size": row["sizeBytes"], "digest": "sha256:" + row["sha256"],
                        "state": "uploaded"} for row in self.expected]

    def validate(self, **changes):
        return PUBLISH.validate_draft_assets(**{
            "release": self.release, "assets": self.assets, "expected": self.expected,
            "tag": self.tag, "source_sha": self.source, "complete": False, **changes,
        })

    def test_matching_subset_can_resume_but_cannot_be_finalized(self) -> None:
        self.assertEqual(self.validate(assets=self.assets[:1]), 42)
        with self.assertRaisesRegex(RuntimeError, "complete verified candidate"):
            self.validate(assets=self.assets[:1], complete=True)
        self.assertEqual(self.validate(complete=True, release_id="42"), 42)

    def test_absent_release_is_allowed_only_before_upload(self) -> None:
        self.assertIsNone(self.validate(release=None, assets=[]))
        with self.assertRaisesRegex(RuntimeError, "draft release is missing"):
            self.validate(release=None, assets=[], complete=True)

    def test_published_wrong_source_or_non_prerelease_version_cannot_be_rewritten(self) -> None:
        for field, value in (("draft", False), ("prerelease", False), ("target_commitish", "2" * 40),
                             ("tag_name", "rust-v9.9.9-beta.1"), ("id", True)):
            with self.subTest(field=field):
                with self.assertRaisesRegex(RuntimeError, "outside the expected source-bound"):
                    self.validate(release={**self.release, field: value})

    def test_existing_asset_must_match_size_digest_and_completed_upload_state(self) -> None:
        for field, value in (("size", True), ("size", 2), ("digest", None),
                             ("digest", "sha256:" + "c" * 64), ("state", "starter")):
            with self.subTest(field=field, value=value):
                assets = [{**self.assets[0], field: value}, self.assets[1]]
                with self.assertRaisesRegex(RuntimeError, "asset bytes differ"):
                    self.validate(assets=assets)

    def test_unknown_duplicate_or_missing_assets_fail_closed(self) -> None:
        for assets in ([*self.assets, {**self.assets[0], "name": "unexpected.key"}],
                       [*self.assets, self.assets[0]]):
            with self.subTest(assets=assets):
                with self.assertRaisesRegex(RuntimeError, "unexpected or repeated"):
                    self.validate(assets=assets)
        with self.assertRaisesRegex(RuntimeError, "complete verified candidate"):
            self.validate(assets=[], complete=True)

    def test_finalization_requires_the_same_numeric_release_id(self) -> None:
        for value in ("43", "0", "main", "42\n"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    self.validate(complete=True, release_id=value)


class TestGitHubReleaseRows(unittest.TestCase):
    def test_all_pages_are_read_and_errors_are_not_interpreted_as_absence(self) -> None:
        pages = [[], [{"id": 1}], [{"id": 2}]]
        with mock.patch.object(PUBLISH.subprocess, "check_output", return_value=json.dumps(pages)) as query:
            self.assertEqual(PUBLISH.gh_rows("repos/example/project/releases?per_page=100"), [{"id": 1}, {"id": 2}])
        query.assert_called_once_with(
            ["gh", "api", "--paginate", "--slurp", "repos/example/project/releases?per_page=100"],
            text=True, timeout=120,
        )
        with mock.patch.object(PUBLISH.subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "gh")):
            with self.assertRaises(subprocess.CalledProcessError):
                PUBLISH.gh_rows("repos/example/project/releases?per_page=100")

    def test_malformed_pages_are_rejected(self) -> None:
        for payload in ('{"pages":[]}', '[{}]', '[["not-an-asset"]]', "not JSON"):
            with self.subTest(payload=payload):
                with mock.patch.object(PUBLISH.subprocess, "check_output", return_value=payload):
                    with self.assertRaisesRegex(RuntimeError, "malformed release metadata"):
                        PUBLISH.gh_rows("repos/example/project/releases")


class TestRegistryPublication(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = "registry.invalid/example/image"
        self.version = "0.1.0-beta.2"
        self.digests = {"ubuntu": "sha256:" + "a" * 64, "alpine": "sha256:" + "b" * 64}
        self.archives = {variant: Path(variant + ".oci.tar") for variant in self.digests}
        self.references = {}
        self.calls = []
        self.writes = []

    def client(self, *arguments):
        self.calls.append(arguments)
        operation = arguments[:2]
        if operation == ("tag", "ls"):
            return "\n".join(reference.removeprefix(self.repository + ":") for reference in self.references)
        if operation == ("image", "digest"):
            return self.references[arguments[2]]
        if operation == ("image", "import"):
            self.writes.append(arguments)
            variant = "alpine" if arguments[2].endswith("-alpine") else "ubuntu"
            self.references[arguments[2]] = self.digests[variant]
            return ""
        if operation == ("image", "copy"):
            self.writes.append(arguments)
            source, target = arguments[2:]
            self.assertTrue(source.startswith(self.repository + "@sha256:"))
            self.references[target] = source.split("@", 1)[1]
            return ""
        raise AssertionError(f"unexpected registry operation: {arguments}")

    def seed_versions(self) -> None:
        self.references = {self.repository + ":" + self.version + "-" + variant: digest
                           for variant, digest in self.digests.items()}
        self.references[self.repository + ":" + self.version] = self.digests["ubuntu"]

    def publish(self, **changes) -> None:
        PUBLISH.publish_verified_images(**{
            "repository": self.repository, "version": self.version, "digests": self.digests,
            "archives": self.archives, "client": self.client, **changes,
        })

    def promote(self, **changes) -> None:
        PUBLISH.promote_nightly(**{
            "repository": self.repository, "version": self.version, "digests": self.digests,
            "client": self.client, **changes,
        })

    def test_both_imports_and_default_alias_use_only_bound_digests(self) -> None:
        self.publish()
        self.assertEqual([row[:2] for row in self.writes], [("image", "import"), ("image", "import"), ("image", "copy")])
        self.assertEqual(self.references[self.repository + ":" + self.version], self.digests["ubuntu"])
        self.assertEqual(self.references[self.repository + ":" + self.version + "-alpine"], self.digests["alpine"])
        self.assertEqual(self.calls.count(("tag", "ls", self.repository)), 1)

    def test_conflict_in_any_immutable_tag_blocks_every_write(self) -> None:
        for suffix in ("-ubuntu", "-alpine", ""):
            with self.subTest(suffix=suffix):
                self.seed_versions()
                self.calls.clear()
                self.writes.clear()
                self.references[self.repository + ":" + self.version + suffix] = "sha256:" + "c" * 64
                with self.assertRaisesRegex(RuntimeError, "Immutable image tag conflicts"):
                    self.publish()
                self.assertFalse(self.writes)

    def test_existing_matching_versions_are_never_reimported_or_overwritten(self) -> None:
        self.seed_versions()
        self.publish()
        self.assertFalse(self.writes)

    def test_partial_import_retry_keeps_the_already_verified_ubuntu_tag(self) -> None:
        self.references[self.repository + ":" + self.version + "-ubuntu"] = self.digests["ubuntu"]
        self.publish()
        self.assertEqual([row[:2] for row in self.writes], [("image", "import"), ("image", "copy")])
        self.assertTrue(self.writes[0][2].endswith("-alpine"))

    def test_registry_transport_failure_is_never_treated_as_an_absent_tag(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            self.publish(client=mock.Mock(side_effect=subprocess.CalledProcessError(1, "regctl")))
        self.assertFalse(self.writes)

    def test_wrong_imported_digest_blocks_the_other_variant_and_default_alias(self) -> None:
        def broken(*arguments):
            value = self.client(*arguments)
            if arguments[:2] == ("image", "import"):
                self.references[arguments[2]] = "sha256:" + "c" * 64
            return value

        with self.assertRaisesRegex(RuntimeError, "Imported image differs"):
            self.publish(client=broken)
        self.assertEqual(len(self.writes), 1)

    def test_nightly_checks_all_versions_before_any_alias_change(self) -> None:
        for suffix in ("-ubuntu", "-alpine", ""):
            with self.subTest(suffix=suffix):
                self.seed_versions()
                self.writes.clear()
                self.references[self.repository + ":" + self.version + suffix] = "sha256:" + "c" * 64
                with self.assertRaisesRegex(RuntimeError, "changed before nightly promotion"):
                    self.promote()
                self.assertFalse(self.writes)

    def test_every_nightly_alias_copies_a_digest_and_is_verified_after_copy(self) -> None:
        self.seed_versions()
        self.promote()
        self.assertEqual(len(self.writes), 3)
        for tag, digest in (("nightly-ubuntu", self.digests["ubuntu"]),
                            ("nightly-alpine", self.digests["alpine"]), ("nightly", self.digests["ubuntu"])):
            self.assertEqual(self.references[self.repository + ":" + tag], digest)
        self.assertEqual(self.calls[-1], ("image", "digest", self.repository + ":nightly"))

    def test_invalid_or_missing_digest_is_rejected_before_registry_access(self) -> None:
        for value in ({"ubuntu": self.digests["ubuntu"]}, {"ubuntu": "latest", "alpine": self.digests["alpine"]}):
            with self.subTest(digests=value):
                with self.assertRaisesRegex(RuntimeError, "both bound OCI digests"):
                    self.publish(digests=value)
                self.assertFalse(self.calls)


class TestReleaseDownloadGuidance(unittest.TestCase):
    version = "0.1.0-beta.2.nightly.20261111.gaaaaaaaa"

    def inventory(self, suffixes: tuple[str, ...]) -> dict:
        return {
            "releaseVersion": self.version,
            "workflow": {"repository": "example/project", "runId": "101", "runAttempt": "2"},
            "artifacts": [{"name": f"emulebb-rust-v{self.version}-{suffix}"} for suffix in suffixes],
            "images": {},
        }

    def test_downloads_and_supporting_links_use_present_inventory_and_actual_digests(self) -> None:
        data = self.inventory(("windows-x64.zip", "linux-amd64-musl.tar.zst",
                               "android-arm64-v8a.tar.zst", "windows-x64.sbom.spdx.json"))
        data["artifacts"].append({"name": "SHA256SUMS"})
        stem = f"emulebb-rust-v{self.version}-"
        data["experimentalAndroid"] = [{"abi": "arm64-v8a", "asset": stem + "android-arm64-v8a.tar.zst"}]
        digest = "sha256:" + "a" * 64
        data["images"] = {"ubuntu": {"ociManifestDigest": digest, "archiveSha256": "b" * 64,
                                     "platforms": {"linux/amd64": {}, "linux/arm64": {}}}}
        layout = {"windows-x64": (stem + "windows-x64.zip",),
                  "linux-x64-musl": (stem + "linux-amd64-musl.tar.zst",)}
        candidate = stem + "candidate-manifest.json"
        rendered = PUBLISH.release_download_guidance(data, layout, candidate)
        for heading in ("Native packages", "Portable Linux musl", "Experimental Android native packages",
                        "Container images", "Verification and supporting files"):
            self.assertIn("### " + heading, rendered)
        for artifact in data["artifacts"]:
            self.assertIn(f"/releases/download/rust-v{self.version}/{artifact['name']}", rendered)
        self.assertIn(f"ghcr.io/example/project@{digest}", rendered)
        self.assertNotIn("b" * 64, rendered)
        self.assertIn(candidate, rendered)
        self.assertIn("/actions/runs/101/attempts/2", rendered)
        self.assertIn("Device runtime, transfers and VPN behavior remain unqualified", rendered)
        self.assertIn("APK packaging and signing remain deferred", rendered)
        self.assertNotIn("android-x86_64", rendered)
        self.assertNotIn("Alpine", rendered)

    def test_absent_platforms_and_empty_groups_are_omitted(self) -> None:
        data = self.inventory(("windows-x64.zip",))
        stem = f"emulebb-rust-v{self.version}-"
        layout = {"windows-x64": (stem + "windows-x64.zip",),
                  "windows-arm64": (stem + "windows-arm64.zip",),
                  "linux-x64-musl": (stem + "linux-amd64-musl.tar.zst",)}
        data["experimentalAndroid"] = [{"abi": "x86_64", "asset": stem + "android-x86_64.tar.zst"}]
        rendered = PUBLISH.release_download_guidance(data, layout, stem + "candidate-manifest.json")
        self.assertIn("Windows x64", rendered)
        for fragment in ("Windows ARM64", "Portable Linux musl", "Android", "Container images",
                         "SHA256SUMS", "SBOMs", "ghcr.io"):
            self.assertNotIn(fragment, rendered)

    def test_finalization_verifies_original_inputs_and_rehashes_final_notes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            notes = root / f"RELEASE-{self.version}-NOTES.md"
            original = f"# eMuleBB Rust {self.version}\n\nCurrent nightly.\n\n## Profile compatibility\n\nUse a fresh test profile.\n"
            notes.write_text(original, encoding="utf-8")
            (root / "SHA256SUMS").write_text("original checksum\n", encoding="ascii")
            asset = root / f"emulebb-rust-v{self.version}-windows-x64.zip"
            asset.write_bytes(b"synthetic package")
            data = self.inventory(("windows-x64.zip",))
            data["artifacts"].extend(({"name": notes.name}, {"name": "SHA256SUMS"}))
            owner = mock.Mock()
            context = mock.Mock(version=self.version)
            candidate = root / f"emulebb-rust-v{self.version}-candidate-manifest.json"
            owner.candidate_path.return_value = candidate
            owner.package_layout.return_value = {"windows-x64": (asset.name,)}

            def verify_original(**_kwargs):
                self.assertEqual(notes.read_text(encoding="utf-8"), original)
                self.assertEqual((root / "SHA256SUMS").read_text(), "original checksum\n")
                return data

            def format_sums(directory, members):
                self.assertEqual(directory, root)
                self.assertIn("## Downloads", notes.read_text(encoding="utf-8"))
                return "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in members)

            owner.candidate_manifest.side_effect = verify_original
            owner._sha256sums_text.side_effect = format_sums
            PUBLISH.finalize_release_notes(
                owner, release_dir=root, context=context, archives_dir=root / "archives", archive_identity=object(),
            )
            result = notes.read_text(encoding="utf-8")
            self.assertLess(result.index("## Downloads"), result.index("## Profile compatibility"))
            self.assertIn(f"{hashlib.sha256(notes.read_bytes()).hexdigest()}  {notes.name}\n",
                          (root / "SHA256SUMS").read_text())
            owner.candidate_manifest.assert_called_once()
            owner._sha256sums_text.assert_called_once()
            self.assertFalse(candidate.exists())

    def test_input_integrity_failure_preserves_notes_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            notes = root / f"RELEASE-{self.version}-NOTES.md"
            notes.write_bytes(b"original notes")
            sums = root / "SHA256SUMS"
            sums.write_bytes(b"original checksums")
            owner = mock.Mock()
            owner.candidate_manifest.side_effect = RuntimeError("input integrity failed")
            with self.assertRaisesRegex(RuntimeError, "input integrity failed"):
                PUBLISH.finalize_release_notes(
                    owner, release_dir=root, context=mock.Mock(version=self.version),
                    archives_dir=root / "archives", archive_identity=object(),
                )
            self.assertEqual(notes.read_bytes(), b"original notes")
            self.assertEqual(sums.read_bytes(), b"original checksums")
            owner._sha256sums_text.assert_not_called()


class TestCandidateControl(unittest.TestCase):
    def test_registry_writes_require_actual_archive_verification_and_current_source_checks(self) -> None:
        for fault in ("archive", "assembly-hash", "source"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / "emulebb-rust-v0.1.0-beta.2-candidate-manifest.json"
                data = {"images": {variant: {"archive": variant + ".oci.tar",
                                             "ociManifestDigest": "sha256:" + character * 64}
                                   for variant, character in (("ubuntu", "a"), ("alpine", "b"))}}
                path.write_text(json.dumps(data), encoding="utf-8")
                owner = mock.Mock()
                owner.candidate_path.return_value = path
                owner.verify_candidate.return_value = data
                if fault == "archive":
                    owner.verify_candidate.side_effect = RuntimeError("actual archive changed")
                digest = "f" * 64 if fault == "assembly-hash" else hashlib.sha256(path.read_bytes()).hexdigest()
                with (
                    mock.patch.object(PUBLISH, "candidate_owner", return_value=owner),
                    mock.patch.object(PUBLISH, "candidate_context", return_value=object()),
                    mock.patch.object(PUBLISH, "archive_identity_reader", return_value=object()),
                    mock.patch.object(PUBLISH, "require_publication_source") as source,
                    mock.patch.object(PUBLISH, "publish_verified_images") as publish,
                ):
                    if fault == "source":
                        source.side_effect = RuntimeError("latest source workflow is not green")
                    with self.assertRaises(RuntimeError):
                        PUBLISH.main([
                            "publish-images", *self.common(root), "--archives-dir", str(root / "archives"),
                            "--harness-repo", str(root / "harness"), "--assembled-candidate-sha256", digest,
                        ])
                publish.assert_not_called()
                if fault != "source":
                    source.assert_not_called()

    def test_expected_identities_can_come_from_the_workflow_environment(self) -> None:
        environment = {
            "RELEASE_VERSION": "0.1.0-beta.2", "RELEASE_CHANNEL": "candidate",
            "EMULEBB_SOURCE_REVISION": "1" * 40, "EMULEBB_BUILD_REF": "2" * 40,
            "EMULEBB_BUILD_TESTS_REF": "3" * 40, "EMULEBB_TOOLING_REF": "4" * 40,
            "MINIUPNP_REF": "5" * 40, "PCPNATPMP_REF": "6" * 40,
            "GITHUB_REPOSITORY": "example/project", "GITHUB_RUN_ID": "101",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW_SHA": "7" * 40,
        }
        with mock.patch.dict(PUBLISH.os.environ, environment):
            args = PUBLISH.build_parser().parse_args([
                "verify-public-candidate", "--release-dir", "synthetic", "--build-repo", "build",
                "--verified-candidate-sha256", "a" * 64,
            ])
        self.assertEqual(args.source_sha, "1" * 40)
        self.assertEqual(args.emulebb_build_ref, "2" * 40)
        self.assertEqual(args.emulebb_build_tests_ref, "3" * 40)
        self.assertEqual(args.workflow_sha, "7" * 40)
        self.assertEqual((args.repository, args.run_id, args.run_attempt), ("example/project", "101", "2"))

    @staticmethod
    def common(root: Path) -> list[str]:
        return [
            "--release-dir", str(root), "--release-version", "0.1.0-beta.2", "--channel", "candidate",
            "--source-sha", "1" * 40, "--emulebb-build-ref", "2" * 40,
            "--emulebb-build-tests-ref", "3" * 40, "--emulebb-tooling-ref", "4" * 40,
            "--emulebb-miniupnp-ref", "5" * 40, "--emulebb-libpcpnatpmp-ref", "6" * 40,
            "--repository", "example/project", "--run-id", "101", "--run-attempt", "2",
            "--workflow-sha", "7" * 40, "--build-repo", str(root / "build"),
        ]

    def test_assembly_and_verification_delegate_to_the_checked_packaging_owner(self) -> None:
        for command in ("candidate-manifest", "verify-candidate", "verify-public-candidate"):
            with self.subTest(command=command), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                path = root / "emulebb-rust-v0.1.0-beta.2-candidate-manifest.json"
                data = {"images": {"ubuntu": {"ociManifestDigest": "sha256:" + "a" * 64},
                                   "alpine": {"ociManifestDigest": "sha256:" + "b" * 64}}}
                path.write_text(json.dumps(data), encoding="utf-8")
                owner = mock.Mock()
                owner.candidate_path.return_value = path
                owner.verify_candidate.return_value = data
                owner.verify_public_candidate.return_value = data
                context, reader = object(), object()
                extra = ["--github-output", str(root / "github-output")]
                if command == "candidate-manifest":
                    extra += ["--output", str(path)]
                    path.unlink()
                    owner.write_candidate.side_effect = lambda **_kwargs: path.write_text(
                        json.dumps(data), encoding="utf-8",
                    )
                if command in {"candidate-manifest", "verify-candidate"}:
                    extra += ["--archives-dir", str(root / "archives"), "--harness-repo", str(root / "harness")]
                else:
                    extra += ["--verified-candidate-sha256", "c" * 64]
                with (
                    mock.patch.object(PUBLISH, "candidate_owner", return_value=owner),
                    mock.patch.object(PUBLISH, "candidate_context", return_value=context),
                    mock.patch.object(PUBLISH, "archive_identity_reader", return_value=reader) as load_reader,
                    mock.patch.object(PUBLISH, "finalize_release_notes") as finalize,
                ):
                    self.assertEqual(PUBLISH.main([command, *self.common(root), *extra]), 0)
                if command == "candidate-manifest":
                    finalize.assert_called_once_with(
                        owner, release_dir=root, context=context, archives_dir=root / "archives", archive_identity=reader,
                    )
                    owner.write_candidate.assert_called_once_with(
                        release_dir=root, context=context, archives_dir=root / "archives", archive_identity=reader,
                    )
                elif command == "verify-candidate":
                    finalize.assert_not_called()
                    owner.verify_candidate.assert_called_once_with(
                        release_dir=root, context=context, archives_dir=root / "archives", archive_identity=reader,
                    )
                else:
                    finalize.assert_not_called()
                    load_reader.assert_not_called()
                    owner.verify_public_candidate.assert_called_once_with(
                        release_dir=root, context=context, verified_candidate_sha256="c" * 64,
                    )
                outputs = (root / "github-output").read_text(encoding="utf-8")
                self.assertIn("candidate_sha256=" + hashlib.sha256(path.read_bytes()).hexdigest(), outputs)
                self.assertIn("ubuntu_digest=sha256:" + "a" * 64, outputs)
                self.assertIn("alpine_digest=sha256:" + "b" * 64, outputs)

    def test_existing_candidate_cannot_trigger_notes_or_checksum_rewrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            path = root / "emulebb-rust-v0.1.0-beta.2-candidate-manifest.json"
            path.write_bytes(b"immutable candidate")
            owner = mock.Mock()
            owner.candidate_path.return_value = path
            with (
                mock.patch.object(PUBLISH, "candidate_owner", return_value=owner),
                mock.patch.object(PUBLISH, "candidate_context", return_value=object()),
                mock.patch.object(PUBLISH, "archive_identity_reader", return_value=object()),
                mock.patch.object(PUBLISH, "finalize_release_notes") as finalize,
            ):
                with self.assertRaisesRegex(RuntimeError, "already exists"):
                    PUBLISH.main([
                        "candidate-manifest", *self.common(root), "--output", str(path),
                        "--archives-dir", str(root / "archives"), "--harness-repo", str(root / "harness"),
                    ])
            self.assertEqual(path.read_bytes(), b"immutable candidate")
            finalize.assert_not_called()
            owner.write_candidate.assert_not_called()

    def test_local_calls_fail_before_checkout_or_import(self) -> None:
        args = PUBLISH.build_parser().parse_args([
            "verify-public-candidate", *self.common(Path("synthetic")),
            "--verified-candidate-sha256", "a" * 64,
        ])
        with (
            mock.patch.dict(PUBLISH.os.environ, {"GITHUB_ACTIONS": "false"}),
            mock.patch.object(PUBLISH, "checked_checkout") as checkout,
            mock.patch.object(PUBLISH.importlib, "import_module") as load,
        ):
            with self.assertRaisesRegex(RuntimeError, "actual GitHub run"):
                PUBLISH.candidate_owner(args)
        checkout.assert_not_called()
        load.assert_not_called()

    def test_dirty_packaging_owner_is_never_imported(self) -> None:
        args = PUBLISH.build_parser().parse_args([
            "verify-public-candidate", *self.common(Path("synthetic")),
            "--verified-candidate-sha256", "a" * 64,
        ])
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "example/project",
                       "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_WORKFLOW_SHA": "7" * 40}
        with (
            mock.patch.dict(PUBLISH.os.environ, environment),
            mock.patch.object(PUBLISH, "checked_checkout", side_effect=[PUBLISH.ROOT, RuntimeError("dirty owner")]),
            mock.patch.object(PUBLISH.importlib, "import_module") as load,
        ):
            with self.assertRaisesRegex(RuntimeError, "dirty owner"):
                PUBLISH.candidate_owner(args)
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
