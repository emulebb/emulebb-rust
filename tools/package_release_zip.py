#!/usr/bin/env python3
"""Package the unsigned Windows x64 release zip for emulebb-rust.

Stages the release binary plus its user-facing docs into
``emulebb-rust-v<version>-windows-x64.zip`` and writes a ``SHA256SUMS`` beside
it. Invoked by ``.github/workflows/release.yml`` after ``cargo build --release``;
stdlib-only so it needs no extra tooling on the runner.

The artifact is always UNSIGNED (workspace policy); do not add code signing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN_NAME = "emulebb-rust.exe"
PACKAGE_ROOT = "emulebb-rust"
REQUIRED_REPO_FILES = (
    "emulebb-rust-settings.example.toml",
    "LICENSE",
)


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    version = manifest["workspace"]["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?", version):
        raise SystemExit(f"unexpected workspace version: {version!r}")
    return version


def required_path_env(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must be set; refusing to derive or override it")
    raw_path = Path(value).expanduser()
    if not raw_path.is_absolute():
        raise SystemExit(f"{name} must be an absolute path: {raw_path}")
    path = raw_path.resolve()
    if name == "EMULEBB_WORKSPACE_ROOT":
        try:
            ROOT.resolve().relative_to(path)
        except ValueError as exc:
            raise SystemExit(f"{name} must contain this checkout: {path}") from exc
    return path


def external_path(value: str | Path, label: str, workspace_root: Path | None = None) -> Path:
    """Resolve a required absolute output path outside every source checkout."""
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SystemExit(f"{label} must be an absolute path outside the source checkout: {path}")
    resolved = path.resolve()
    roots = [ROOT.resolve()]
    if workspace_root is None:
        workspace_root = required_path_env("EMULEBB_WORKSPACE_ROOT")
    roots.append(workspace_root.expanduser().resolve())
    for root in roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        raise SystemExit(f"{label} must be outside the source checkout: {resolved}")
    return resolved


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target-dir",
        required=True,
        help="cargo release output dir containing the built binary",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="output directory for the zip + SHA256SUMS",
    )
    parser.add_argument(
        "--webui-dir",
        help="built WebUI directory containing index.html; defaults to <target-dir>/webui",
    )
    parser.add_argument(
        "--release-scope",
        required=True,
        help="RELEASE-SCOPE.md source to include in the package",
    )
    args = parser.parse_args(argv)

    version = workspace_version()
    target_dir = external_path(args.target_dir, "--target-dir")
    out_dir = external_path(args.out, "--out")
    webui_dir = external_path(args.webui_dir or target_dir / "webui", "--webui-dir")
    release_scope = input_file(args.release_scope, "--release-scope")
    binary = target_dir / BIN_NAME
    if not binary.is_file():
        raise SystemExit(f"release binary not found: {binary} (run cargo build --release first)")
    webui_files = collect_webui_files(webui_dir)

    release_files = []
    for rel in REQUIRED_REPO_FILES:
        source = ROOT / rel
        if not source.is_file():
            raise SystemExit(f"required release file missing: {rel}")
        release_files.append((rel, source))

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_name = f"emulebb-rust-v{version}-windows-x64.zip"
    zip_path = out_dir / zip_name
    manifest_path = out_dir / f"emulebb-rust-v{version}-windows-x64.manifest.json"
    sbom_path = out_dir / f"emulebb-rust-v{version}-windows-x64.sbom.spdx.json"
    sums_path = out_dir / "SHA256SUMS"

    entries: list[tuple[str, Path | bytes]] = [
        (f"{PACKAGE_ROOT}/{BIN_NAME}", binary),
        (f"{PACKAGE_ROOT}/README.md", package_readme(version).encode("utf-8")),
        (f"{PACKAGE_ROOT}/RELEASE-SCOPE.md", release_scope),
    ]
    for rel, source in release_files:
        entries.append((f"{PACKAGE_ROOT}/{Path(rel).name}", source))
    for rel, source in webui_files:
        entries.append((f"{PACKAGE_ROOT}/webui/{rel.as_posix()}", source))
    sbom = build_sbom(version, zip_name, entries)
    sbom_bytes = (json.dumps(sbom, indent=2) + "\n").encode("utf-8")
    entries.append((f"{PACKAGE_ROOT}/SBOM.spdx.json", sbom_bytes))

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for archive_name, source in sorted(entries, key=lambda item: item[0]):
            if isinstance(source, bytes):
                archive.writestr(archive_name, source)
            else:
                archive.write(source, archive_name)
    assert_package_contents(zip_path)

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sbom_path.write_bytes(sbom_bytes)
    manifest = build_manifest(
        version=version,
        zip_name=zip_name,
        zip_sha256=digest,
        sbom_path=sbom_path,
        entries=entries,
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    sums_path.write_text(
        "".join(
            f"{sha256_file(path)}  {path.name}\n"
            for path in (zip_path, manifest_path, sbom_path)
        ),
        encoding="ascii",
        newline="\n",
    )

    print(f"packaged {zip_path} ({zip_path.stat().st_size} bytes)")
    print(f"sha256  {digest}")
    return 0


def input_file(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"{label} file not found: {path}")
    return path


def collect_webui_files(webui_dir: Path) -> list[tuple[Path, Path]]:
    if not webui_dir.is_dir():
        raise SystemExit(f"built WebUI directory not found: {webui_dir}")
    if not (webui_dir / "index.html").is_file():
        raise SystemExit(f"built WebUI index.html not found: {webui_dir / 'index.html'}")
    files = [
        (path.relative_to(webui_dir), path)
        for path in sorted(webui_dir.rglob("*"))
        if path.is_file()
    ]
    if not files:
        raise SystemExit(f"built WebUI directory contains no files: {webui_dir}")
    return files


def package_readme(version: str) -> str:
    return (
        f"eMuleBB Rust {version}\n"
        "====================\n\n"
        "This is the unsigned Windows x64 beta package for the headless emulebb-rust daemon.\n\n"
        "Run `emulebb-rust.exe --profile <profile-dir>` from this directory or from a script that points at a profile.\n"
        "The daemon serves the embedded browser WebUI from the packaged `webui` directory beside the executable.\n\n"
        "The native Slint UI is not shipped in this package.\n"
    )


def build_manifest(
    *,
    version: str,
    zip_name: str,
    zip_sha256: str,
    sbom_path: Path,
    entries: list[tuple[str, Path | bytes]],
) -> dict[str, object]:
    return {
        "schema": "emulebb.rust.package/1",
        "package": "emulebb-rust",
        "version": version,
        "tag": f"rust-v{version}",
        "platform": "x64",
        "configuration": "Release",
        "signed": False,
        "builtUtc": datetime.now(timezone.utc).isoformat(),
        "asset": zip_name,
        "sha256": zip_sha256,
        "executable": f"{PACKAGE_ROOT}/{BIN_NAME}",
        "webuiRoot": f"{PACKAGE_ROOT}/webui",
        "releaseScope": f"{PACKAGE_ROOT}/RELEASE-SCOPE.md",
        "settingsExample": f"{PACKAGE_ROOT}/emulebb-rust-settings.example.toml",
        "sbom": sbom_path.name,
        "sbomSha256": sha256_file(sbom_path),
        "perFileSha256": entry_hashes(entries),
        "source": {"emulebbRust": repo_provenance(ROOT)},
    }


def build_sbom(version: str, zip_name: str, entries: list[tuple[str, Path | bytes]]) -> dict[str, object]:
    files = [
        {
            "fileName": name,
            "SPDXID": spdx_ref("File", name),
            "checksums": [{"algorithm": "SHA256", "checksumValue": sha256_entry(source)}],
            "licenseConcluded": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }
        for name, source in entries
    ]
    package = {
        "name": f"emulebb-rust-{version}-windows-x64",
        "SPDXID": "SPDXRef-Package",
        "downloadLocation": f"https://github.com/emulebb/emulebb-rust/releases/download/rust-v{version}/{zip_name}",
        "filesAnalyzed": True,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "GPL-2.0-only",
        "copyrightText": "NOASSERTION",
        "versionInfo": version,
    }
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"eMuleBB Rust {version} Windows x64 package",
        "documentNamespace": f"https://github.com/emulebb/emulebb-rust/releases/download/rust-v{version}/{zip_name}.sbom",
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: emulebb-rust tools/package_release_zip.py"],
        },
        "packages": [package],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            },
            *(
                {
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": file["SPDXID"],
                }
                for file in files
            ),
        ],
        "documentDescribes": ["SPDXRef-Package"],
    }


def assert_package_contents(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = [name.replace("\\", "/") for name in archive.namelist()]
    required = {
        f"{PACKAGE_ROOT}/{BIN_NAME}",
        f"{PACKAGE_ROOT}/webui/index.html",
        f"{PACKAGE_ROOT}/emulebb-rust-settings.example.toml",
        f"{PACKAGE_ROOT}/LICENSE",
        f"{PACKAGE_ROOT}/README.md",
        f"{PACKAGE_ROOT}/RELEASE-SCOPE.md",
        f"{PACKAGE_ROOT}/SBOM.spdx.json",
    }
    missing = sorted(required.difference(names))
    if missing:
        raise SystemExit("release zip missing required entries:\n" + "\n".join(missing))
    forbidden = sorted(
        name
        for name in names
        if "emulebb-rust-ui" in Path(name).name or "emulebb-rust-diagnostics" in Path(name).name
    )
    if forbidden:
        raise SystemExit("release zip contains forbidden UI/diagnostics artifacts:\n" + "\n".join(forbidden))
    outside_root = sorted(name for name in names if not name.startswith(f"{PACKAGE_ROOT}/"))
    if outside_root:
        raise SystemExit(f"release zip contains entries outside {PACKAGE_ROOT}/:\n" + "\n".join(outside_root))


def entry_hashes(entries: list[tuple[str, Path | bytes]]) -> dict[str, str]:
    return {name: sha256_entry(source) for name, source in sorted(entries, key=lambda item: item[0])}


def sha256_entry(source: Path | bytes) -> str:
    if isinstance(source, bytes):
        return hashlib.sha256(source).hexdigest()
    return sha256_file(source)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repo_provenance(repo: Path) -> dict[str, str]:
    return {
        "commit": git_value(repo, "rev-parse", "HEAD"),
        "branch": git_value(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "remote": git_value(repo, "config", "--get", "remote.origin.url"),
    }


def git_value(repo: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def spdx_ref(prefix: str, value: str) -> str:
    suffix = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip(".-")
    return f"SPDXRef-{prefix}-{suffix or 'unknown'}"


if __name__ == "__main__":
    sys.exit(main())
