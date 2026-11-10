"""Pinned CI tools and explicit local input provenance; no operator configuration repair."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = json.loads((ROOT / "tools/ci-toolchain.json").read_text(encoding="utf-8"))
VERSION_PROBE_DIAGNOSTIC_BYTES = 4096


def require_version(name: str, actual: str, expected: str) -> str:
    """Refuse to describe checks run with a different toolchain as equivalent."""
    if actual != expected:
        raise RuntimeError(f"{name} version mismatch: expected {expected}, observed {actual}")
    return actual


def _version_probe_diagnostic(output: str | bytes | None) -> str:
    """Keep a bounded diagnostic tail without credentials or signed URL values."""
    text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output or ""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    for name, value in os.environ.items():
        if len(value) >= 8 and re.search(r"TOKEN|PASSWORD|SECRET|API_?KEY|CREDENTIAL", name, re.I):
            text = text.replace(value, "<redacted>")
    text = re.sub(r"(?im)(\bauthorization\s*:\s*)[^\r\n]+", r"\1<redacted>", text)
    text = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer <redacted>", text)
    text = re.sub(
        r"(?i)\b([A-Z0-9_]*(?:TOKEN|PASSWORD|SECRET|API_?KEY|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*)"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s]+)", r"\1<redacted>", text,
    )

    def public_url(match: re.Match[str]) -> str:
        try:
            parts = urllib.parse.urlsplit(match.group(0))
            return urllib.parse.urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))
        except ValueError:
            return "<redacted-url>"

    text = re.sub(r"https?://[^\s\"'<>]+", public_url, text).strip() or "(no captured output)"
    encoded = text.encode("utf-8")
    if len(encoded) > VERSION_PROBE_DIAGNOSTIC_BYTES:
        marker = "[truncated diagnostic tail]\n"
        budget = VERSION_PROBE_DIAGNOSTIC_BYTES - len(marker.encode("utf-8"))
        return marker + encoded[-budget:].decode("utf-8", errors="ignore")
    return text


def command_version(command: list[str], pattern: str) -> str:
    """Read a tool version using its public CLI in the selected Rust checkout."""
    label = Path(command[0]).name
    try:
        text = subprocess.check_output(command, cwd=ROOT, text=True, stderr=subprocess.STDOUT, timeout=30)
    except subprocess.CalledProcessError as error:
        # WHY: CalledProcessError.__str__ omits captured output, losing the
        # actual toolchain failure before the environment report can be written.
        raise RuntimeError(
            f"Version probe for {label} failed (exit {error.returncode}):\n{_version_probe_diagnostic(error.output)}"
        ) from None
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Version probe for {label} timed out after {error.timeout}s:\n{_version_probe_diagnostic(error.output)}"
        ) from None
    match = re.search(pattern, text)
    if match is None:
        raise RuntimeError(f"Cannot identify version of {label}: {_version_probe_diagnostic(text)}")
    return match.group(1)


def archive_binary(archive: Path, executable: str) -> bytes:
    """Read only the expected binary, without extracting archive-controlled paths."""
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as source:
            names = [name for name in source.namelist() if PurePosixPath(name).name == executable]
            if len(names) != 1:
                raise RuntimeError("ShellCheck archive must contain exactly one expected binary")
            return source.read(names[0])
    with tarfile.open(archive, "r:gz") as source:
        members = [member for member in source.getmembers() if member.isfile() and PurePosixPath(member.name).name == executable]
        if len(members) != 1:
            raise RuntimeError("ShellCheck archive must contain exactly one expected binary")
        return source.extractfile(members[0]).read()


def ensure_shellcheck(output: Path) -> Path:
    """Install the checksum-pinned official tool under the external output root."""
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    key = f"{platform.system().lower()}-{machine}"
    config = TOOLCHAIN["shellcheck"]
    if key not in config["assets"]:
        raise RuntimeError(f"No reviewed ShellCheck asset for {key}")
    filename, expected_hash = config["assets"][key]
    cache = output / "cache" / "ci-tools"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / filename
    if not archive.is_file():
        url = f"https://github.com/koalaman/shellcheck/releases/download/v{config['version']}/{filename}"
        print(f"Downloading pinned ShellCheck {config['version']} for {key}", flush=True)
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as temporary:
            temporary_path = Path(temporary.name)
        try:
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(url, timeout=60) as response, temporary_path.open("wb") as target:
                        shutil.copyfileobj(response, target)
                    break
                except (urllib.error.URLError, TimeoutError, ConnectionResetError) as error:
                    if isinstance(error, urllib.error.HTTPError) and error.code not in {429, 500, 502, 503, 504}:
                        raise
                    if attempt == 2:
                        raise
                    print(f"Transient ShellCheck download failure; retry {attempt + 1}/2", flush=True)
                    time.sleep(2 ** attempt)
            with temporary_path.open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != expected_hash:
                    raise RuntimeError("Downloaded ShellCheck archive checksum mismatch")
            temporary_path.replace(archive)
        finally:
            temporary_path.unlink(missing_ok=True)
    with archive.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != expected_hash:
            raise RuntimeError(f"Cached ShellCheck archive checksum mismatch: {archive}")
    executable = "shellcheck.exe" if os.name == "nt" else "shellcheck"
    binary = archive_binary(archive, executable)
    target = output / "tools" / "shellcheck" / config["version"] / key / executable
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_file() or hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(binary).digest():
        target.write_bytes(binary)
    target.chmod(0o755)
    require_version("ShellCheck", command_version([str(target), "--version"], r"version: (\S+)"), config["version"])
    return target


def prepare_command(command: list[str], env: dict[str, str]) -> list[str]:
    """Check relevant tool versions and make ShellCheck coverage mandatory."""
    if command[0] == sys.executable:
        require_version("Python", platform.python_version(), TOOLCHAIN["python"])
        if any(Path(argument).name in {"test_webui.py", "fresh_rust_build.py"} for argument in command):
            node_versions()
        if command[-1].endswith("rust-rest-openapi-ci.py"):
            print(json.dumps({"conformance_inputs": report_inputs(env, ("emulebb-build-tests", "emulebb-tooling"))}, indent=2), flush=True)
    elif command[:2] == ["go", "run"]:
        require_version("Go", command_version(["go", "version"], r"go version go(\S+)"), TOOLCHAIN["go"])
        shellcheck = ensure_shellcheck(Path(env["EMULEBB_WORKSPACE_OUTPUT_ROOT"]))
        return [*command, f"-shellcheck={shellcheck}"]
    elif command[:2] == ["cargo", "deny"]:
        require_version("cargo-deny", command_version(["cargo", "deny", "--version"], r"cargo-deny (\S+)"), TOOLCHAIN["cargo_deny"])
    elif command[0] == "cargo":
        expected = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
        require_version("Rust", command_version(["rustc", "--version"], r"rustc (\S+)"), expected)
    return command


def node_versions() -> dict:
    """Require identical Node and npm versions for UI tests and staged assets."""
    npm = shutil.which("npm")
    if not npm:
        raise RuntimeError("The pinned npm tool is required for WebUI validation")
    return {
        "node": require_version("Node", command_version(["node", "--version"], r"v(\S+)"), TOOLCHAIN["node"]),
        "npm": require_version("npm", command_version([npm, "--version"], r"(\d+\.\d+\.\d+)"), TOOLCHAIN["npm"]),
    }


def input_state(path: Path, expected: str) -> dict:
    """Report source differences rather than replacing an operator checkout."""
    def git(*args):
        return subprocess.check_output(["git", "-C", str(path), *args], text=True, stderr=subprocess.PIPE).strip()
    if not path.is_dir():
        return {"expected": expected, "status": "missing"}
    head = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain"))
    return {"expected": expected, "observed": head, "dirty": dirty, "status": "matching" if head == expected and not dirty else "different"}


def native_source_root(name: str, env: dict[str, str]) -> Path:
    """Match native build-script discovery for canonical and managed checkouts."""
    variable = {"emulebb-miniupnp": "MINIUPNP_ROOT", "emulebb-libpcpnatpmp": "PCPNATPMP_ROOT"}[name]
    if variable in env:
        return Path(env[variable])
    if "EMULEBB_WORKSPACE_ROOT" in env:
        root = Path(env["EMULEBB_WORKSPACE_ROOT"])
        if not root.is_absolute() or not root.is_dir():
            raise RuntimeError("EMULEBB_WORKSPACE_ROOT must identify an existing absolute workspace root")
        root = root.resolve()
        if not ROOT.resolve().is_relative_to(root):
            raise RuntimeError("EMULEBB_WORKSPACE_ROOT must contain this checkout")
        # WHY: worktrees are not native-source siblings. Use the same canonical
        # repos/third_party contract as the Cargo build scripts.
        return root / "repos" / "third_party" / name
    return ROOT.parent / "third_party" / name


def report_inputs(env: dict[str, str], names=None) -> dict:
    """Identify the same native source locations used by the build scripts."""
    from rust_quality_gate import require_workspace_root_env
    root = require_workspace_root_env(env)
    inputs = {}
    for name, ref in TOOLCHAIN["inputs"].items():
        if names is not None and name not in names:
            continue
        variable = {"emulebb-miniupnp": "MINIUPNP_ROOT", "emulebb-libpcpnatpmp": "PCPNATPMP_ROOT"}.get(name)
        if variable:
            path = native_source_root(name, env)
        else:
            path = root / "repos" / name
        inputs[name] = input_state(path, ref)
    if names is None or "emulebb-tooling" in names:
        override = env.get("EMULEBB_REST_OPENAPI_CONTRACT_PATH")
        contract = Path(override) if override else root / "repos/emulebb-tooling/docs/products/emulebb-rust/api/REST-API-OPENAPI.yaml"
        observed = hashlib.sha256(contract.read_bytes()).hexdigest() if contract.is_file() else None
        expected = TOOLCHAIN["openapi_sha256"]
        inputs["REST-API-OPENAPI.yaml"] = {
            "expected": expected, "observed": observed, "override": bool(override),
            "status": "matching" if observed == expected else "different" if observed else "missing",
        }
    return inputs


def environment_report(env: dict[str, str], *, scope: str = "full") -> dict:
    """Capture versions and the exact inputs behind a local or hosted result."""
    if scope not in {"full", "quality"}:
        raise ValueError("Environment scope must be full or quality")
    shellcheck = None
    versions = {"python": require_version("Python", platform.python_version(), TOOLCHAIN["python"])}
    if scope == "full":
        shellcheck = ensure_shellcheck(Path(env["EMULEBB_WORKSPACE_OUTPUT_ROOT"]))
        for key, command, pattern in (
            ("go", ["go", "version"], r"go version go(\S+)"),
            ("cargo_deny", ["cargo", "deny", "--version"], r"cargo-deny (\S+)"),
        ):
            versions[key] = require_version(key, command_version(command, pattern), TOOLCHAIN[key])
        versions["shellcheck"] = TOOLCHAIN["shellcheck"]["version"]
        versions["actionlint"] = TOOLCHAIN["actionlint"]
    expected_rust = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))["toolchain"]["channel"]
    versions["rust"] = require_version("Rust", command_version(["rustc", "--version"], r"rustc (\S+)"), expected_rust)
    versions.update(node_versions())
    versions["python_packages"] = {line.split("==")[0]: require_version(line.split("==")[0], importlib.metadata.version(line.split("==")[0]), line.split("==")[1]) for line in (ROOT / "tools/requirements-ci.txt").read_text().splitlines() if "==" in line}
    report = {"scope": scope, "tools": versions, "inputs": report_inputs(env), "platform": platform.platform(),
              "shellcheck": str(shellcheck) if shellcheck is not None else None}
    report_dir = Path(env["EMULEBB_WORKSPACE_OUTPUT_ROOT"]) / "reports" / "ci-environment"
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "latest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    from rust_quality_gate import build_env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("full", "quality"), default="full")
    report = environment_report(build_env(), scope=parser.parse_args().scope)
    print(json.dumps(report, indent=2))
    if any(item["status"] != "matching" for item in report["inputs"].values()):
        print("Input differences recorded: this result describes the current checkouts; GitHub checks the declared pinned inputs.")
