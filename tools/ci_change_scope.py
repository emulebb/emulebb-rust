#!/usr/bin/env python3
"""Classify immutable GitHub inputs using only a protected base revision's code.

The workflows extract this stdlib-only file from the event's base commit and run
it with Python isolation. It never imports code from the checkout under review.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib


SCHEMA = "emulebb.ci-change-scope/1"
CLASSIFIER = "tools/ci_change_scope.py"
SHA = re.compile(r"[0-9a-f]{40}")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
TEXT_LIMIT = 1024 * 1024


def git(repo: Path, *arguments: str, stdin: bytes | None = None) -> bytes:
    """Read Git objects without a shell or external diff/textconv execution."""
    return subprocess.run(["git", "-C", str(repo), *arguments], input=stdin,
                          check=True, capture_output=True, timeout=30).stdout


def exact_equal(left: object, right: object) -> bool:
    """Compare TOML types as well as values; bool/int/float are not aliases."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(exact_equal(left[key], right[key]) for key in left)
    if isinstance(left, list):
        return len(left) == len(right) and all(exact_equal(a, b) for a, b in zip(left, right))
    return left == right


def text_blob(repo: Path, object_id: str) -> str:
    size = int(git(repo, "cat-file", "-s", object_id))
    if size > TEXT_LIMIT:
        raise ValueError("text exceeds validation limit")
    raw = git(repo, "cat-file", "blob", object_id)
    if b"\0" in raw or any(byte < 32 and byte not in (9, 10) for byte in raw):
        raise ValueError("not regular LF text")
    return raw.decode("utf-8")


def phase_gate_only(before: str, after: str) -> bool:
    """Permit the existing descriptive phase gate while preserving every key."""
    left, right = tomllib.loads(before), tomllib.loads(after)
    for value in (left, right):
        product = value.get("product")
        if (type(product) is not dict or type(product.get("phase_gate")) is not str
                or not product["phase_gate"].strip()):
            return False
        del product["phase_gate"]
    return exact_equal(left, right)


def repository_from_origin(origin: str) -> str | None:
    for prefix in ("https://github.com/", "git@github.com:", "ssh://git@github.com/"):
        if origin.startswith(prefix):
            value = origin[len(prefix):].removesuffix(".git")
            return value if REPOSITORY.fullmatch(value) else None
    return None


def classify(repo: Path, event: dict, event_name: str, repository: str,
             tested_sha: str, base_sha: str, classifier_path: Path) -> dict:
    """Return full unless every identity, file and semantic allowlist check passes."""
    receipt = {"schema": SCHEMA, "repository": repository, "event": event_name,
               "baseSha": base_sha, "testedSha": tested_sha, "headSha": tested_sha, "classifierBlob": None,
               "scope": "full", "docsValidated": False, "reason": "unsupported-event", "changes": []}

    def full(reason: str) -> dict:
        receipt["reason"] = reason
        return receipt

    if event_name not in {"push", "pull_request"}:
        return receipt
    if (not REPOSITORY.fullmatch(repository) or not SHA.fullmatch(base_sha)
            or not SHA.fullmatch(tested_sha) or set(base_sha) == {"0"}
            or set(tested_sha) == {"0"}):
        return full("invalid-source-identity")
    if (event.get("repository", {}).get("full_name") != repository
            or repository_from_origin(git(repo, "remote", "get-url", "origin").decode().strip()) != repository
            or git(repo, "rev-parse", "HEAD").decode().strip() != tested_sha):
        return full("repository-or-checkout-mismatch")
    try:
        git(repo, "cat-file", "-e", base_sha + "^{commit}")
        git(repo, "cat-file", "-e", tested_sha + "^{commit}")
    except subprocess.CalledProcessError:
        return full("missing-source-object")
    if event_name == "push":
        if (event.get("ref") != "refs/heads/main" or event.get("before") != base_sha
                or event.get("after") != tested_sha or event.get("deleted") is True):
            return full("push-identity-mismatch")
        try:
            git(repo, "merge-base", "--is-ancestor", base_sha, tested_sha)
        except subprocess.CalledProcessError:
            return full("nonancestor-push-base")
    else:
        pull = event.get("pull_request", {})
        base, head = pull.get("base", {}), pull.get("head", {})
        head_sha = head.get("sha", "")
        receipt["headSha"] = head_sha
        if (base.get("sha") != base_sha or base.get("ref") != "main"
                or base.get("repo", {}).get("full_name") != repository
                or type(head_sha) is not str or not SHA.fullmatch(head_sha)
                or set(head_sha) == {"0"}):
            return full("pull-request-identity-mismatch")
        parents = git(repo, "show", "-s", "--format=%P", tested_sha).decode().strip().split()
        if parents != [base_sha, head_sha]:
            return full("pull-request-merge-parent-mismatch")
    # WHY: a PR cannot replace its own admission code and then certify itself.
    # Match the executing isolated file to the protected base's regular blob.
    entry = git(repo, "ls-tree", base_sha, "--", CLASSIFIER).decode().strip()
    if not entry.startswith("100644 blob "):
        return full("base-classifier-unavailable")
    object_id = entry.split()[2]
    if git(repo, "hash-object", "--stdin", stdin=classifier_path.read_bytes()).decode().strip() != object_id:
        raise RuntimeError("Executing classifier does not match the immutable base blob")
    receipt["classifierBlob"] = object_id
    receipt["classifierSha256"] = hashlib.sha256(classifier_path.read_bytes()).hexdigest()
    raw = git(repo, "diff", "--raw", "-z", "--no-renames", "--no-abbrev", "--no-ext-diff",
              "--no-textconv", base_sha, tested_sha, "--")
    records = raw.split(b"\0")
    if not records[-1] == b"" or len(records) % 2 != 1:
        return full("invalid-change-records")
    changes = []
    for index in range(0, len(records) - 1, 2):
        try:
            header = records[index].decode("ascii").split()
            path = records[index + 1].decode("utf-8")
        except UnicodeError:
            return full("invalid-change-record-encoding")
        if len(header) != 5 or not header[0].startswith(":"):
            return full("invalid-change-records")
        before_mode, after_mode, before_oid, after_oid, status = header
        receipt["changes"].append({"path": path, "status": status,
                                   "beforeMode": before_mode[1:], "afterMode": after_mode})
        changes.append((before_mode, after_mode, before_oid, after_oid, status, path))
    # WHY: a full verdict may be decided by its first code change, but retained
    # evidence must still describe every valid path in the complete Git range.
    for before_mode, after_mode, before_oid, after_oid, status, path in changes:
        if (before_mode != ":100644" or after_mode != "100644" or status != "M"
                or path not in {"README.md", "policy/rust-client.toml"}):
            return full("outside-documentation-allowlist")
        try:
            before, after = text_blob(repo, before_oid), text_blob(repo, after_oid)
            if path == "policy/rust-client.toml" and not phase_gate_only(before, after):
                return full("policy-semantics-changed")
        except (UnicodeError, ValueError, tomllib.TOMLDecodeError):
            return full("invalid-documentation-text-or-toml")
    if not receipt["changes"]:
        return full("empty-change-range")
    try:
        git(repo, "diff", "--check", "--no-ext-diff", "--no-textconv", base_sha, tested_sha, "--")
    except subprocess.CalledProcessError:
        return full("documentation-whitespace-invalid")
    receipt.update(scope="docs", docsValidated=True, reason="validated-documentation-only")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "event-path", "event-name", "repository", "tested-sha", "base-sha",
                 "github-output", "receipt"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    event = json.loads(Path(args.event_path).read_text(encoding="utf-8"))
    if type(event) is not dict:
        raise ValueError("GitHub event must be an object")
    result = classify(Path(args.repo), event, args.event_name, args.repository,
                      args.tested_sha, args.base_sha, Path(__file__))
    target = Path(args.receipt)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with Path(args.github_output).open("a", encoding="utf-8") as output:
        output.write(f"scope={result['scope']}\ndocs_validated={str(result['docsValidated']).lower()}\n")
        output.write(f"tested_sha={result['testedSha']}\nclassifier_blob={result['classifierBlob'] or ''}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
