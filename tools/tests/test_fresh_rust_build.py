from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "fresh_rust_build.py"
SPEC = importlib.util.spec_from_file_location("fresh_rust_build", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
FRESH_BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FRESH_BUILD)


def test_stage_release_outputs_copies_cargo_pdb_under_staged_exe_name(tmp_path: Path) -> None:
    release_dir = tmp_path / "target" / "release"
    stage_dir = tmp_path / "stage"
    release_dir.mkdir(parents=True)
    exe = release_dir / "emulebb-rust-diagnostics.exe"
    pdb = release_dir / "emulebb_rust_diagnostics.pdb"
    exe.write_bytes(b"exe")
    pdb.write_bytes(b"pdb")

    FRESH_BUILD.stage_release_outputs({"emulebb-rust-diagnostics": exe}, stage_dir)

    assert (stage_dir / "emulebb-rust-diagnostics.exe").read_bytes() == b"exe"
    assert (stage_dir / "emulebb-rust-diagnostics.pdb").read_bytes() == b"pdb"
    assert (stage_dir / "emulebb_rust_diagnostics.pdb").read_bytes() == b"pdb"


def test_remove_profile_outputs_removes_stale_staged_and_cargo_pdb_names(tmp_path: Path) -> None:
    for name in (
        "emulebb-rust-diagnostics.exe",
        "emulebb-rust-diagnostics.pdb",
        "emulebb_rust_diagnostics.pdb",
    ):
        (tmp_path / name).write_bytes(b"old")

    FRESH_BUILD.remove_profile_outputs(tmp_path, ("emulebb-rust-diagnostics",))

    assert not (tmp_path / "emulebb-rust-diagnostics.exe").exists()
    assert not (tmp_path / "emulebb-rust-diagnostics.pdb").exists()
    assert not (tmp_path / "emulebb_rust_diagnostics.pdb").exists()
