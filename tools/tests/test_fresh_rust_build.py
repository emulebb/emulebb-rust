from __future__ import annotations

import importlib.util
import argparse
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock


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


def test_remove_stale_release_stage_artifacts_prunes_dead_slint_ui(tmp_path: Path) -> None:
    for name in (
        "emulebb-rust-ui.exe",
        "emulebb-rust-ui.pdb",
        "emulebb_rust_ui.pdb",
        "emulebb-rust.exe",
    ):
        (tmp_path / name).write_bytes(b"old")

    FRESH_BUILD.remove_stale_release_stage_artifacts(tmp_path)

    assert not (tmp_path / "emulebb-rust-ui.exe").exists()
    assert not (tmp_path / "emulebb-rust-ui.pdb").exists()
    assert not (tmp_path / "emulebb_rust_ui.pdb").exists()
    assert (tmp_path / "emulebb-rust.exe").exists()


class TestRegisteredRuntimeStage(unittest.TestCase):
    def test_owner_bootstrap_selects_registered_builder_without_repairing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, output = Path(directory) / "workspace", Path(directory) / "output"
            source = workspace / "workspaces/agents/sample/emulebb-rust"
            owner = workspace / "workspaces/agents/sample/emulebb-build"
            source.mkdir(parents=True)
            output.mkdir()
            environment = {"EMULEBB_WORKSPACE_ROOT": str(workspace), "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output)}
            child_env = {**environment, "CARGO_TARGET_DIR": str(output / "builds/rust/target")}
            select = mock.Mock(return_value=(owner, "sample"))
            bootstrap = {"validation_environment": lambda: child_env, "orchestration_owner": select}
            warning = "Warning: runtime ready; owned previous backup cleanup failed\n"
            completed = mock.Mock(returncode=0, stdout='{"discarded":true}', stderr=warning)
            description = {"pendingRoot": str(output / "owned-pending")}
            with (mock.patch.object(FRESH_BUILD, "ROOT", source),
                  mock.patch.object(FRESH_BUILD.runpy, "run_path", return_value=bootstrap),
                  mock.patch.object(FRESH_BUILD.subprocess, "run", return_value=completed) as run,
                  mock.patch("sys.stderr", new_callable=io.StringIO) as stderr):
                self.assertEqual(FRESH_BUILD.runtime_stage_request("discard", environment, description), {"discarded": True})
                self.assertEqual(stderr.getvalue(), warning)
            select.assert_called_once_with(workspace, output, source, child_env)
            command = run.call_args.args[0]
            self.assertEqual(command[-4:], ["--rust-repo", str(source), "--workstream", "sample"])
            self.assertEqual(run.call_args.kwargs["cwd"], owner)
            self.assertEqual(json.loads(run.call_args.kwargs["input"]), description)
            self.assertEqual(environment, {"EMULEBB_WORKSPACE_ROOT": str(workspace),
                                           "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output)})

    def test_registered_build_uses_pending_bundle_and_always_discards_on_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                workspace, output = Path(directory) / "workspace", Path(directory) / "output"
                source = workspace / "workspaces/agents/sample/emulebb-rust"
                source.mkdir(parents=True)
                output.mkdir()
                operator = output / "tools/emulebb-rust/bin"
                operator.mkdir(parents=True)
                (operator / "emulebb-rust.exe").write_bytes(b"main")
                description = {"stageRoot": str(output / "tools/workstreams/sample/emulebb-rust/native"),
                               "pendingRoot": str(output / "tmp/pending")}
                actions = []

                def request(action, env, selected=None):
                    actions.append(action)
                    if action == "prepare":
                        return description
                    self.assertEqual(selected, description)
                    return {"binDir": str(Path(description["stageRoot"]) / "bin")}

                def build(env, target, stage_bin, args):
                    self.assertEqual(stage_bin, Path(description["pendingRoot"]) / "bin")
                    self.assertEqual(target, output / "builds/rust/target")
                    if fail:
                        raise RuntimeError("synthetic compilation failure")

                environment = {"EMULEBB_WORKSPACE_ROOT": str(workspace),
                               "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output),
                               "CARGO_TARGET_DIR": str(output / "builds/rust/target")}
                with (mock.patch.object(FRESH_BUILD, "ROOT", source), mock.patch.dict(os.environ, environment),
                      mock.patch.object(FRESH_BUILD, "runtime_stage_request", side_effect=request),
                      mock.patch.object(FRESH_BUILD, "build_workspace", side_effect=build)):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, "synthetic compilation failure"):
                            FRESH_BUILD.main(["--registered-stage"])
                    else:
                        self.assertEqual(FRESH_BUILD.main(["--registered-stage"]), 0)
                self.assertEqual(actions, ["prepare", "discard"] if fail else ["prepare", "publish", "discard"])
                self.assertEqual((operator / "emulebb-rust.exe").read_bytes(), b"main")

    def test_verification_calls_owner_without_building_or_changing_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace, output = Path(directory) / "workspace", Path(directory) / "output"
            source = workspace / "workspaces/agents/sample/emulebb-rust"
            source.mkdir(parents=True)
            output.mkdir()
            identity = {"source": {"revision": "a" * 40}, "executable": str(output / "owned/emulebb-rust.exe")}
            environment = {"EMULEBB_WORKSPACE_ROOT": str(workspace), "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output)}
            with (mock.patch.object(FRESH_BUILD, "ROOT", source), mock.patch.dict(os.environ, environment),
                  mock.patch.object(FRESH_BUILD, "runtime_stage_request", return_value=identity) as request,
                  mock.patch.object(FRESH_BUILD, "build_workspace") as build,
                  mock.patch("sys.stdout", new_callable=io.StringIO) as stream):
                self.assertEqual(FRESH_BUILD.main(["--verify-stage"]), 0)
                self.assertEqual(json.loads(stream.getvalue()), identity)
                self.assertEqual(os.environ["EMULEBB_WORKSPACE_OUTPUT_ROOT"], str(output))
            self.assertEqual(request.call_args.args[0], "verify")
            build.assert_not_called()

    def test_reused_webui_bundle_keeps_output_root_and_fresh_build_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            args = argparse.Namespace(force_rebuild=False, webui_dist=output / "built-ui")
            webui = mock.Mock()
            with (mock.patch.dict("sys.modules", {"build_webui": webui}),
                  mock.patch.object(FRESH_BUILD, "run") as run,
                  mock.patch.object(FRESH_BUILD, "verify_profile_outputs", return_value={}),
                  mock.patch.object(FRESH_BUILD, "stage_release_outputs"),
                  mock.patch.object(FRESH_BUILD, "remove_profile_outputs"),
                  mock.patch.object(FRESH_BUILD, "remove_stale_release_stage_artifacts")):
                FRESH_BUILD.build_workspace({"EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output)},
                                            output / "target", output / "pending/bin", args)
            self.assertEqual(run.call_count, 3)
            webui.stage_dist.assert_called_once_with(args.webui_dist, output / "pending/bin/webui", output)
