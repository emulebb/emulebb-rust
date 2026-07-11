from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "rust_quality_gate.py"
SPEC = importlib.util.spec_from_file_location("rust_quality_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
QUALITY_GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY_GATE)


class TestDiagnosticsGate(unittest.TestCase):
    def build_env_fixture(self) -> dict[str, str]:
        output_root = Path(tempfile.gettempdir()) / "emulebb-out"
        return {
            "EMULEBB_WORKSPACE_ROOT": str(QUALITY_GATE.ROOT.parent.parent),
            "EMULEBB_WORKSPACE_OUTPUT_ROOT": str(output_root),
            "CARGO_TARGET_DIR": str(output_root / "builds" / "rust" / "target"),
        }

    def test_builds_only_the_named_diagnostics_feature(self) -> None:
        label, command = QUALITY_GATE.diagnostics_step()
        self.assertEqual(label, "packet diagnostics binary")
        self.assertIn("emulebb-rust-diagnostics", command)
        self.assertIn("packet-diagnostics", command)
        self.assertNotIn("--all-features", command)
        self.assertNotIn("egress-audit", command)
        self.assertIn("--locked", command)

    def test_quick_gate_includes_diagnostics(self) -> None:
        labels = [label for label, _ in QUALITY_GATE.commands_for_gate("quick")]
        self.assertIn("packet diagnostics binary", labels)

    def test_clippy_uses_the_committed_lockfile(self) -> None:
        _, command = QUALITY_GATE.clippy_step()
        self.assertIn("--locked", command)

    def test_vpn_leak_gate_is_individually_addressable(self) -> None:
        labels = [label for label, _ in QUALITY_GATE.commands_for_gate("test-vpn-leak")]
        self.assertEqual(labels, ["vpn leak-test (observed egress)"])

    def test_build_gate_uses_fresh_build_helper(self) -> None:
        env = self.build_env_fixture()
        label, command = QUALITY_GATE.build_step(env)
        self.assertEqual(label, "fresh debug/release workspace builds")
        self.assertIn("tools/fresh_rust_build.py", command)
        self.assertIn("--stage-bin-dir", command)
        self.assertIn("emulebb-rust", command[-1])
        self.assertNotIn("--force-rebuild", command)

    def test_build_gate_can_force_rebuild_explicitly(self) -> None:
        env = self.build_env_fixture()
        _, command = QUALITY_GATE.build_step(env, force_rebuild=True)
        self.assertIn("--force-rebuild", command)

    def test_release_stage_bin_dir_uses_output_root(self) -> None:
        env = self.build_env_fixture()
        output_root = Path(env["EMULEBB_WORKSPACE_OUTPUT_ROOT"]).resolve()
        self.assertEqual(
            QUALITY_GATE.release_stage_bin_dir(env),
            output_root / "tools" / "emulebb-rust" / "bin",
        )

    def test_missing_path_env_fails_instead_of_deriving(self) -> None:
        with self.assertRaises(SystemExit):
            QUALITY_GATE.require_path_env({}, "EMULEBB_WORKSPACE_OUTPUT_ROOT")


if __name__ == "__main__":
    unittest.main()
