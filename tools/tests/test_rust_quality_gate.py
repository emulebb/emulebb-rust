from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "rust_quality_gate.py"
SPEC = importlib.util.spec_from_file_location("rust_quality_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
QUALITY_GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALITY_GATE)


class TestDiagnosticsGate(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
