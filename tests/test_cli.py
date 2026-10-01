"""CLI exit codes for a clean tree and a quality-gate failure."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


AWS_LINE = 'const key = "AKIAIOSFODNN7EXAMPLE";\n'


class CliTest(unittest.TestCase):
    def test_clean_directory_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "app.js"
            sample.write_text("const value = 1;\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "secscan", tmp, "--format", "json", "--fail-on", "critical"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["findings"], [])
            self.assertEqual(payload["metrics"]["securityImpactScore"], 0)

    def test_fail_on_and_max_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.js").write_text(AWS_LINE, encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, "-m", "secscan", tmp, "--format", "json", "--fail-on", "high"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 1)
            self.assertIn("quality gate", failed.stderr)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", failed.stdout)

            risk = subprocess.run(
                [sys.executable, "-m", "secscan", tmp, "--max-risk", "10", "--format", "table"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(risk.returncode, 1)
            self.assertIn("Impact:", risk.stdout)

    def test_missing_rules_file(self):
        completed = subprocess.run(
            [sys.executable, "-m", "secscan", ".", "--rules", "missing-rules.json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
