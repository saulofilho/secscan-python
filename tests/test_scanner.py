"""Scanner behavior for secrets, ignores, score, and redacted reports."""

import json
import tempfile
import unittest
from pathlib import Path

from secscan import calculate_entropy, mask_secret, scan_path, scan_text
from secscan.rules import Rule
from secscan.report import to_json, to_sarif
from secscan.scanner import load_rules


AWS_LINE = 'const key = "AKIAIOSFODNN7EXAMPLE";\n'


class ScannerTest(unittest.TestCase):
    def test_entropy_and_mask(self):
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertGreater(calculate_entropy("AKIAIOSFODNN7EXAMPLE"), 3.5)
        masked = mask_secret("AKIAIOSFODNN7EXAMPLE")
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MPLE"))
        self.assertNotIn("IOSFODNN7EXA", masked)

    def test_aws_key_sets_elevated_impact(self):
        report = scan_text(AWS_LINE, path="src/app.js")
        self.assertEqual([item.rule_id for item in report.findings], ["sec-aws-akid"])
        self.assertEqual(report.metrics.critical_count, 1)
        self.assertEqual(report.metrics.security_impact_score, 37)
        self.assertEqual(report.metrics.impact_level, "ELEVATED")
        self.assertEqual(report.findings[0].file_criticality, "MEDIUM")

    def test_database_uri_and_admin_route(self):
        source = (
            'const db = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/main";\n'
            'app.get("/api/v1/admin/users", handler);\n'
        )
        report = scan_text(source, path="src/routes/users.js")
        rule_ids = {item.rule_id for item in report.findings}
        self.assertIn("sec-db-uri", rule_ids)
        self.assertIn("sec-sensitive-api-path", rule_ids)
        self.assertEqual(report.api_endpoints[0].method, "GET")
        self.assertTrue(report.api_endpoints[0].is_internal_or_admin)

    def test_low_entropy_and_invalid_rule_are_skipped(self):
        rules = [
            Rule(
                id="sec-low",
                name="Low",
                pattern="a+",
                severity="HIGH",
                category="CUSTOM",
                description="low",
                min_entropy=4.0,
            ),
            Rule(
                id="sec-bad",
                name="Bad",
                pattern="(",
                severity="HIGH",
                category="CUSTOM",
                description="bad",
            ),
        ]
        report = scan_text("const value = 'aaaaaaa';\n", path="src/app.js", rules=rules)
        self.assertEqual(report.findings, [])

    def test_reports_mask_literals(self):
        report = scan_text(AWS_LINE, path="src/app.js")
        payload = to_json(report)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", payload)
        self.assertIn("sec-aws-akid", payload)
        sarif = json.loads(to_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        message = sarif["runs"][0]["results"][0]["message"]["text"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", message)

    def test_ignore_vendor_and_custom_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.js").write_text(AWS_LINE, encoding="utf-8")
            vendor = root / "node_modules" / "pkg"
            vendor.mkdir(parents=True)
            (vendor / "index.js").write_text(AWS_LINE, encoding="utf-8")
            tests = root / "tests"
            tests.mkdir()
            (tests / "leak.js").write_text(AWS_LINE, encoding="utf-8")

            report = scan_path(root, ignore=["tests/*"])
            files = {item.file for item in report.findings}
            self.assertEqual(files, {"src/app.js"})

    def test_custom_rules_file_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.json"
            rules.write_text(
                json.dumps(
                    [
                        {
                            "id": "sec-demo",
                            "name": "Demo",
                            "pattern": "SECSCAN_DEMO_[A-Z0-9]{8}",
                            "severity": "LOW",
                            "category": "CUSTOM",
                            "description": "demo",
                            "minEntropy": 1,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            loaded = load_rules(rules)
            self.assertTrue(any(rule.id == "sec-aws-akid" for rule in loaded))
            self.assertTrue(any(rule.id == "sec-demo" for rule in loaded))


if __name__ == "__main__":
    unittest.main()
