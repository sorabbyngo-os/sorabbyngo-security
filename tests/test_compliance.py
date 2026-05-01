#!/usr/bin/env python3
"""Tests for check_compliance.py"""
import json, sys, tempfile, unittest
from pathlib import Path
import yaml
sys.path.insert(0, str(Path(__file__).parent.parent / "compliance" / "kenya-dpa"))
from check_compliance import (
    ComplianceReport, CheckResult,
    check_dpo_appointed, check_retention_policy,
    check_breach_notification, check_encryption_at_rest,
)

class TestComplianceReport(unittest.TestCase):
    def test_score_calculation(self):
        r = ComplianceReport()
        r.add(CheckResult("A", True,  "ok",   "S1"))
        r.add(CheckResult("B", False, "fail", "S2"))
        self.assertEqual(r.score, 1)
        self.assertEqual(r.total, 2)
        self.assertAlmostEqual(r.percentage, 50.0)

    def test_perfect_score(self):
        r = ComplianceReport()
        for i in range(5):
            r.add(CheckResult(f"Check{i}", True, "ok", "S1"))
        self.assertEqual(r.percentage, 100.0)

    def test_zero_total(self):
        r = ComplianceReport()
        self.assertEqual(r.percentage, 0.0)


class TestDPOCheck(unittest.TestCase):
    def _write_dpo(self, tmpdir, appointed=None):
        data = {"dpo": {"name": "Test DPO", "email": "dpo@test.com", "appointed_date": appointed}}
        f = Path(tmpdir) / "dpo_contact.yaml"
        f.write_text(yaml.dump(data))
        return f

    def test_dpo_not_appointed(self):
        import check_compliance as cc
        with tempfile.TemporaryDirectory() as d:
            self._write_dpo(d, appointed=None)
            orig = cc.SCRIPT_DIR
            cc.SCRIPT_DIR = Path(d)
            r = ComplianceReport()
            check_dpo_appointed(r)
            cc.SCRIPT_DIR = orig
        self.assertFalse(r.results[0].passed)

    def test_dpo_appointed(self):
        import check_compliance as cc
        with tempfile.TemporaryDirectory() as d:
            self._write_dpo(d, appointed="2026-04-30")
            orig = cc.SCRIPT_DIR
            cc.SCRIPT_DIR = Path(d)
            r = ComplianceReport()
            check_dpo_appointed(r)
            cc.SCRIPT_DIR = orig
        self.assertTrue(r.results[0].passed)


class TestRetentionPolicy(unittest.TestCase):
    def _write_policy(self, tmpdir, years=7):
        data = {
            "retention_periods": {
                "patient_records": {
                    "retention_years": years,
                    "storage": "PostgreSQL — AES-256 encrypted at rest"
                }
            },
            "breach_notification": {"odpc_deadline_hours": 72}
        }
        f = Path(tmpdir) / "data_retention_policy.yaml"
        f.write_text(yaml.dump(data))
        return f

    def test_valid_retention(self):
        import check_compliance as cc
        with tempfile.TemporaryDirectory() as d:
            self._write_policy(d, years=7)
            orig = cc.SCRIPT_DIR
            cc.SCRIPT_DIR = Path(d)
            r = ComplianceReport()
            check_retention_policy(r)
            cc.SCRIPT_DIR = orig
        passed = [x.passed for x in r.results]
        self.assertTrue(all(passed))

    def test_excessive_retention_fails(self):
        import check_compliance as cc
        with tempfile.TemporaryDirectory() as d:
            self._write_policy(d, years=15)
            orig = cc.SCRIPT_DIR
            cc.SCRIPT_DIR = Path(d)
            r = ComplianceReport()
            check_retention_policy(r)
            cc.SCRIPT_DIR = orig
        # Second check is the years <= 10 check
        self.assertFalse(r.results[1].passed)

if __name__ == "__main__":
    unittest.main(verbosity=2)
