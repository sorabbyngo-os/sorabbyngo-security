#!/usr/bin/env python3
"""Tests for audit_writer.py"""
import hashlib, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "audit"))
from audit_writer import AuditWriter

class TestAuditWriter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.path = Path(self.tmp.name)
        self.writer = AuditWriter(log_path=self.path, node_id="a"*64)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def _entries(self):
        return [json.loads(l) for l in self.path.read_text().strip().splitlines() if l.strip()]

    def test_write_creates_entry(self):
        e = self.writer.write("user1", "data.access", "patient/123", "SUCCESS")
        self.assertIn("sha256_self", e)
        self.assertIn("sha256_prev", e)
        self.assertEqual(e["sha256_prev"], "0" * 64)

    def test_chain_links(self):
        e1 = self.writer.write("user1", "auth.login", "system", "SUCCESS")
        e2 = self.writer.write("user1", "data.access", "patient/1", "SUCCESS")
        self.assertEqual(e2["sha256_prev"], e1["sha256_self"])

    def test_sha256_self_correct(self):
        e = self.writer.write("user1", "auth.login", "system", "SUCCESS")
        copy = {k: v for k, v in e.items() if k != "sha256_self"}
        expected = hashlib.sha256(json.dumps(copy, sort_keys=True).encode()).hexdigest()
        self.assertEqual(e["sha256_self"], expected)

    def test_persistence(self):
        self.writer.write("user1", "auth.login", "system", "SUCCESS")
        self.writer.write("user2", "data.access", "patient/2", "SUCCESS")
        w2 = AuditWriter(log_path=self.path, node_id="a"*64)
        e3 = w2.write("user3", "auth.logout", "system", "SUCCESS")
        entries = self._entries()
        self.assertEqual(len(entries), 3)
        self.assertEqual(e3["sha256_prev"], entries[1]["sha256_self"])

    def test_threat_event(self):
        e = self.writer.threat_event("port_scan", "1.2.3.4", 8.5, True)
        self.assertEqual(e["outcome"], "BLOCKED")
        self.assertEqual(e["metadata"]["src_ip"], "1.2.3.4")

    def test_outcome_uppercase(self):
        e = self.writer.write("svc", "system.start", "cyberwall", "success")
        self.assertEqual(e["outcome"], "SUCCESS")

    def test_multiple_writers_chain(self):
        self.writer.write("a", "auth.login", "system", "SUCCESS")
        w2 = AuditWriter(log_path=self.path, node_id="b"*64)
        w2.write("b", "data.access", "patient/1", "SUCCESS")
        entries = self._entries()
        self.assertEqual(entries[1]["sha256_prev"], entries[0]["sha256_self"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
