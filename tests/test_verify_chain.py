#!/usr/bin/env python3
"""Tests for verify_chain.py"""
import hashlib, json, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "audit"))
from audit_writer import AuditWriter
sys.path.insert(0, str(Path(__file__).parent.parent / "audit"))
from verify_chain import verify_file, hash_entry

class TestVerifyChain(unittest.TestCase):
    def _make_log(self, n=5):
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        path = Path(tmp.name)
        w = AuditWriter(log_path=path, node_id="a"*64)
        for i in range(n):
            w.write(f"user{i}", "data.access", f"resource/{i}", "SUCCESS")
        return path

    def tearDown(self):
        pass

    def test_valid_chain_passes(self):
        path = self._make_log(10)
        ok, count, errors = verify_file(path)
        self.assertTrue(ok)
        self.assertEqual(count, 10)
        self.assertEqual(errors, [])
        path.unlink()

    def test_empty_file_passes(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        path = Path(tmp.name)
        ok, count, errors = verify_file(path)
        self.assertTrue(ok)
        self.assertEqual(count, 0)
        path.unlink()

    def test_tampered_sha256_self_detected(self):
        path = self._make_log(3)
        lines = path.read_text().strip().splitlines()
        entry = json.loads(lines[1])
        entry["sha256_self"] = "f" * 64
        lines[1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        ok, _, errors = verify_file(path)
        self.assertFalse(ok)
        self.assertTrue(any("sha256_self mismatch" in e for e in errors))
        path.unlink()

    def test_tampered_data_detected(self):
        path = self._make_log(3)
        lines = path.read_text().strip().splitlines()
        entry = json.loads(lines[1])
        entry["actor"] = "HACKER"
        # Keep old sha256_self — mismatch should be detected
        lines[1] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        ok, _, errors = verify_file(path)
        self.assertFalse(ok)
        path.unlink()

    def test_broken_chain_detected(self):
        path = self._make_log(3)
        lines = path.read_text().strip().splitlines()
        entry = json.loads(lines[2])
        entry["sha256_prev"] = "0" * 64
        entry["sha256_self"] = hash_entry(entry)
        lines[2] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n")
        ok, _, errors = verify_file(path)
        self.assertFalse(ok)
        self.assertTrue(any("chain broken" in e for e in errors))
        path.unlink()

    def test_deleted_entry_detected(self):
        path = self._make_log(4)
        lines = path.read_text().strip().splitlines()
        # Remove middle entry — breaks chain
        del lines[1]
        path.write_text("\n".join(lines) + "\n")
        ok, _, errors = verify_file(path)
        self.assertFalse(ok)
        path.unlink()

if __name__ == "__main__":
    unittest.main(verbosity=2)
