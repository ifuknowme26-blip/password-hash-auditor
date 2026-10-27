import tempfile
import unittest
from pathlib import Path

from auditor import dictionary_audit, hashing


class TestDictionaryAudit(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.wordlist = Path(self.tmpdir.name) / "words.txt"
        self.wordlist.write_text("password\n123456\nhunter2\ncorrect-horse\n")

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_fast_hash_found(self):
        target = hashing.fast_hash("hunter2", "sha256")
        self.assertEqual(
            dictionary_audit.audit_fast_hash(target, "sha256", str(self.wordlist)), "hunter2"
        )

    def test_fast_hash_not_found(self):
        target = hashing.fast_hash("not-in-list-xyz", "sha256")
        self.assertIsNone(dictionary_audit.audit_fast_hash(target, "sha256", str(self.wordlist)))

    def test_salted_hash_found(self):
        stored = hashing.hash_password("correct-horse", iterations=1000)
        self.assertEqual(dictionary_audit.audit_salted_hash(stored, str(self.wordlist)), "correct-horse")

    def test_salted_hash_not_found(self):
        stored = hashing.hash_password("not-in-the-list-at-all", iterations=1000)
        self.assertIsNone(dictionary_audit.audit_salted_hash(stored, str(self.wordlist)))

    def test_audit_file_multiple_hashes(self):
        hash_list_path = Path(self.tmpdir.name) / "hashes.txt"
        found = hashing.fast_hash("password", "sha256")
        missing = hashing.fast_hash("xyz-never-in-list", "sha256")
        hash_list_path.write_text(f"{found}\n{missing}\n")
        results = dictionary_audit.audit_file(str(hash_list_path), "sha256", str(self.wordlist))
        self.assertEqual(results[found], "password")
        self.assertIsNone(results[missing])

    def test_rejects_bad_algorithm(self):
        with self.assertRaises(ValueError):
            dictionary_audit.audit_fast_hash("deadbeef", "sha3000", str(self.wordlist))


if __name__ == "__main__":
    unittest.main()
