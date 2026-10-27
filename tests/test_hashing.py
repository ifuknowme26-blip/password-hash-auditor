import hashlib
import unittest

from auditor import hashing


class TestFastHash(unittest.TestCase):
    def test_matches_hashlib(self):
        for algo in hashing.FAST_ALGORITHMS:
            self.assertEqual(
                hashing.fast_hash("hello", algo),
                hashlib.new(algo, b"hello").hexdigest(),
            )

    def test_rejects_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            hashing.fast_hash("hello", "sha3000")

    def test_deterministic_and_case_sensitive(self):
        self.assertEqual(hashing.fast_hash("Secret"), hashing.fast_hash("Secret"))
        self.assertNotEqual(hashing.fast_hash("secret"), hashing.fast_hash("Secret"))


class TestSecureHash(unittest.TestCase):
    def test_roundtrip(self):
        stored = hashing.hash_password("correct horse battery staple", iterations=1000)
        self.assertTrue(hashing.verify_password("correct horse battery staple", stored))
        self.assertFalse(hashing.verify_password("wrong password", stored))

    def test_salt_randomised_each_time(self):
        a = hashing.hash_password("same password", iterations=1000)
        b = hashing.hash_password("same password", iterations=1000)
        self.assertNotEqual(a, b)  # different random salts -> different strings
        self.assertTrue(hashing.verify_password("same password", a))
        self.assertTrue(hashing.verify_password("same password", b))

    def test_format(self):
        stored = hashing.hash_password("x", iterations=1000)
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        self.assertEqual(algo, "pbkdf2_sha256")
        self.assertEqual(int(iterations), 1000)
        self.assertEqual(len(salt_hex), 32)   # 16 bytes
        self.assertEqual(len(hash_hex), 64)   # 32 bytes (sha256 output)

    def test_malformed_stored_hash_raises(self):
        with self.assertRaises(ValueError):
            hashing.verify_password("x", "not-a-real-hash")
        with self.assertRaises(ValueError):
            hashing.verify_password("x", "md5$1000$aa$bb")


if __name__ == "__main__":
    unittest.main()
