import unittest

from auditor import strength


class TestStrengthAnalysis(unittest.TestCase):
    def test_common_password_flagged_very_weak(self):
        report = strength.analyze("123456")
        self.assertTrue(report.is_common_password)
        self.assertEqual(report.verdict, "Very weak")

    def test_short_password_is_weak(self):
        self.assertEqual(strength.analyze("ab1!").verdict, "Very weak")

    def test_sequential_and_repeated_detected(self):
        self.assertTrue(strength.analyze("abcd1234").has_sequential_run)
        self.assertTrue(strength.analyze("aaaaaaaa").has_repeated_chars)

    def test_long_random_password_is_strong(self):
        report = strength.analyze("xQ7!mZ2#vL9$pR4&wK1@")
        self.assertIn(report.verdict, ("Strong", "Very strong"))
        self.assertFalse(report.is_common_password)

    def test_entropy_increases_with_charset(self):
        lower_only = strength.analyze("abcdefgh")
        mixed = strength.analyze("aB3$efgh")
        self.assertGreater(mixed.entropy_bits, lower_only.entropy_bits)

    def test_empty_password(self):
        report = strength.analyze("")
        self.assertEqual(report.password_length, 0)
        self.assertEqual(report.entropy_bits, 0.0)

    def test_crack_time_monotonic_in_entropy(self):
        low = strength.estimate_crack_time_seconds(20)
        high = strength.estimate_crack_time_seconds(60)
        self.assertLess(low, high)

    def test_human_time_formats(self):
        self.assertIn("second", strength.human_time(30))
        self.assertIn("year", strength.human_time(60 * 60 * 24 * 400))


if __name__ == "__main__":
    unittest.main()
