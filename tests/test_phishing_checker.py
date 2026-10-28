
import unittest

from phishing_checker import inspect_url, calculate_risk, risk_label


class PhishingCheckerTests(unittest.TestCase):

    def test_example_url(self):
        warnings = inspect_url("https://www.example.com/login")
        self.assertEqual(
            warnings,
            ["No listed warning signs found. This does NOT prove safety."],
        )

    def test_ip_and_http(self):
        warnings = inspect_url("http://192.0.2.10/account")
        self.assertIn(
            "Uses an IP address instead of a familiar domain.",
            warnings,
        )
        self.assertIn(
            "Uses HTTP. HTTPS alone does not prove trust.",
            warnings,
        )

    def test_at_symbol_and_http(self):
        warnings = inspect_url(
            "http://example.com@sample.invalid/login"
        )
        self.assertIn(
            "Contains an @ symbol; inspect carefully.",
            warnings,
        )
        self.assertIn(
            "Uses HTTP. HTTPS alone does not prove trust.",
            warnings,
        )

    def test_many_hostname_segments(self):
        warnings = inspect_url(
            "https://a.b.c.d.e.example.invalid/path"
        )
        self.assertIn(
            "Contains many hostname segments/subdomains.",
            warnings,
        )

    def test_punycode(self):
        warnings = inspect_url("https://xn--example.invalid/")
        self.assertIn(
            "Contains a punycode-style hostname.",
            warnings,
        )

    def test_risk_score_is_bounded(self):
        warnings = inspect_url("http://192.0.2.10/account")
        score = calculate_risk(warnings)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_risk_labels(self):
        self.assertEqual(risk_label(0), "Low")
        self.assertEqual(risk_label(20), "Medium")
        self.assertEqual(risk_label(50), "High")


if __name__ == "__main__":
    unittest.main()
