import unittest

from phishing_detector import analyze_url


class PhishingDetectorTests(unittest.TestCase):
    def test_safe_known_url_is_low_risk(self):
        analysis = analyze_url("https://www.google.com/account/about/")

        self.assertEqual(analysis.verdict, "Low risk")
        self.assertLess(analysis.score, 30)

    def test_brand_impersonation_is_high_risk(self):
        analysis = analyze_url("http://paypal-login-security-update.example.xyz/verify/account")

        self.assertEqual(analysis.verdict, "High risk")
        self.assertGreaterEqual(analysis.score, 60)
        self.assertTrue(any("brand impersonation" in finding.title.lower() for finding in analysis.findings))

    def test_userinfo_trick_is_detected(self):
        analysis = analyze_url("https://google.com@evil-login.example.top/secure/confirm")

        self.assertEqual(analysis.host, "evil-login.example.top")
        self.assertTrue(any("userinfo" in finding.title.lower() for finding in analysis.findings))

    def test_ip_address_host_is_detected(self):
        analysis = analyze_url("http://192.168.0.50/login/update-password")

        self.assertTrue(any("ip address" in finding.title.lower() for finding in analysis.findings))

    def test_json_ready_fields_are_present(self):
        analysis = analyze_url("https://paypa1.com/signin")

        self.assertEqual(analysis.registered_domain, "paypa1.com")
        self.assertTrue(analysis.findings)


if __name__ == "__main__":
    unittest.main()
