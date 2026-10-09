"""
Comprehensive Test Suite for Paytm DRP Platform
Verifies 0% False Positive rate on official brand assets and accurate threat scoring.
"""

import unittest
from core.exclusion_engine import StrictExclusionEngine
from core.homoglyph_engine import LookAlikeHomoglyphEngine
from core.social_evaluator import SocialCandidate, SocialMediaEvaluator
from core.app_store_evaluator import MobileAppCandidate, AppStoreEvaluator
from core.threat_orchestrator import ThreatOrchestrator
from data.test_datasets import TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES


class TestDRPEngines(unittest.TestCase):

    def setUp(self):
        self.orchestrator = ThreatOrchestrator()
        self.exclusion_engine = StrictExclusionEngine()
        self.homoglyph_engine = LookAlikeHomoglyphEngine()
        self.social_evaluator = SocialMediaEvaluator()
        self.app_evaluator = AppStoreEvaluator()

    def test_strict_exclusion_social_assets(self):
        """Official handles must receive 0% risk and be classified as OFFICIAL_SAFE."""
        official_handles = ["@Paytm", "@PaytmCare", "@PaytmMoney", "paytm", "@paytmbank"]
        for handle in official_handles:
            candidate = SocialCandidate(
                handle=handle,
                display_name="Paytm",
                bio="Official handle",
                is_verified=True,
            )
            res = self.social_evaluator.evaluate(candidate)
            self.assertTrue(res.is_whitelisted, f"Failed whitelist for {handle}")
            self.assertEqual(res.risk_score, 0.0, f"Risk score not 0.0 for {handle}")
            self.assertEqual(res.risk_tier, "OFFICIAL_SAFE")

    def test_strict_exclusion_mobile_apps(self):
        """Official mobile apps must receive 0% risk and OFFICIAL_SAFE."""
        official_apps = [
            ("net.one97.paytm", "Paytm - One97 Communications Ltd."),
            ("com.paytm.business", "Paytm - One97 Communications Ltd."),
            ("com.paytmmoney", "Paytm Money Limited"),
        ]
        for pkg, pub in official_apps:
            candidate = MobileAppCandidate(
                app_title="Official Paytm App",
                package_id=pkg,
                publisher_name=pub,
            )
            res = self.app_evaluator.evaluate(candidate)
            self.assertTrue(res.is_whitelisted, f"Failed app whitelist for {pkg}")
            self.assertEqual(res.risk_score, 0.0)
            self.assertEqual(res.risk_tier, "OFFICIAL_SAFE")

    def test_homoglyph_and_leetspeak_detection(self):
        """Engine must de-obfuscate Cyrillic homoglyphs and leetspeak substitution."""
        # Leetspeak '4' -> 'a'
        res_leet = self.homoglyph_engine.analyze("@P4ytm_Helpline")
        self.assertTrue(res_leet.has_leetspeak)
        self.assertIn("paytm", res_leet.de_leeted_text)
        self.assertIn("helpline", res_leet.padding_tokens_found)

        # Unicode Cyrillic 'Р' (U+0420)
        cyrillic_handle = "@\u0420aytm_Care"
        res_homo = self.homoglyph_engine.analyze(cyrillic_handle)
        self.assertTrue(res_homo.has_homoglyphs)
        self.assertIn("paytm", res_homo.de_leeted_text)

    def test_benign_differentiation(self):
        """Benign accounts like 'Payton Miller' must not be flagged as brand impersonators."""
        cand = SocialCandidate(
            handle="@PaytonMiller_Art",
            display_name="Payton Miller",
            bio="Digital Illustrator & Concept Artist based in Seattle.",
            is_verified=False,
            followers_count=8500,
        )
        res = self.social_evaluator.evaluate(cand)
        self.assertFalse(res.is_whitelisted)
        self.assertLess(res.risk_score, 30.0, f"Benign score {res.risk_score} should be < 30.0")
        self.assertEqual(res.risk_tier, "SAFE")

    def test_critical_social_impersonator(self):
        """Critical impersonators must trigger >= 85% risk score."""
        cand = SocialCandidate(
            handle="@Paytm_Care_Refund",
            display_name="Paytm 24x7 Customer Care Helpdesk",
            bio="Official 24x7 Helpdesk. DM for stuck UPI refund, KYC update issues or call 1800-419-0157",
            is_verified=False,
            followers_count=34,
            external_urls=["https://wa.me/919876543210"],
        )
        res = self.social_evaluator.evaluate(cand)
        self.assertGreaterEqual(res.risk_score, 85.0)
        self.assertEqual(res.risk_tier, "CRITICAL")
        self.assertGreater(len(res.matched_scam_triggers), 0)

    def test_malicious_app_namespace_squatting(self):
        """Apps attempting namespace squatting and publisher mismatch must be flagged Critical."""
        cand = MobileAppCandidate(
            app_title="Paytm Fast Loan & Quick Cash",
            package_id="net.one97.paytm.quickloan",
            publisher_name="Shenzhen Fast Credit Tech Ltd.",
            permissions=["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW"],
            downloads_count=5000,
        )
        res = self.app_evaluator.evaluate(cand)
        self.assertGreaterEqual(res.risk_score, 85.0)
        self.assertEqual(res.risk_tier, "CRITICAL")
        self.assertTrue(res.is_namespace_squatted)
        self.assertTrue(res.is_publisher_mismatch)

    def test_batch_dataset_zero_false_positive_rate(self):
        """Complete realistic dataset batch run must exhibit strictly 0% FP on official assets."""
        batch = self.orchestrator.batch_process(TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES)
        summary = batch["summary"]
        self.assertEqual(summary["false_positive_count"], 0)
        self.assertEqual(summary["false_positive_rate"], "0.0%")
        self.assertGreaterEqual(summary["critical_threats"], 4)
        self.assertGreaterEqual(summary["takedowns_ready"], 4)


if __name__ == "__main__":
    unittest.main()
