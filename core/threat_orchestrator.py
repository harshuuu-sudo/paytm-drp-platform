"""
DRP Threat Orchestration Engine
Unifies Social Media & Mobile App Store threat intelligence, telemetry aggregation,
and end-to-end detection pipelines.
"""

from typing import Any, Dict, List, Optional
from core.exclusion_engine import StrictExclusionEngine
from core.homoglyph_engine import LookAlikeHomoglyphEngine
from core.social_evaluator import (
    SocialCandidate,
    SocialMediaEvaluator,
    SocialThreatEvaluationResult,
)
from core.app_store_evaluator import (
    MobileAppCandidate,
    AppStoreEvaluator,
    AppStoreThreatEvaluationResult,
)
from core.takedown_generator import TakedownNoticeGenerator


class ThreatOrchestrator:
    """
    Central DRP Orchestrator powering SOC real-time dashboards and batch pipelines.
    """

    def __init__(self):
        self.exclusion_engine = StrictExclusionEngine()
        self.homoglyph_engine = LookAlikeHomoglyphEngine()
        self.social_evaluator = SocialMediaEvaluator(
            exclusion_engine=self.exclusion_engine,
            homoglyph_engine=self.homoglyph_engine,
        )
        self.app_evaluator = AppStoreEvaluator(
            exclusion_engine=self.exclusion_engine,
            homoglyph_engine=self.homoglyph_engine,
        )
        self.takedown_gen = TakedownNoticeGenerator()

    def scan_social_candidate(self, candidate_dict: Dict[str, Any]) -> Dict[str, Any]:
        cand = SocialCandidate(
            handle=candidate_dict.get("handle", ""),
            display_name=candidate_dict.get("display_name", ""),
            bio=candidate_dict.get("bio", ""),
            platform=candidate_dict.get("platform", "Twitter/X"),
            is_verified=candidate_dict.get("is_verified", False),
            followers_count=candidate_dict.get("followers_count", 0),
            external_urls=candidate_dict.get("external_urls", []),
        )
        res = self.social_evaluator.evaluate(cand)
        res_dict = res.to_dict()
        if res.risk_tier in ["CRITICAL", "HIGH"]:
            res_dict["takedown_notice"] = self.takedown_gen.generate_social_takedown(res_dict)
        return res_dict

    def scan_app_candidate(self, candidate_dict: Dict[str, Any]) -> Dict[str, Any]:
        cand = MobileAppCandidate(
            app_title=candidate_dict.get("app_title", ""),
            package_id=candidate_dict.get("package_id", ""),
            publisher_name=candidate_dict.get("publisher_name", ""),
            app_store=candidate_dict.get("app_store", "Google Play Store"),
            permissions=candidate_dict.get("permissions", []),
            downloads_count=candidate_dict.get("downloads_count", 0),
            rating=candidate_dict.get("rating", 0.0),
            app_url=candidate_dict.get("app_url", ""),
            description=candidate_dict.get("description", ""),
        )
        res = self.app_evaluator.evaluate(cand)
        res_dict = res.to_dict()
        if res.risk_tier in ["CRITICAL", "HIGH"]:
            res_dict["takedown_notice"] = self.takedown_gen.generate_app_store_takedown(res_dict)
        return res_dict

    def batch_process(
        self,
        social_candidates: List[Dict[str, Any]],
        app_candidates: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        social_results = [self.scan_social_candidate(c) for c in social_candidates]
        app_results = [self.scan_app_candidate(c) for c in app_candidates]

        all_results = social_results + app_results
        total = len(all_results)

        critical_count = sum(1 for r in all_results if r["risk_tier"] == "CRITICAL")
        high_count = sum(1 for r in all_results if r["risk_tier"] == "HIGH")
        medium_count = sum(1 for r in all_results if r["risk_tier"] == "MEDIUM")
        safe_count = sum(1 for r in all_results if r["risk_tier"] in ["SAFE", "OFFICIAL_SAFE"])
        official_safe_count = sum(1 for r in all_results if r["risk_tier"] == "OFFICIAL_SAFE")

        # False positive check on canonical official assets:
        # A false positive is defined as any official asset receiving risk_score > 0
        official_tested = sum(1 for r in all_results if r.get("is_whitelisted", False))
        fp_count = sum(
            1 for r in all_results if r.get("is_whitelisted", False) and r["risk_score"] > 0
        )
        fp_rate = (fp_count / official_tested * 100.0) if official_tested > 0 else 0.0

        return {
            "summary": {
                "total_monitored": total,
                "critical_threats": critical_count,
                "high_risk": high_count,
                "medium_risk": medium_count,
                "safe_count": safe_count,
                "official_safe_count": official_safe_count,
                "false_positive_rate": f"{fp_rate:.1f}%",
                "false_positive_count": fp_count,
                "takedowns_ready": critical_count + high_count,
            },
            "social_results": social_results,
            "app_results": app_results,
        }
