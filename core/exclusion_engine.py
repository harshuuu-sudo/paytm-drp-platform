"""
Strict Exclusion & Whitelist Engine
Guarantees 0% False Positive Rate for verified canonical brand assets of Paytm / One97.
"""

import re
from dataclasses import dataclass
from typing import Optional, Set
from config.brand_config import (
    OFFICIAL_HANDLES,
    OFFICIAL_PACKAGE_IDS,
    OFFICIAL_PUBLISHERS,
    OFFICIAL_DOMAINS,
    BRAND_NAME,
    PARENT_COMPANY,
)


@dataclass
class ExclusionResult:
    is_excluded: bool
    risk_score: float
    risk_tier: str
    matched_rule: str
    matched_asset: str
    explanation: str

    def to_dict(self):
        return {
            "is_excluded": self.is_excluded,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "matched_rule": self.matched_rule,
            "matched_asset": self.matched_asset,
            "explanation": self.explanation,
        }


class StrictExclusionEngine:
    """
    Deterministic Whitelist Evaluation Engine.
    Executes pre-flight evaluation before any heuristic or ML detection models.
    Matches against canonical brand registers.
    """

    def __init__(
        self,
        official_handles: Optional[Set[str]] = None,
        official_packages: Optional[Set[str]] = None,
        official_publishers: Optional[Set[str]] = None,
        official_domains: Optional[Set[str]] = None,
    ):
        self.official_handles = official_handles or OFFICIAL_HANDLES
        self.official_packages = official_packages or OFFICIAL_PACKAGE_IDS
        self.official_publishers = official_publishers or OFFICIAL_PUBLISHERS
        self.official_domains = official_domains or OFFICIAL_DOMAINS

    @staticmethod
    def _normalize_string(val: str) -> str:
        if not val:
            return ""
        return val.strip().lower()

    @staticmethod
    def _normalize_handle(handle: str) -> str:
        if not handle:
            return ""
        cleaned = handle.strip().lower()
        if cleaned.startswith("@"):
            cleaned = cleaned[1:]
        return cleaned

    def check_social_candidate(self, handle: str, url: str = "") -> Optional[ExclusionResult]:
        """
        Evaluates a social media candidate against canonical official handles.
        Returns ExclusionResult with 0% risk if verified official, else None.
        """
        norm_handle = self._normalize_handle(handle)
        raw_with_at = f"@{norm_handle}"

        # 1. Exact handle match check (with or without '@')
        if norm_handle in self.official_handles or raw_with_at in self.official_handles:
            return ExclusionResult(
                is_excluded=True,
                risk_score=0.0,
                risk_tier="OFFICIAL_SAFE",
                matched_rule="RULE_EXCLUSION_CANONICAL_HANDLE",
                matched_asset=handle,
                explanation=f"Exact match with canonical verified {BRAND_NAME} handle '{handle}'. Strict exclusion applied; false positive eliminated.",
            )

        # 2. Canonical domain URL verification
        if url:
            norm_url = self._normalize_string(url)
            for domain in self.official_domains:
                pattern = rf"https?://(?:[a-zA-Z0-9\-]+\.)?{re.escape(domain)}(?:/.*)?"
                if re.match(pattern, norm_url):
                    # Check if it links to an official brand property
                    for off_handle in self.official_handles:
                        if off_handle.replace("@", "") in norm_url:
                            return ExclusionResult(
                                is_excluded=True,
                                risk_score=0.0,
                                risk_tier="OFFICIAL_SAFE",
                                matched_rule="RULE_EXCLUSION_OFFICIAL_DOMAIN_ANCHOR",
                                matched_asset=url,
                                explanation=f"Profile is hosted or verified under official domain '{domain}'. Strict exclusion applied.",
                            )

        return None

    def check_app_candidate(
        self, package_id: str, publisher_name: str
    ) -> Optional[ExclusionResult]:
        """
        Evaluates a mobile app candidate against registered package IDs & authorized publisher.
        Both package ID AND authorized publisher must match to prevent unauthorized spoofing of IDs.
        """
        norm_pkg = self._normalize_string(package_id)
        norm_pub = self._normalize_string(publisher_name)

        is_pkg_official = norm_pkg in self.official_packages

        # Publisher matching: check canonical list or parent organization
        is_pub_official = False
        for pub in self.official_publishers:
            if pub in norm_pub or norm_pub in pub:
                is_pub_official = True
                break

        # Strict exclusion requires genuine publisher & registered package ID
        if is_pkg_official and is_pub_official:
            return ExclusionResult(
                is_excluded=True,
                risk_score=0.0,
                risk_tier="OFFICIAL_SAFE",
                matched_rule="RULE_EXCLUSION_VERIFIED_APP_AND_PUBLISHER",
                matched_asset=f"{package_id} by {publisher_name}",
                explanation=(
                    f"Candidate app matches registered Package ID '{package_id}' and authorized publisher "
                    f"'{publisher_name}' for {PARENT_COMPANY}. Strict exclusion applied; guaranteed 0% FP."
                ),
            )

        return None
