"""
Mobile App Store Impersonation Monitoring Engine
Detects rogue APKs, publisher mismatches, package ID namespace squatting,
cloned titles, and predatory permission harvesting.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config.brand_config import (
    BRAND_NAME,
    BRAND_STEM,
    OFFICIAL_PACKAGE_IDS,
    OFFICIAL_PUBLISHERS,
    RISK_TIERS,
)
from core.exclusion_engine import StrictExclusionEngine, ExclusionResult
from core.homoglyph_engine import LookAlikeHomoglyphEngine


@dataclass
class MobileAppCandidate:
    app_title: str
    package_id: str
    publisher_name: str
    app_store: str = "Google Play Store"
    permissions: List[str] = field(default_factory=list)
    downloads_count: int = 0
    rating: float = 0.0
    app_url: str = ""
    description: str = ""


@dataclass
class AppStoreThreatEvaluationResult:
    candidate: MobileAppCandidate
    is_whitelisted: bool
    risk_score: float
    risk_tier: str  # CRITICAL, HIGH, MEDIUM, SAFE, OFFICIAL_SAFE
    is_publisher_mismatch: bool
    is_namespace_squatted: bool
    dangerous_permissions_found: List[str]
    detected_flags: List[str]
    score_breakdown: Dict[str, float]
    recommended_action: str
    evidence_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "app_title": self.candidate.app_title,
            "package_id": self.candidate.package_id,
            "publisher_name": self.candidate.publisher_name,
            "app_store": self.candidate.app_store,
            "permissions": self.candidate.permissions,
            "downloads_count": self.candidate.downloads_count,
            "is_whitelisted": self.is_whitelisted,
            "risk_score": round(self.risk_score, 1),
            "risk_tier": self.risk_tier,
            "is_publisher_mismatch": self.is_publisher_mismatch,
            "is_namespace_squatted": self.is_namespace_squatted,
            "dangerous_permissions_found": self.dangerous_permissions_found,
            "detected_flags": self.detected_flags,
            "score_breakdown": {k: round(v, 2) for k, v in self.score_breakdown.items()},
            "recommended_action": self.recommended_action,
            "evidence_summary": self.evidence_summary,
        }


# High-risk predatory/trojan permissions frequently seen in counterfeit fintech apps
DANGEROUS_PERMISSIONS = {
    "READ_SMS": "Intercepts 2FA OTP codes for banking fraud",
    "RECEIVE_SMS": "Silent incoming SMS theft",
    "READ_CONTACTS": "Harassment and blackmail vector in predatory loan apps",
    "SYSTEM_ALERT_WINDOW": "Phishing overlay injection over authentic banking screens",
    "BIND_ACCESSIBILITY_SERVICE": "Full UI hijacking and credential keystroke theft",
    "RECORD_AUDIO": "Unauthorized ambient eavesdropping",
    "ACCESS_FINE_LOCATION": "Precision geolocation tracking",
}


class AppStoreEvaluator:
    """
    Evaluator for mobile applications across Google Play, Apple App Store, and third-party stores.
    Enforces strict publisher authentication and detects namespace imitation.
    """

    def __init__(
        self,
        exclusion_engine: Optional[StrictExclusionEngine] = None,
        homoglyph_engine: Optional[LookAlikeHomoglyphEngine] = None,
    ):
        self.exclusion_engine = exclusion_engine or StrictExclusionEngine()
        self.homoglyph_engine = homoglyph_engine or LookAlikeHomoglyphEngine()

    def evaluate(self, candidate: MobileAppCandidate) -> AppStoreThreatEvaluationResult:
        # Step 1: Pre-flight Strict Exclusion Engine Check (0% FP Guarantee)
        exclusion = self.exclusion_engine.check_app_candidate(
            package_id=candidate.package_id,
            publisher_name=candidate.publisher_name,
        )
        if exclusion and exclusion.is_excluded:
            return AppStoreThreatEvaluationResult(
                candidate=candidate,
                is_whitelisted=True,
                risk_score=0.0,
                risk_tier="OFFICIAL_SAFE",
                is_publisher_mismatch=False,
                is_namespace_squatted=False,
                dangerous_permissions_found=[],
                detected_flags=["OFFICIAL_CANONICAL_APP: Whitelist validated"],
                score_breakdown={
                    "identity_risk": 0.0,
                    "publisher_risk": 0.0,
                    "permission_risk": 0.0,
                    "composite_score": 0.0,
                },
                recommended_action="WHITELIST_PROTECTED: No Action. Authorized Production App.",
                evidence_summary=exclusion.explanation,
            )

        norm_pkg = candidate.package_id.strip().lower()
        norm_pub = candidate.publisher_name.strip().lower()
        norm_title = candidate.app_title.strip().lower()
        combined_text = f"{norm_title} {norm_pkg} {candidate.description.lower()}"

        detected_flags: List[str] = []
        dangerous_perms_found: List[str] = []

        # Step 2: Check for Canonical Namespace Squatting / Sub-Namespace Imitation
        is_namespace_squatted = False
        if norm_pkg.startswith("net.one97.paytm.") or norm_pkg.startswith("com.paytm."):
            is_namespace_squatted = True
            detected_flags.append(
                f"FLAG_NAMESPACE_SQUATTING: Package ID '{candidate.package_id}' exploits official brand reverse-DNS hierarchy."
            )

        # Step 3: Publisher Mismatch Analysis
        is_authorized_pub = any(pub in norm_pub for pub in OFFICIAL_PUBLISHERS)
        title_claims_brand = BRAND_NAME.lower() in norm_title or BRAND_STEM in norm_pkg

        is_publisher_mismatch = False
        if title_claims_brand and not is_authorized_pub:
            is_publisher_mismatch = True
            detected_flags.append(
                f"FLAG_PUBLISHER_MISMATCH: App branding invokes '{BRAND_NAME}', but developer '{candidate.publisher_name}' is unauthorized."
            )

        # Check if developer itself tries to fake the brand publisher name
        if not is_authorized_pub and ("one97" in norm_pub or BRAND_STEM in norm_pub):
            detected_flags.append(
                f"FLAG_COUNTERFEIT_DEVELOPER_NAME: Developer entity '{candidate.publisher_name}' mimics brand corporate identity."
            )

        # Step 4: Permission Analysis
        for perm in candidate.permissions:
            perm_clean = perm.replace("android.permission.", "").strip()
            if perm_clean in DANGEROUS_PERMISSIONS:
                dangerous_perms_found.append(perm_clean)
                detected_flags.append(
                    f"FLAG_HIGH_RISK_PERMISSION: {perm_clean} ({DANGEROUS_PERMISSIONS[perm_clean]})"
                )

        # Step 5: Loan / Phishing / Cloned Keyword Check
        high_risk_app_keywords = ["fast loan", "quick cash", "instant loan", "refund", "customer care", "scratch card", "airdrop"]
        found_app_keywords = [kw for kw in high_risk_app_keywords if kw in combined_text]
        if found_app_keywords:
            detected_flags.append(f"FLAG_PREDATORY_KEYWORD: Found lure keywords {found_app_keywords}")

        # Step 6: Benign App Differentiation (e.g. "Payment Tracker", "Payton Calculator")
        is_benign = False
        if not is_namespace_squatted and not title_claims_brand:
            if "payton" in norm_title or "paypal" in norm_title or "payment" in norm_title:
                is_benign = True
                detected_flags.append("FLAG_BENIGN_APP: Unrelated third-party app with generic or distinct name.")

        # Step 7: Multi-Factor Scoring
        identity_risk = 0.0
        publisher_risk = 0.0
        permission_risk = 0.0

        if is_benign:
            composite_score = 5.0
        else:
            # Identity Risk (Title + Package ID)
            if is_namespace_squatted:
                identity_risk += 50.0
            elif BRAND_STEM in norm_pkg:
                identity_risk += 35.0

            if BRAND_NAME.lower() in norm_title:
                identity_risk += 40.0

            identity_risk = min(100.0, identity_risk)

            # Publisher Risk
            if is_publisher_mismatch:
                publisher_risk += 60.0
            if "one97" in norm_pub or BRAND_STEM in norm_pub:
                publisher_risk += 30.0
            publisher_risk = min(100.0, publisher_risk)

            # Permission Risk
            if dangerous_perms_found:
                permission_risk = min(100.0, len(dangerous_perms_found) * 25.0)

            # Weighting: 40% Publisher mismatch, 35% Identity imitation, 25% Dangerous permissions
            composite_score = (0.40 * publisher_risk) + (0.35 * identity_risk) + (0.25 * permission_risk)

            # Amplification: Namespace spoofing OR (Brand clone + SMS/Overlay) -> Auto Critical
            if is_namespace_squatted or (is_publisher_mismatch and len(dangerous_perms_found) >= 2):
                composite_score = max(composite_score, 88.0)
            elif is_publisher_mismatch and found_app_keywords:
                composite_score = max(composite_score, 85.0)

        composite_score = min(100.0, max(0.0, composite_score))

        # Categorization
        if composite_score >= RISK_TIERS["CRITICAL"]:
            risk_tier = "CRITICAL"
            recommended_action = "CRITICAL_TAKEDOWN: Rogue application spoofing official app. Dispatch Google Play / Store DMCA Notice."
        elif composite_score >= RISK_TIERS["HIGH"]:
            risk_tier = "HIGH"
            recommended_action = "TAKEDOWN_SUBMIT: Unauthorized trademark usage & developer mismatch. Submit trademark violation."
        elif composite_score >= RISK_TIERS["MEDIUM"]:
            risk_tier = "MEDIUM"
            recommended_action = "ANALYST_REVIEW: Ambiguous branding. Flag for automated APK static analysis."
        else:
            risk_tier = "SAFE"
            recommended_action = "SAFE_BENIGN: Legitimate or unrelated application. No action required."

        evidence_summary = (
            f"Package '{candidate.package_id}' evaluated on {candidate.app_store}. "
            f"Publisher: '{candidate.publisher_name}'. Flags triggered: {len(detected_flags)}. "
            f"High-risk permissions: {len(dangerous_perms_found)}."
        )

        return AppStoreThreatEvaluationResult(
            candidate=candidate,
            is_whitelisted=False,
            risk_score=composite_score,
            risk_tier=risk_tier,
            is_publisher_mismatch=is_publisher_mismatch,
            is_namespace_squatted=is_namespace_squatted,
            dangerous_permissions_found=dangerous_perms_found,
            detected_flags=detected_flags,
            score_breakdown={
                "identity_risk": identity_risk,
                "publisher_risk": publisher_risk,
                "permission_risk": permission_risk,
                "composite_score": composite_score,
            },
            recommended_action=recommended_action,
            evidence_summary=evidence_summary,
        )
