"""
Social Media Threat Evaluation Engine
Deep behavioral analysis of handles, display names, bios, scam triggers,
and multi-factor risk scoring with strict whitelist enforcement.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from config.brand_config import (
    SCAM_CONTENT_TRIGGERS,
    RISK_TIERS,
    BRAND_NAME,
    BRAND_STEM,
)
from core.exclusion_engine import StrictExclusionEngine, ExclusionResult
from core.homoglyph_engine import LookAlikeHomoglyphEngine, HomoglyphAnalysisResult


@dataclass
class SocialCandidate:
    handle: str
    display_name: str
    bio: str
    platform: str = "Twitter/X"
    is_verified: bool = False
    followers_count: int = 0
    external_urls: List[str] = field(default_factory=list)
    profile_id: str = ""


@dataclass
class SocialThreatEvaluationResult:
    candidate: SocialCandidate
    is_whitelisted: bool
    risk_score: float
    risk_tier: str  # CRITICAL, HIGH, MEDIUM, SAFE, OFFICIAL_SAFE
    homoglyph_result: Optional[HomoglyphAnalysisResult]
    matched_scam_triggers: List[Dict[str, Any]]
    context_penalties: List[str]
    score_breakdown: Dict[str, float]
    recommended_action: str
    evidence_summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "handle": self.candidate.handle,
            "display_name": self.candidate.display_name,
            "bio": self.candidate.bio,
            "platform": self.candidate.platform,
            "is_verified": self.candidate.is_verified,
            "followers_count": self.candidate.followers_count,
            "is_whitelisted": self.is_whitelisted,
            "risk_score": round(self.risk_score, 1),
            "risk_tier": self.risk_tier,
            "homoglyph_data": self.homoglyph_result.to_dict() if self.homoglyph_result else None,
            "matched_scam_triggers": self.matched_scam_triggers,
            "context_penalties": self.context_penalties,
            "score_breakdown": {k: round(v, 2) for k, v in self.score_breakdown.items()},
            "recommended_action": self.recommended_action,
            "evidence_summary": self.evidence_summary,
        }


class SocialMediaEvaluator:
    """
    Principal SOC Social Threat Evaluator.
    Combines deterministic whitelisting, homoglyph de-obfuscation, NLP scam triggers,
    and contextual trust modeling.
    """

    def __init__(
        self,
        exclusion_engine: Optional[StrictExclusionEngine] = None,
        homoglyph_engine: Optional[LookAlikeHomoglyphEngine] = None,
    ):
        self.exclusion_engine = exclusion_engine or StrictExclusionEngine()
        self.homoglyph_engine = homoglyph_engine or LookAlikeHomoglyphEngine()

    def evaluate(self, candidate: SocialCandidate) -> SocialThreatEvaluationResult:
        # Step 1: Pre-flight Strict Exclusion Engine Check (0% FP Guarantee)
        url_context = candidate.external_urls[0] if candidate.external_urls else ""
        exclusion = self.exclusion_engine.check_social_candidate(candidate.handle, url_context)
        if exclusion and exclusion.is_excluded:
            return SocialThreatEvaluationResult(
                candidate=candidate,
                is_whitelisted=True,
                risk_score=0.0,
                risk_tier="OFFICIAL_SAFE",
                homoglyph_result=None,
                matched_scam_triggers=[],
                context_penalties=[],
                score_breakdown={
                    "identity_score": 0.0,
                    "content_score": 0.0,
                    "context_score": 0.0,
                    "composite_score": 0.0,
                },
                recommended_action="WHITELIST_PROTECTED: No Action. Official Asset Verified.",
                evidence_summary=exclusion.explanation,
            )

        # Step 2: Look-Alike & Homoglyph De-obfuscation
        homoglyph_res = self.homoglyph_engine.analyze(
            candidate_text=candidate.handle,
            display_name=candidate.display_name,
            bio=candidate.bio,
        )

        # Step 3: Bio & Content Scam Trigger Analysis
        combined_text = f"{candidate.handle} {candidate.display_name} {candidate.bio}".lower()
        matched_triggers: List[Dict[str, Any]] = []
        content_score = 0.0

        for trig in SCAM_CONTENT_TRIGGERS:
            pattern = trig["pattern"]
            matches = re.findall(pattern, combined_text, re.IGNORECASE)
            if matches:
                matched_triggers.append({
                    "label": trig["label"],
                    "pattern": pattern,
                    "weight": trig["weight"],
                    "match_count": len(matches),
                })
                content_score += trig["weight"]

        # Phone / Exfiltration regex
        phone_matches = re.findall(r"(?:(?:\+91|0)?[6-9]\d{9}|1800\d{6,7})", combined_text)
        if phone_matches:
            matched_triggers.append({
                "label": "Suspected Rogue Helpline Phone / Vishing Number",
                "pattern": "phone_pattern",
                "weight": 25,
                "match_count": len(phone_matches),
            })
            content_score += 25

        # Telegram / WhatsApp external redirects
        for ext_url in candidate.external_urls:
            if any(dom in ext_url.lower() for dom in ["t.me", "telegram.me", "wa.me", "api.whatsapp.com", "bit.ly"]):
                matched_triggers.append({
                    "label": f"Suspicious External Out-of-Band Redirect ({ext_url})",
                    "pattern": "redirect_link",
                    "weight": 20,
                    "match_count": 1,
                })
                content_score += 20

        content_score = min(100.0, content_score)

        # Step 4: Contextual & Behavioral Assessment
        context_score = 0.0
        context_penalties: List[str] = []

        is_claiming_support = any(
            t in combined_text for t in ["care", "help", "support", "refund", "helpline", "official"]
        )
        has_brand_name = BRAND_STEM in homoglyph_res.de_leeted_text or BRAND_NAME.lower() in candidate.display_name.lower()

        # Unverified claiming to be official brand support
        if is_claiming_support and has_brand_name and not candidate.is_verified:
            context_score += 45.0
            context_penalties.append("PENALTY_UNVERIFIED_SUPPORT_CLAIM: Claims official support status without verified badge.")

        # Disproportionate follower metrics for a purported major bank / fintech helpdesk
        if is_claiming_support and has_brand_name and candidate.followers_count < 1000:
            context_score += 35.0
            context_penalties.append(
                f"PENALTY_SUSPICIOUS_LOW_AUDIENCE:Purported official support account has only {candidate.followers_count} followers."
            )

        # Exact brand display name clone
        if candidate.display_name.strip().lower() in [b.lower() for b in [BRAND_NAME, f"{BRAND_NAME} Care", f"{BRAND_NAME} Support"]]:
            context_score += 20.0
            context_penalties.append("PENALTY_DISPLAY_NAME_HIJACK: Display name directly clones official brand identity.")

        context_score = min(100.0, context_score)

        # Step 5: Multi-Factor Scoring Formula
        identity_score = homoglyph_res.identity_risk_score
        w_id = 0.45
        w_cont = 0.35
        w_ctx = 0.20

        composite_score = (w_id * identity_score) + (w_cont * content_score) + (w_ctx * context_score)

        # High-Impact Amplification Rules
        # Rule A: If benign confirmed with 0 scam triggers -> cap at benign level (< 20%)
        if homoglyph_res.is_likely_benign and len(matched_triggers) == 0:
            composite_score = min(composite_score, 15.0)

        # Rule B: If direct brand stem + high-risk padding (refund/care/upi) + scam triggers -> push to Critical
        if homoglyph_res.stem_detected and len(homoglyph_res.padding_tokens_found) >= 1 and len(matched_triggers) >= 1:
            composite_score = max(composite_score, 88.0)

        # Rule C: If homoglyph or leetspeak spoofing used to mimic brand + support claim -> push to Critical
        if (homoglyph_res.has_homoglyphs or homoglyph_res.has_leetspeak) and is_claiming_support:
            composite_score = max(composite_score, 86.0)

        composite_score = min(100.0, max(0.0, composite_score))

        # Risk Categorization
        if composite_score >= RISK_TIERS["CRITICAL"]:
            risk_tier = "CRITICAL"
            recommended_action = "IMMEDIATE_TAKEDOWN: High-confidence brand impersonation & scam vector. Auto-dispatch takedown notice."
        elif composite_score >= RISK_TIERS["HIGH"]:
            risk_tier = "HIGH"
            recommended_action = "ESCALATE_TO_SOC: High probability of phishing or brand abuse. Flagged for priority analyst review."
        elif composite_score >= RISK_TIERS["MEDIUM"]:
            risk_tier = "MEDIUM"
            recommended_action = "MONITOR_ACTIVE: Moderate similarity or suspicious phrasing. Added to automated telemetry watch-list."
        else:
            risk_tier = "SAFE"
            recommended_action = "BENIGN_IGNORE: Benign third party or low threat potential. Zero action required."

        # Generate Evidence Summary
        evidence_parts = []
        if homoglyph_res.has_homoglyphs or homoglyph_res.has_leetspeak:
            evidence_parts.append(
                f"Obfuscation detected ({len(homoglyph_res.detected_homoglyphs)} homoglyphs, {len(homoglyph_res.detected_leetspeak)} leetspeak chars)."
            )
        if homoglyph_res.padding_tokens_found:
            evidence_parts.append(f"Padding tokens hijacked: {', '.join(homoglyph_res.padding_tokens_found)}.")
        if matched_triggers:
            trig_names = [t['label'] for t in matched_triggers]
            evidence_parts.append(f"Scam triggers activated: {', '.join(trig_names)}.")
        if context_penalties:
            evidence_parts.append(f"Context flags: {len(context_penalties)} behavioral violations.")
        if homoglyph_res.is_likely_benign:
            evidence_parts.append(f"Benign assessment: {homoglyph_res.benign_rationale}")

        evidence_summary = " ".join(evidence_parts) if evidence_parts else "No significant threat signals detected."

        return SocialThreatEvaluationResult(
            candidate=candidate,
            is_whitelisted=False,
            risk_score=composite_score,
            risk_tier=risk_tier,
            homoglyph_result=homoglyph_res,
            matched_scam_triggers=matched_triggers,
            context_penalties=context_penalties,
            score_breakdown={
                "identity_score": identity_score,
                "content_score": content_score,
                "context_score": context_score,
                "composite_score": composite_score,
            },
            recommended_action=recommended_action,
            evidence_summary=evidence_summary,
        )
