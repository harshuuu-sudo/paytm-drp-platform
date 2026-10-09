"""
Automated Incident Response & Takedown Package Generator
Generates legally compliant Cease-and-Desist, DMCA, and Abuse reports
for social media platforms, app stores, and domain registrars.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict
from config.brand_config import BRAND_NAME, PARENT_COMPANY


class TakedownNoticeGenerator:
    """
    Generates structured SOC takedown requests and evidence packages.
    """

    @staticmethod
    def _generate_evidence_hash(data: Dict[str, Any]) -> str:
        serialized = json.dumps(data, sort_keys=True).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @classmethod
    def generate_social_takedown(
        cls, evaluation_result: Dict[str, Any], case_id: str = "TICKET-DRP-8921"
    ) -> Dict[str, Any]:
        """
        Creates a platform abuse request for social media (Twitter/X, Instagram, Telegram).
        """
        handle = evaluation_result.get("handle", "")
        platform = evaluation_result.get("platform", "Social Media")
        risk_score = evaluation_result.get("risk_score", 0.0)
        risk_tier = evaluation_result.get("risk_tier", "CRITICAL")
        evidence_summary = evaluation_result.get("evidence_summary", "")
        scam_triggers = [t.get("label") for t in evaluation_result.get("matched_scam_triggers", [])]
        timestamp = datetime.now(timezone.utc).isoformat()

        evidence_hash = cls._generate_evidence_hash(evaluation_result)

        notice_body = f"""================================================================================
FORMAL BRAND IMPERSONATION & FRAUDULENT PHISHING TAKEDOWN NOTICE
================================================================================
Case Reference: {case_id}
Timestamp (UTC): {timestamp}
Platform Target: {platform}
Designated Brand: {BRAND_NAME} ({PARENT_COMPANY})
Target Infringing Account: {handle}
Evaluated Risk Tier: {risk_tier} (Risk Score: {risk_score}%)

TO: Abuse & Trust/Safety Legal Operations
FROM: Brand Protection & Infosec Operations Team, {PARENT_COMPANY}

RE: Urgent Removal Request - Deceptive Phishing Account Impersonating {BRAND_NAME}

Dear Trust & Safety Team,

We represent {PARENT_COMPANY}, the registered trademark holder and operator of {BRAND_NAME}, a premier Indian digital payments and financial services platform.

Our automated Digital Risk Protection (DRP) monitoring has detected an unauthorized account operating on your platform under the handle '{handle}'. This account is willfully impersonating our brand and engaging in deceptive activities targeting unsuspecting consumers.

TECHNICAL DETECTION & EVIDENCE SUMMARY:
- Target Entity: {handle}
- Platform: {platform}
- Violation Category: Trademark Infringement & Financial Phishing
- Key Malicious Signals: {evidence_summary}
- Identified Phishing Vectors: {", ".join(scam_triggers) if scam_triggers else "Unauthorized Brand Impersonation"}
- Cryptographic Forensic Hash (SHA-256): {evidence_hash}

LEGAL & POLICY BASIS:
1. Trademark Infringement: The infringing account unauthorizedly uses registered trademarks of {BRAND_NAME}.
2. Consumer Fraud & Phishing: The account attempts to solicit private user financial credentials, UPI details, or direct messages under the guise of an official support helpline.
3. Violation of Platform Community Standards & Impersonation Policies.

REQUESTED ACTION:
We formally demand that your team immediately SUSPEND and PERMANENTLY REMOVE the account '{handle}' to prevent irreversible consumer financial loss and maintain platform integrity.

Authorized Signature:
Principal Brand Protection Counsel & CISO Office
{PARENT_COMPANY}
Official Registry: brand-protection@paytm.com / abuse@one97.com
================================================================================
"""

        return {
            "case_id": case_id,
            "target": handle,
            "platform": platform,
            "risk_score": risk_score,
            "timestamp": timestamp,
            "evidence_hash": evidence_hash,
            "notice_text": notice_body,
        }

    @classmethod
    def generate_app_store_takedown(
        cls, evaluation_result: Dict[str, Any], case_id: str = "TICKET-APP-4421"
    ) -> Dict[str, Any]:
        """
        Creates a formal Mobile App Store DMCA & Trademark Infringement notice.
        """
        app_title = evaluation_result.get("app_title", "")
        package_id = evaluation_result.get("package_id", "")
        publisher = evaluation_result.get("publisher_name", "")
        app_store = evaluation_result.get("app_store", "Google Play Store")
        risk_score = evaluation_result.get("risk_score", 0.0)
        risk_tier = evaluation_result.get("risk_tier", "CRITICAL")
        flags = evaluation_result.get("detected_flags", [])
        perms = evaluation_result.get("dangerous_permissions_found", [])
        timestamp = datetime.now(timezone.utc).isoformat()

        evidence_hash = cls._generate_evidence_hash(evaluation_result)

        notice_body = f"""================================================================================
MOBILE APP STORE COUNTERFEIT & MALWARE TAKEDOWN NOTIFICATION
================================================================================
Case Reference: {case_id}
Timestamp (UTC): {timestamp}
Store Target: {app_store}
Designated Brand: {BRAND_NAME} ({PARENT_COMPANY})
Infringing Application Title: "{app_title}"
Infringing Package Identifier: "{package_id}"
Unauthorized Publisher: "{publisher}"
Evaluated Risk Tier: {risk_tier} (Risk Score: {risk_score}%)

TO: Google Play Developer Support / Apple Store App Review & Legal Compliance
FROM: Global Security Operations & IP Enforcement, {PARENT_COMPANY}

RE: Urgent Delisting Demand - Counterfeit Application Spoofing {BRAND_NAME}

Dear Store Compliance & Security Team,

We are writing on behalf of {PARENT_COMPANY}, owner of all proprietary rights and registered trademarks for {BRAND_NAME} (Registration Class 9, 36, 38, 42).

An unauthorized application is currently listed in the {app_store}:
- Title: "{app_title}"
- Package ID: "{package_id}"
- Registered Developer: "{publisher}"

EVIDENCE OF TRADEMARK INFRINGEMENT & USER HARMFUL ACTIVITY:
1. Publisher Mismatch: The developer "{publisher}" has no affiliation with {PARENT_COMPANY} or {BRAND_NAME}.
2. Title & Brand Cloned: Uses "{BRAND_NAME}" deceptively to trick consumers into downloading counterfeit software.
3. Namespace / Lookalike Squatting: Exploits brand identifiers.
4. Dangerous Permissions Requested: {", ".join(perms) if perms else "Excessive device access"}.
5. Specific Threat Indicators: {", ".join(flags)}.
6. Forensic Integrity Hash: {evidence_hash}

DEMAND:
In accordance with your Developer Distribution Agreement and intellectual property protection policies, we demand immediate removal and global delisting of package "{package_id}".

Authorized Signature:
Head of Information Security & Intellectual Property Rights
{PARENT_COMPANY}
Contact: security@paytm.com | legal@one97.com
================================================================================
"""

        return {
            "case_id": case_id,
            "target": package_id,
            "app_title": app_title,
            "store": app_store,
            "risk_score": risk_score,
            "timestamp": timestamp,
            "evidence_hash": evidence_hash,
            "notice_text": notice_body,
        }
