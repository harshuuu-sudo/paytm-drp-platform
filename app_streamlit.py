"""
Paytm Digital Risk Protection (DRP) Platform
Interactive SOC Web Dashboard (Streamlit)
Principal Cybersecurity Software Engineering Standard
"""

import streamlit as st
import pandas as pd
import json
from datetime import datetime, timezone

from config.brand_config import (
    BRAND_NAME,
    PARENT_COMPANY,
    OFFICIAL_HANDLES,
    OFFICIAL_PACKAGE_IDS,
    OFFICIAL_PUBLISHERS,
    HIGH_RISK_PADDING_TOKENS,
    SCAM_CONTENT_TRIGGERS,
    RISK_TIERS,
)
from core.threat_orchestrator import ThreatOrchestrator
from data.test_datasets import TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES

# Page Configuration
st.set_page_config(
    page_title="Paytm DRP Platform | SOC Threat Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-End Cyber SOC Styling
st.markdown(
    """
    <style>
    /* Dark Theme SOC styling */
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: 'Inter', -apple-system, sans-serif;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    .metric-val {
        font-size: 28px;
        font-weight: 700;
        margin-top: 4px;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-medium {
        background-color: #eab308;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-safe {
        background-color: #10b981;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .badge-official {
        background-color: #06b6d4;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 11px;
    }
    .code-box {
        background-color: #020617;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px;
        font-family: 'Courier New', monospace;
        font-size: 13px;
        color: #38bdf8;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_orchestrator():
    return ThreatOrchestrator()


orchestrator = get_orchestrator()

# Header Banner
st.title("🛡️ Paytm Digital Risk Protection (DRP) Platform")
st.caption(
    f"Anchor Brand: **{BRAND_NAME} ({PARENT_COMPANY})** | Scope: **Social Media & Mobile App Store Impersonation Monitoring**"
)

# Run batch processing
batch_data = orchestrator.batch_process(TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES)
summary = batch_data["summary"]

# Top Telemetry Row
col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">MONITORED TARGETS</span>
            <div class="metric-val" style="color: #38bdf8;">{summary['total_monitored']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">CRITICAL IMPERSONATORS</span>
            <div class="metric-val" style="color: #ef4444;">{summary['critical_threats']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">HIGH / MEDIUM RISKS</span>
            <div class="metric-val" style="color: #f59e0b;">{summary['high_risk'] + summary['medium_risk']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">OFFICIAL PROTECTED</span>
            <div class="metric-val" style="color: #06b6d4;">{summary['official_safe_count']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col5:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">FALSE POSITIVE RATE</span>
            <div class="metric-val" style="color: #10b981;">{summary['false_positive_rate']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col6:
    st.markdown(
        f"""
        <div class="metric-card">
            <span style="color: #94a3b8; font-size: 12px;">TAKEDOWNS READY</span>
            <div class="metric-val" style="color: #f43f5e;">{summary['takedowns_ready']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# Navigation Tabs
tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📊 Threat Matrix & Inspector",
        "⚡ Live Threat Simulator",
        "🏛️ Architecture & Detection Logic",
        "⚙️ Brand Asset Configuration",
    ]
)

# ==============================================================================
# TAB 1: THREAT MATRIX & INSPECTOR
# ==============================================================================
with tab1:
    st.subheader("Global Threat Intelligence Feed")
    feed_mode = st.radio("Channel Filter", ["All Channels", "Social Media Threats", "Mobile App Store Threats"], horizontal=True)

    rows = []
    if feed_mode in ["All Channels", "Social Media Threats"]:
        for r in batch_data["social_results"]:
            rows.append({
                "Channel": f"Social ({r['platform']})",
                "Identifier": r["handle"],
                "Entity Name / Title": r["display_name"],
                "Risk Tier": r["risk_tier"],
                "Risk Score": f"{r['risk_score']}%",
                "Whitelist": "PROTECTED (0% FP)" if r["is_whitelisted"] else "No",
                "Action Required": r["recommended_action"].split(":")[0],
                "Raw": r,
                "Type": "social",
            })

    if feed_mode in ["All Channels", "Mobile App Store Threats"]:
        for r in batch_data["app_results"]:
            rows.append({
                "Channel": f"Mobile App ({r['app_store']})",
                "Identifier": r["package_id"],
                "Entity Name / Title": r["app_title"],
                "Risk Tier": r["risk_tier"],
                "Risk Score": f"{r['risk_score']}%",
                "Whitelist": "PROTECTED (0% FP)" if r["is_whitelisted"] else "No",
                "Action Required": r["recommended_action"].split(":")[0],
                "Raw": r,
                "Type": "app",
            })

    df = pd.DataFrame(rows)
    display_df = df[["Channel", "Identifier", "Entity Name / Title", "Risk Tier", "Risk Score", "Whitelist", "Action Required"]]
    st.dataframe(display_df, use_container_width=True)

    st.divider()
    st.subheader("🔍 Deep-Dive Forensic Threat Inspector")

    selected_idx = st.selectbox(
        "Select Candidate Entity to Inspect Details & Takedown Package:",
        options=range(len(rows)),
        format_func=lambda i: f"[{rows[i]['Risk Tier']}] {rows[i]['Identifier']} - {rows[i]['Entity Name / Title']}",
    )

    selected_item = rows[selected_idx]
    item_raw = selected_item["Raw"]

    col_det1, col_det2 = st.columns([1, 1])

    with col_det1:
        st.markdown(f"#### Target: `{selected_item['Identifier']}`")
        st.write(f"**Entity Name / Title:** {selected_item['Entity Name / Title']}")
        st.write(f"**Channel / Platform:** {selected_item['Channel']}")

        # Tier styling badge
        tier = selected_item["Risk Tier"]
        if tier == "OFFICIAL_SAFE":
            st.markdown('<span class="badge-official">OFFICIAL SAFE (0% Risk)</span>', unsafe_allow_html=True)
        elif tier == "CRITICAL":
            st.markdown('<span class="badge-critical">CRITICAL IMPERSONATOR (>=85%)</span>', unsafe_allow_html=True)
        elif tier == "HIGH":
            st.markdown('<span class="badge-high">HIGH RISK ALERT (>=60%)</span>', unsafe_allow_html=True)
        elif tier == "MEDIUM":
            st.markdown('<span class="badge-medium">MEDIUM SUSPICIOUS (>=30%)</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="badge-safe">SAFE / BENIGN (&lt;30%)</span>', unsafe_allow_html=True)

        st.write("")
        st.write(f"**Evidence Summary:** {item_raw.get('evidence_summary', 'N/A')}")
        st.write(f"**Recommended SOC Action:** `{item_raw.get('recommended_action', 'N/A')}`")

        # Score breakdown bars
        breakdown = item_raw.get("score_breakdown", {})
        if breakdown:
            st.markdown("##### Multi-Factor Risk Score Breakdown")
            for k, v in breakdown.items():
                if k != "composite_score":
                    st.progress(min(1.0, v / 100.0), text=f"{k.replace('_', ' ').title()}: {v}%")

    with col_det2:
        if selected_item["Type"] == "social":
            hg = item_raw.get("homoglyph_data")
            if hg:
                st.markdown("#### Homoglyph & Identity Forensics")
                c_a, c_b = st.columns(2)
                c_a.metric("Has Unicode Homoglyphs", "YES" if hg["has_homoglyphs"] else "No")
                c_b.metric("Has Leetspeak Sub", "YES" if hg["has_leetspeak"] else "No")

                st.write(f"**De-leeted Normalized String:** `{hg['de_leeted_text']}`")
                st.write(f"**Stem Hijacked:** `{hg['stem_detected']}`")
                st.write(f"**Padding Tokens:** `{', '.join(hg['padding_tokens_found']) if hg['padding_tokens_found'] else 'None'}`")
                st.write(f"**Levenshtein Distance to Stem:** `{hg['levenshtein_distance_to_stem']}`")

            scam_trigs = item_raw.get("matched_scam_triggers", [])
            if scam_trigs:
                st.markdown("#### Flagged Phishing & Scam Triggers")
                for st_item in scam_trigs:
                    st.error(f"🚨 **{st_item['label']}** (Weight: +{st_item['weight']}%)")

        elif selected_item["Type"] == "app":
            st.markdown("#### Mobile App Forensics")
            st.write(f"**Package ID:** `{item_raw.get('package_id')}`")
            st.write(f"**Publisher Name:** `{item_raw.get('publisher_name')}`")
            st.write(f"**Namespace Squatting:** `{'YES - Severe Infringement' if item_raw.get('is_namespace_squatted') else 'No'}`")
            st.write(f"**Publisher Mismatch:** `{'YES - Counterfeit Developer' if item_raw.get('is_publisher_mismatch') else 'No'}`")

            perms = item_raw.get("dangerous_permissions_found", [])
            if perms:
                st.markdown("#### High-Risk Android Permissions")
                for p in perms:
                    st.warning(f"⚠️ **{p}** (Banking trojan / Harassment vector)")

    # Takedown Notice Section
    if "takedown_notice" in item_raw:
        st.divider()
        st.markdown("### 📜 Automated Cease-and-Desist / Platform Takedown Notice")
        tk = item_raw["takedown_notice"]
        st.caption(f"Case ID: **{tk['case_id']}** | Cryptographic Forensic Hash (SHA-256): `{tk['evidence_hash']}`")
        st.text_area("Legal Notice Body (Ready to Dispatch)", tk["notice_text"], height=220)
        st.download_button(
            label="⬇️ Download Formal Takedown Notice (.txt)",
            data=tk["notice_text"],
            file_name=f"Takedown_{selected_item['Identifier'].replace('@', '').replace('.', '_')}.txt",
            mime="text/plain",
        )


# ==============================================================================
# TAB 2: LIVE THREAT SIMULATOR
# ==============================================================================
with tab2:
    st.subheader("Real-Time Threat Simulation & Interactive Sandbox")
    st.write("Input any candidate social handle or mobile app to execute the full DRP detection pipeline live.")

    scan_mode = st.radio("Select Target Vector", ["Social Media Candidate", "Mobile Application Candidate"], horizontal=True)

    if scan_mode == "Social Media Candidate":
        with st.form("social_scan_form"):
            col_s1, col_s2 = st.columns(2)
            with col_s1:
                test_handle = st.text_input("Handle / Username", value="@P4ytm_Cash_Help")
                test_display = st.text_input("Display Name", value="Paytm Customer Support 24x7")
                test_platform = st.selectbox("Platform", ["Twitter/X", "Instagram", "Telegram", "Facebook", "LinkedIn"])
            with col_s2:
                test_bio = st.text_area(
                    "Bio / Profile Description",
                    value="Official Paytm helpdesk. DM for stuck UPI refund, KYC update issues or WhatsApp +919876543210",
                )
                test_verified = st.checkbox("Platform Verified Badge", value=False)
                test_followers = st.number_input("Follower Count", value=15, min_value=0)

            submitted_social = st.form_submit_button("🚀 Run Live Forensic Evaluation")

        if submitted_social:
            with st.spinner("Analyzing character homoglyphs, leetspeak, scam triggers, and whitelist registers..."):
                cand_payload = {
                    "handle": test_handle,
                    "display_name": test_display,
                    "bio": test_bio,
                    "platform": test_platform,
                    "is_verified": test_verified,
                    "followers_count": test_followers,
                    "external_urls": ["https://wa.me/919876543210"] if "+91" in test_bio else [],
                }
                live_res = orchestrator.scan_social_candidate(cand_payload)

            st.success("Analysis Complete!")
            col_res1, col_res2 = st.columns([1, 1])

            with col_res1:
                st.markdown(f"### Evaluation Result: `{live_res['risk_tier']}`")
                st.metric("Composite Risk Score", f"{live_res['risk_score']}%")
                st.write(f"**Recommended Action:** {live_res['recommended_action']}")
                st.write(f"**Evidence:** {live_res['evidence_summary']}")

            with col_res2:
                st.markdown("### Forensic Findings")
                if live_res.get("homoglyph_data"):
                    h = live_res["homoglyph_data"]
                    st.write(f"- De-leeted String: `{h['de_leeted_text']}`")
                    st.write(f"- Homoglyphs Found: `{len(h['detected_homoglyphs'])}`")
                    st.write(f"- Leetspeak Substitutions: `{len(h['detected_leetspeak'])}`")
                    st.write(f"- Padding Tokens Hijacked: `{h['padding_tokens_found']}`")
                for trig in live_res.get("matched_scam_triggers", []):
                    st.warning(f"🚨 Scam Trigger: {trig['label']}")

            if "takedown_notice" in live_res:
                st.divider()
                st.markdown("#### Generated Platform Takedown Notice")
                st.text_area("Notice Preview", live_res["takedown_notice"]["notice_text"], height=180)

    else:
        with st.form("app_scan_form"):
            col_a1, col_a2 = st.columns(2)
            with col_a1:
                test_title = st.text_input("App Title", value="Paytm Quick Instant Loan")
                test_pkg = st.text_input("Package ID", value="net.one97.paytm.fastcash")
                test_store = st.selectbox("App Store", ["Google Play Store", "Apple App Store", "APKPure", "9Apps"])
            with col_a2:
                test_pub = st.text_input("Developer / Publisher Name", value="Global Micro Credit FinCorp")
                test_desc = st.text_area("Description", value="Instant cash disbursal without KYC. 100% Paytm backed loan.")
                test_perms = st.multiselect(
                    "Requested Permissions",
                    ["READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "CAMERA"],
                    default=["READ_SMS", "SYSTEM_ALERT_WINDOW"],
                )

            submitted_app = st.form_submit_button("🚀 Run Live Mobile App Scan")

        if submitted_app:
            with st.spinner("Evaluating package namespace, publisher registry, and permission trojan heuristics..."):
                cand_payload = {
                    "app_title": test_title,
                    "package_id": test_pkg,
                    "publisher_name": test_pub,
                    "app_store": test_store,
                    "description": test_desc,
                    "permissions": test_perms,
                    "downloads_count": 1000,
                }
                live_app_res = orchestrator.scan_app_candidate(cand_payload)

            st.success("App Store Analysis Complete!")
            col_ar1, col_ar2 = st.columns([1, 1])
            with col_ar1:
                st.markdown(f"### Evaluation Result: `{live_app_res['risk_tier']}`")
                st.metric("Composite Risk Score", f"{live_app_res['risk_score']}%")
                st.write(f"**Action:** {live_app_res['recommended_action']}")
                st.write(f"**Evidence:** {live_app_res['evidence_summary']}")
            with col_ar2:
                st.markdown("### Threat Flags")
                for f in live_app_res.get("detected_flags", []):
                    st.error(f)

            if "takedown_notice" in live_app_res:
                st.divider()
                st.markdown("#### Generated Store Delisting Notice")
                st.text_area("Notice Preview", live_app_res["takedown_notice"]["notice_text"], height=180)


# ==============================================================================
# TAB 3: ARCHITECTURE & DETECTION LOGIC
# ==============================================================================
with tab3:
    st.subheader("Platform Architecture & Detection Pipeline Specification")
    st.caption("Principal Cybersecurity Software Engineering Blueprint")

    st.markdown(
        """
        ```
        +---------------------------------------------------------------------------------------------------+
        |                                PAYTM DRP INGESTION & PIPELINE DATA FLOW                           |
        +---------------------------------------------------------------------------------------------------+
                                                      |
                                     [ Social Media & Mobile App Telemetry ]
                                                      |
                                                      v
                                      +-------------------------------+
                                      |  STAGE 1: STRICT EXCLUSION    |
                                      |    Deterministic Whitelist    |
                                      +-------------------------------+
                                            /                  \\
                             [Match Official Asset]      [Unknown / Unmatched]
                                          /                      \\
                                         v                        v
                            +--------------------+   +------------------------------------+
                            | 0% Risk Guaranteed |   | STAGE 2: HOMOGLYPH & LEETSPEAK     |
                            |   OFFICIAL_SAFE    |   | Normalization & De-obfuscation     |
                            +--------------------+   +------------------------------------+
                                                                  |
                                                                  v
                                                     +------------------------------------+
                                                     | STAGE 3: CONTENT & SCAM TRIGGERS   |
                                                     | Urgent refund, UPI, KYC, Vishing   |
                                                     +------------------------------------+
                                                                  |
                                                                  v
                                                     +------------------------------------+
                                                     | STAGE 4: CONTEXTUAL BEHAVIOR &     |
                                                     | APP STORE PERMISSION TROJAN ENGINE |
                                                     +------------------------------------+
                                                                  |
                                                                  v
                                                     +------------------------------------+
                                                     | STAGE 5: COMPOSITE SCORING ENGINE  |
                                                     | S = 0.45*Id + 0.35*Cont + 0.20*Ctx |
                                                     +------------------------------------+
                                                                  |
                                            +---------------------+---------------------+
                                            |                     |                     |
                                            v                     v                     v
                                    [CRITICAL >=85%]        [HIGH >=60%]          [SAFE <30%]
                                            |                     |                     |
                                            v                     v                     v
                                  Auto-Gen Takedown      SOC Priority Queue        Benign Log
        ```
        """
    )

    col_arch1, col_arch2 = st.columns(2)

    with col_arch1:
        st.markdown("#### 1. Multi-Stage Detection Pipeline")
        st.markdown(
            """
            - **Stage 1: Pre-Flight Strict Exclusion Engine (0% FP Target)**
              - Evaluates canonical brand registers (`@Paytm`, `@PaytmCare`, `@PaytmMoney`, `net.one97.paytm`, etc.).
              - Exact match triggers deterministic bypass returning strictly `0.0% Risk` and `OFFICIAL_SAFE`.
            - **Stage 2: Look-Alike & Homoglyph De-obfuscation Engine**
              - Unicode NFKD decomposition + Cyrillic/Greek cross-script mapping (e.g. Cyrillic `Р` U+0420 $\\to$ `p`).
              - Leetspeak translation table (`'0'->'o'`, `'4'->'a'`, `'1'->'l'`, `'$'->'s'`, `'@'->'a'`).
              - High-risk token padding isolation (`refund`, `care`, `support`, `upi`, `kyc`, `helpline`).
              - Levenshtein & RapidFuzz token distance to brand stem `paytm`.
            - **Stage 3: NLP Phishing & Scam Intent Engine**
              - Regex evaluation of social bios and app descriptions.
              - Flags urgent financial triggers: `"urgent refund"`, `"DM for stuck UPI"`, `"KYC update"`, `"send OTP"`.
              - Out-of-band redirect tracking (`wa.me`, `t.me`, suspicious shortlinks).
            - **Stage 4: App Store Namespace & Permission Trojan Engine**
              - Flags reverse-DNS namespace squatting (`net.one97.paytm.*`, `com.paytm.*`).
              - Verifies publisher authentication against `One97 Communications Ltd.`.
              - Identifies dangerous spyware permissions (`READ_SMS`, `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`).
            """
        )

    with col_arch2:
        st.markdown("#### 2. Mathematical Scoring Formula")
        st.latex(r"S_{\text{composite}} = w_{\text{id}} \cdot S_{\text{identity}} + w_{\text{content}} \cdot S_{\text{content}} + w_{\text{context}} \cdot S_{\text{context}}")
        st.markdown(
            """
            Where weights are configured as:
            - **$w_{\\text{id}} = 0.45$** (Identity, Homoglyph, Leetspeak, Token padding)
            - **$w_{\\text{content}} = 0.35$** (Scam triggers, UPI vectors, Credential harvesting)
            - **$w_{\\text{context}} = 0.20$** (Unverified status, audience anomaly, developer mismatch)

            **SOC Amplification & Override Rules:**
            1. $\\text{IsWhitelisted} \\implies S_{\\text{composite}} = 0.0$ (`OFFICIAL_SAFE`).
            2. $\\text{StemDetected} \\land \\text{PaddingHijack} \\land \\text{ScamTrigger} \\implies S_{\\text{composite}} \\ge 88.0$ (`CRITICAL`).
            3. $\\text{NamespaceSquatted} \\lor (\\text{PublisherMismatch} \\land \\text{SmsPermission}) \\implies S_{\\text{composite}} \\ge 88.0$ (`CRITICAL`).
            4. $\\text{BenignConfirmed} \\land \\text{NoScamTriggers} \\implies S_{\\text{composite}} \\le 15.0$ (`SAFE`).
            """
        )

        st.markdown("#### 3. Takedown & Incident Response SLA")
        st.markdown(
            r"""
            | Risk Tier | Score Range | Operational SLA | Automated Response |
            | :--- | :--- | :--- | :--- |
            | **Critical** | $\ge 85\%$ | **< 15 Minutes** | Auto-generate DMCA / Platform Abuse notice + Forensic SHA-256 evidence |
            | **High** | $\ge 60\%$ | **< 1 Hour** | Priority SOC Queue dispatch, Cease-and-Desist letter draft |
            | **Medium** | $\ge 30\%$ | **< 24 Hours** | Add to automated telemetry watch-list & periodic re-scan |
            | **Safe** | $< 30\%$ | N/A | Benign log archive; zero disruption |
            """
        )


# ==============================================================================
# TAB 4: BRAND WHITELIST & ASSETS
# ==============================================================================
with tab4:
    st.subheader("Configured Brand Assets & Whitelist Registers")
    st.write(f"Managing assets for **{BRAND_NAME} ({PARENT_COMPANY})**")

    col_w1, col_w2 = st.columns(2)

    with col_w1:
        st.markdown("#### 📱 Registered Canonical Social Handles")
        for h in sorted(list(OFFICIAL_HANDLES)):
            if h.startswith("@"):
                st.code(h, language="text")

        st.markdown("#### 📦 Registered Mobile App Package Identifiers")
        for p in sorted(list(OFFICIAL_PACKAGE_IDS)):
            st.code(p, language="text")

    with col_w2:
        st.markdown("#### 🏢 Authorized Publisher Names")
        for pub in sorted(list(OFFICIAL_PUBLISHERS)):
            st.code(pub, language="text")

        st.markdown("#### ⚠️ High-Risk Brand Hijacking Padding Tokens")
        st.write(", ".join([f"`{t}`" for t in sorted(list(HIGH_RISK_PADDING_TOKENS))]))

st.write("")
st.divider()
st.caption("Paytm Digital Risk Protection Platform | SOC Engineering Standard | Version 2.4.0-PROD")
