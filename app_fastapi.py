"""
Paytm Digital Risk Protection (DRP) Platform - Standalone FastAPI Server
Provides REST APIs and an embedded high-performance Modern SOC Dashboard.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import json
from typing import List, Optional
import uvicorn

from config.brand_config import BRAND_NAME, PARENT_COMPANY
from core.threat_orchestrator import ThreatOrchestrator
from data.test_datasets import TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES

app = FastAPI(
    title="Paytm DRP Platform API",
    description="Digital Risk Protection Platform for Paytm / One97 Communications Ltd.",
    version="2.4.0",
)

orchestrator = ThreatOrchestrator()


class SocialScanRequest(BaseModel):
    handle: str
    display_name: str = ""
    bio: str = ""
    platform: str = "Twitter/X"
    is_verified: bool = False
    followers_count: int = 0
    external_urls: List[str] = []


class AppScanRequest(BaseModel):
    app_title: str
    package_id: str
    publisher_name: str
    app_store: str = "Google Play Store"
    permissions: List[str] = []
    downloads_count: int = 0
    rating: float = 0.0
    description: str = ""


@app.get("/api/summary")
def get_summary():
    batch = orchestrator.batch_process(TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES)
    return batch["summary"]


@app.get("/api/threats")
def get_all_threats():
    return orchestrator.batch_process(TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES)


@app.post("/api/scan/social")
def scan_social(req: SocialScanRequest):
    return orchestrator.scan_social_candidate(req.model_dump())


@app.post("/api/scan/app")
def scan_app(req: AppScanRequest):
    return orchestrator.scan_app_candidate(req.model_dump())


# Embedded High-Fidelity Modern Dashboard UI
@app.get("/", response_class=HTMLResponse)
def index_dashboard():
    batch = orchestrator.batch_process(TEST_SOCIAL_CANDIDATES, TEST_APP_CANDIDATES)
    summary = batch["summary"]
    socials_json = json.dumps(batch["social_results"])
    apps_json = json.dumps(batch["app_results"])

    html_content = f"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paytm DRP Platform | SOC Threat Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'Plus Jakarta Sans', sans-serif; background-color: #0b0f19; }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
    </style>
</head>
<body class="text-slate-100 min-h-screen">
    <!-- Top Navbar -->
    <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div class="flex items-center space-x-3">
            <div class="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold text-xl">🛡️</div>
            <div>
                <h1 class="font-bold text-lg text-white tracking-tight">Paytm DRP Platform <span class="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 ml-2 font-mono">SOC PROD v2.4</span></h1>
                <p class="text-xs text-slate-400">Anchor Brand: <span class="text-cyan-300 font-semibold">{BRAND_NAME} ({PARENT_COMPANY})</span> | Target: Social & App Store Impersonation</p>
            </div>
        </div>
        <div class="flex items-center space-x-4">
            <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                <span class="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span> False Positive Target: 0.0% Enforced
            </span>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 py-8 space-y-8">
        <!-- KPI Row -->
        <div class="grid grid-cols-2 md:grid-cols-6 gap-4">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">TOTAL MONITORED</p>
                <p class="text-2xl font-bold text-cyan-400 mt-1">{summary['total_monitored']}</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">CRITICAL ALERTS</p>
                <p class="text-2xl font-bold text-rose-500 mt-1">{summary['critical_threats']}</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">HIGH RISKS</p>
                <p class="text-2xl font-bold text-amber-500 mt-1">{summary['high_risk']}</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">OFFICIAL SAFE</p>
                <p class="text-2xl font-bold text-emerald-400 mt-1">{summary['official_safe_count']}</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">FP RATE</p>
                <p class="text-2xl font-bold text-emerald-300 mt-1">{summary['false_positive_rate']}</p>
            </div>
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm">
                <p class="text-xs font-semibold text-slate-400 tracking-wider">TAKEDOWNS READY</p>
                <p class="text-2xl font-bold text-rose-400 mt-1">{summary['takedowns_ready']}</p>
            </div>
        </div>

        <!-- Navigation Tabs -->
        <div class="border-b border-slate-800 flex space-x-6 text-sm font-semibold">
            <button onclick="switchTab('feed')" id="tab-btn-feed" class="pb-3 border-b-2 border-cyan-400 text-cyan-400">Threat Matrix & Inspector</button>
            <button onclick="switchTab('simulator')" id="tab-btn-simulator" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200">Live Threat Simulator</button>
            <button onclick="switchTab('architecture')" id="tab-btn-architecture" class="pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200">Architecture & Detection Logic</button>
        </div>

        <!-- TAB 1: THREAT MATRIX -->
        <div id="tab-content-feed" class="space-y-6">
            <div class="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
                <div class="p-4 bg-slate-950/50 border-b border-slate-800 flex justify-between items-center">
                    <h2 class="font-bold text-white text-base">Evaluated Threat Entities (Social & App Store)</h2>
                    <span class="text-xs text-slate-400">Click any row to inspect deep forensics & takedown</span>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full text-left text-sm text-slate-300">
                        <thead class="text-xs text-slate-400 uppercase bg-slate-950/30 border-b border-slate-800">
                            <tr>
                                <th class="px-4 py-3">Channel</th>
                                <th class="px-4 py-3">Candidate Identifier</th>
                                <th class="px-4 py-3">Display Name / Title</th>
                                <th class="px-4 py-3">Risk Tier</th>
                                <th class="px-4 py-3">Risk Score</th>
                                <th class="px-4 py-3">Status</th>
                                <th class="px-4 py-3">Action</th>
                            </tr>
                        </thead>
                        <tbody id="threat-table-body" class="divide-y divide-slate-800/60 font-mono text-xs">
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Detail Modal / Inspector Box -->
            <div id="inspector-card" class="hidden bg-slate-900 border border-cyan-500/40 rounded-xl p-6 space-y-4 shadow-xl">
                <div class="flex justify-between items-start">
                    <div>
                        <span id="inspect-tier-badge" class="px-2.5 py-1 rounded text-xs font-bold uppercase"></span>
                        <h3 id="inspect-title" class="text-xl font-bold text-white mt-2"></h3>
                        <p id="inspect-subtitle" class="text-xs text-slate-400"></p>
                    </div>
                    <button onclick="closeInspector()" class="text-slate-400 hover:text-white text-sm bg-slate-800 px-3 py-1 rounded">Close</button>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                    <div class="space-y-2 text-xs">
                        <p class="text-slate-400 font-semibold uppercase">Forensic Summary</p>
                        <p id="inspect-evidence" class="text-slate-200 bg-slate-950 p-3 rounded border border-slate-800"></p>
                        <p id="inspect-action" class="text-cyan-400 font-medium"></p>
                    </div>
                    <div class="space-y-2 text-xs">
                        <p class="text-slate-400 font-semibold uppercase">Detection Indicators</p>
                        <div id="inspect-tags" class="space-y-1"></div>
                    </div>
                </div>
                <div id="takedown-box" class="pt-4 border-t border-slate-800 hidden">
                    <p class="text-xs font-bold text-rose-400 uppercase">Automated Takedown Notice Package</p>
                    <textarea id="takedown-text" readonly class="w-full mt-2 h-44 bg-slate-950 text-cyan-300 font-mono text-xs p-3 rounded border border-slate-800"></textarea>
                </div>
            </div>
        </div>

        <!-- TAB 2: LIVE SIMULATOR -->
        <div id="tab-content-simulator" class="hidden space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Social Media Scanner -->
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                    <h3 class="font-bold text-white text-base flex items-center">
                        <span class="w-2 h-2 rounded-full bg-cyan-400 mr-2"></span> Social Media Candidate Scanner
                    </h3>
                    <div class="space-y-3 text-xs">
                        <div>
                            <label class="text-slate-400 block mb-1">Candidate Handle</label>
                            <input id="sim-handle" type="text" value="@P4ytm_Helpline_Desk" class="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono">
                        </div>
                        <div>
                            <label class="text-slate-400 block mb-1">Display Name</label>
                            <input id="sim-display" type="text" value="Paytm Customer Support" class="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono">
                        </div>
                        <div>
                            <label class="text-slate-400 block mb-1">Bio Text</label>
                            <textarea id="sim-bio" rows="3" class="w-full bg-slate-950 border border-slate-800 rounded p-2 text-white font-mono">Official 24x7 Support. DM for stuck UPI refund, KYC update issues or WhatsApp +919876543210</textarea>
                        </div>
                        <button onclick="runSocialSim()" class="w-full py-2.5 rounded bg-cyan-600 hover:bg-cyan-500 font-semibold text-white">Execute Real-Time Scan</button>
                    </div>
                </div>

                <!-- Simulation Output -->
                <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                    <h3 class="font-bold text-white text-base">Real-Time Forensic Scan Output</h3>
                    <div id="sim-output" class="text-xs text-slate-400 p-4 bg-slate-950 rounded border border-slate-800 min-h-[260px] font-mono">
                        Ready. Click "Execute Real-Time Scan" to analyze candidate across all engines.
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 3: ARCHITECTURE & DETECTION LOGIC -->
        <div id="tab-content-architecture" class="hidden space-y-6">
            <div class="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
                <h3 class="font-bold text-white text-lg">Digital Risk Protection Platform - Engineering Architecture</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-slate-300">
                    <div class="space-y-4 bg-slate-950 p-4 rounded-xl border border-slate-800">
                        <h4 class="font-bold text-cyan-400 text-sm">Detection Pipeline Stages</h4>
                        <ol class="list-decimal pl-4 space-y-2">
                            <li><strong class="text-white">Strict Deterministic Whitelist (0% FP):</strong> Pre-flight verification against canonical brand handles and official publisher signatures. Exact matches immediately return 0.0% Risk / OFFICIAL_SAFE.</li>
                            <li><strong class="text-white">Unicode & Leetspeak De-obfuscation:</strong> Converts Cyrillic/Greek homoglyphs (e.g. Cyrillic 'Р' U+0420) and leetspeak substitution ('4'->'a', '0'->'o', '1'->'l', '$'->'s').</li>
                            <li><strong class="text-white">Token Padding & Hijacking:</strong> Extracts brand stem ('paytm') and detects collision with high-risk financial padding ('refund', 'care', 'upi', 'kyc', 'helpline').</li>
                            <li><strong class="text-white">NLP Phishing Triggers:</strong> Evaluates bios and app descriptions for social engineering phrases ('urgent refund', 'DM for stuck UPI', 'send OTP').</li>
                            <li><strong class="text-white">App Store Namespace & Permissions:</strong> Flags unauthorized package namespaces ('net.one97.paytm.*'), publisher mismatches, and spyware permissions (READ_SMS, overlay).</li>
                        </ol>
                    </div>
                    <div class="space-y-4 bg-slate-950 p-4 rounded-xl border border-slate-800">
                        <h4 class="font-bold text-cyan-400 text-sm">Mathematical Risk Scoring Model</h4>
                        <div class="p-3 bg-slate-900 rounded font-mono text-cyan-300 text-xs">
                            S_composite = (0.45 * S_identity) + (0.35 * S_content) + (0.20 * S_context)
                        </div>
                        <ul class="list-disc pl-4 space-y-2">
                            <li><strong class="text-white">Critical (>=85%):</strong> Confirmed brand impersonator + scam trigger OR App namespace spoofing. Auto-triggers formal takedown.</li>
                            <li><strong class="text-white">High (>=60%):</strong> Trademark infringement or unauthorized publisher. Escalated to SOC analyst queue.</li>
                            <li><strong class="text-white">Medium (>=30%):</strong> Suspicious keyword presence or low-confidence lookalike. Added to continuous telemetry watchlist.</li>
                            <li><strong class="text-white">Safe (&lt;30%):</strong> Benign third party (e.g. 'Payton Miller') or verified official asset. Zero disruption.</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        const socialData = {socials_json};
        const appData = {apps_json};
        const allCandidates = [...socialData.map(s => ({{...s, _type: 'social'}})), ...appData.map(a => ({{...a, _type: 'app'}}))];

        function renderTable() {{
            const tbody = document.getElementById('threat-table-body');
            tbody.innerHTML = '';
            allCandidates.forEach((item, idx) => {{
                const tr = document.createElement('tr');
                tr.className = 'hover:bg-slate-800/40 cursor-pointer transition';
                tr.onclick = () => inspectItem(idx);

                let badgeClass = 'bg-slate-800 text-slate-300';
                if (item.risk_tier === 'CRITICAL') badgeClass = 'bg-rose-950 text-rose-400 border border-rose-800';
                else if (item.risk_tier === 'HIGH') badgeClass = 'bg-amber-950 text-amber-400 border border-amber-800';
                else if (item.risk_tier === 'OFFICIAL_SAFE') badgeClass = 'bg-cyan-950 text-cyan-400 border border-cyan-800';
                else if (item.risk_tier === 'SAFE') badgeClass = 'bg-emerald-950 text-emerald-400 border border-emerald-800';

                const idStr = item.handle || item.package_id;
                const nameStr = item.display_name || item.app_title;
                const chan = item._type === 'social' ? 'Social (' + item.platform + ')' : 'App (' + item.app_store + ')';

                tr.innerHTML = `
                    <td class="px-4 py-3 font-sans text-slate-400">${{chan}}</td>
                    <td class="px-4 py-3 text-white font-semibold">${{idStr}}</td>
                    <td class="px-4 py-3 font-sans">${{nameStr}}</td>
                    <td class="px-4 py-3"><span class="px-2 py-0.5 rounded ${{badgeClass}} font-bold text-[10px]">${{item.risk_tier}}</span></td>
                    <td class="px-4 py-3 font-bold">${{item.risk_score}}%</td>
                    <td class="px-4 py-3">${{item.is_whitelisted ? '<span class="text-cyan-400">WHITELIST (0% FP)</span>' : '<span class="text-slate-400">UNREGISTERED</span>'}}</td>
                    <td class="px-4 py-3 font-sans text-cyan-400">${{item.recommended_action.split(':')[0]}}</td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function inspectItem(idx) {{
            const item = allCandidates[idx];
            const card = document.getElementById('inspector-card');
            card.classList.remove('hidden');

            document.getElementById('inspect-title').innerText = item.handle || item.package_id;
            document.getElementById('inspect-subtitle').innerText = (item.display_name || item.app_title) + ' | ' + (item.platform || item.app_store);
            document.getElementById('inspect-evidence').innerText = item.evidence_summary;
            document.getElementById('inspect-action').innerText = item.recommended_action;

            const badge = document.getElementById('inspect-tier-badge');
            badge.innerText = item.risk_tier + ' (' + item.risk_score + '%)';
            badge.className = 'px-2.5 py-1 rounded text-xs font-bold uppercase ' + (item.risk_tier === 'CRITICAL' ? 'bg-rose-900 text-rose-200' : 'bg-cyan-900 text-cyan-200');

            const tagsContainer = document.getElementById('inspect-tags');
            tagsContainer.innerHTML = '';
            if (item.matched_scam_triggers) {{
                item.matched_scam_triggers.forEach(t => {{
                    tagsContainer.innerHTML += `<div class="p-1.5 bg-rose-950/60 border border-rose-900 text-rose-300 rounded font-mono">🚨 Trigger: ${{t.label}}</div>`;
                }});
            }}
            if (item.dangerous_permissions_found) {{
                item.dangerous_permissions_found.forEach(p => {{
                    tagsContainer.innerHTML += `<div class="p-1.5 bg-amber-950/60 border border-amber-900 text-amber-300 rounded font-mono">⚠️ Permission: ${{p}}</div>`;
                }});
            }}

            const takedownBox = document.getElementById('takedown-box');
            if (item.takedown_notice) {{
                takedownBox.classList.remove('hidden');
                document.getElementById('takedown-text').value = item.takedown_notice.notice_text;
            }} else {{
                takedownBox.classList.add('hidden');
            }}

            card.scrollIntoView({{ behavior: 'smooth' }});
        }}

        function closeInspector() {{
            document.getElementById('inspector-card').classList.add('hidden');
        }}

        function switchTab(tabId) {{
            ['feed', 'simulator', 'architecture'].forEach(t => {{
                document.getElementById('tab-content-' + t).classList.add('hidden');
                document.getElementById('tab-btn-' + t).className = 'pb-3 border-b-2 border-transparent text-slate-400 hover:text-slate-200';
            }});
            document.getElementById('tab-content-' + tabId).classList.remove('hidden');
            document.getElementById('tab-btn-' + tabId).className = 'pb-3 border-b-2 border-cyan-400 text-cyan-400';
        }}

        async function runSocialSim() {{
            const handle = document.getElementById('sim-handle').value;
            const display = document.getElementById('sim-display').value;
            const bio = document.getElementById('sim-bio').value;
            const outDiv = document.getElementById('sim-output');
            outDiv.innerHTML = 'Executing scan...';

            try {{
                const res = await fetch('/api/scan/social', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ handle, display_name: display, bio }})
                }});
                const data = await res.json();
                outDiv.innerHTML = JSON.stringify(data, null, 2);
            }} catch(e) {{
                outDiv.innerHTML = 'Error communicating with detection engine API: ' + e;
            }}
        }}

        renderTable();
    </script>
</body>
</html>"""
    return html_content


if __name__ == "__main__":
    uvicorn.run("app_fastapi:app", host="127.0.0.1", port=8000, reload=True)
