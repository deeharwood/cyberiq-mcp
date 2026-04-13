"""
CyberIQ Security MCP Server
====================================
An MCP server that gives any AI agent instant access to:
- NVD vulnerability data with CVSS scores
- CISA KEV catalog with BOD 22-01 status
- EPSS exploit probability scores
- MITRE ATT&CK technique mapping
- MITRE ATLAS adversarial AI technique lookup
- SAFE-AI NIST 800-53 control mappings for AI systems
- POA&M generation

Deploy: Railway, Docker, or local
Protocol: Streamable HTTP (remote) or stdio (local)

Usage with Claude Desktop:
  Add to claude_desktop_config.json:
  {
    "mcpServers": {
      "cyberiq": {
        "command": "python",
        "args": ["cyberiq_mcp_server.py"]
      }
    }
  }

Usage remote (Streamable HTTP):
  python cyberiq_mcp_server.py --transport http --port 8100
"""

import os
import re
import json
import httpx
from datetime import datetime, timedelta
from typing import Optional
from mcp.server.fastmcp import FastMCP

# ATLAS / SAFE-AI Knowledge Base
try:
    from atlas_knowledge import ATLAS_TACTICS, ATLAS_TECHNIQUES, SAFE_AI_THREATS, get_atlas_context
    print("✅ ATLAS/SAFE-AI knowledge base loaded")
except ImportError:
    print("⚠️  atlas_knowledge.py not found - ATLAS tools disabled")
    ATLAS_TACTICS = {}
    ATLAS_TECHNIQUES = {}
    SAFE_AI_THREATS = {}
    def get_atlas_context(q): return "ATLAS knowledge base not loaded"

# ========================================
# Initialize MCP Server
# ========================================
mcp = FastMCP("CyberIQ Security")

# ========================================
# REST Test Endpoints (browser-friendly)
# ========================================
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse, HTMLResponse

async def test_page(request):
    """Browser-based test page for MCP tools"""
    html = """<!DOCTYPE html>
<html><head><title>CyberIQ MCP Server</title>
<style>
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #333; padding: 40px; min-height: 100vh; margin: 0; }
.container { max-width: 800px; margin: 0 auto; }
h1 { color: white; font-size: 32px; text-shadow: 0 2px 10px rgba(0,0,0,0.2); }
h2 { color: white; margin-top: 30px; font-size: 20px; text-shadow: 0 1px 4px rgba(0,0,0,0.2); }
a { color: #667eea; font-weight: 500; }
p { color: rgba(255,255,255,0.9); }
ul { background: white; border-radius: 12px; padding: 20px 20px 20px 40px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
li { padding: 4px 0; color: #444; }
li a { color: #667eea; }
pre { background: white; color: #333; padding: 16px; border-radius: 12px; overflow-x: auto; font-size: 13px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
.badge { background: white; color: #667eea; padding: 5px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; display: inline-block; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
.footer { text-align: center; padding: 30px 0 10px; color: rgba(255,255,255,0.6); font-size: 13px; }
.footer a { color: white; text-decoration: none; }
</style></head><body>
<div class="container">
<h1>&#128737; CyberIQ Security MCP Server</h1>
<p><span class="badge">LIVE</span> &nbsp; Powered by CyberIQ &mdash; <a href="https://cyberiq.co" style="color:white;">cyberiq.co</a></p>

<h2>MCP Endpoint</h2>
<pre>SSE: """ + request.url.scheme + "://" + request.headers.get("host", "") + """/sse</pre>
<p>Connect any MCP client (Claude Desktop, ChatGPT, Cursor, etc.) to this endpoint.</p>

<h2>Test Tools (REST API)</h2>
<ul>
<li><a href="/api/test/lookup/CVE-2024-3400">/api/test/lookup/CVE-2024-3400</a> &mdash; CVE lookup with KEV + EPSS</li>
<li><a href="/api/test/lookup/CVE-2024-21887">/api/test/lookup/CVE-2024-21887</a> &mdash; Ivanti Connect Secure</li>
<li><a href="/api/test/kev/ransomware">/api/test/kev/ransomware</a> &mdash; Ransomware KEVs</li>
<li><a href="/api/test/kev/Microsoft">/api/test/kev/Microsoft</a> &mdash; Microsoft KEVs</li>
<li><a href="/api/test/epss/CVE-2024-3400,CVE-2024-21887">/api/test/epss/CVE-2024-3400,CVE-2024-21887</a> &mdash; Batch EPSS</li>
<li><a href="/api/test/threat/Volt Typhoon">/api/test/threat/Volt Typhoon</a> &mdash; Threat actor lookup</li>
<li><a href="/api/test/threat/T1190">/api/test/threat/T1190</a> &mdash; ATT&CK technique</li>
<li><a href="/api/test/atlas/technique/AML.T0051">/api/test/atlas/technique/AML.T0051</a> &mdash; ATLAS: Prompt Injection</li>
<li><a href="/api/test/atlas/technique/AML.T0054">/api/test/atlas/technique/AML.T0054</a> &mdash; ATLAS: LLM Jailbreak</li>
<li><a href="/api/test/atlas/threats">/api/test/atlas/threats</a> &mdash; All SAFE-AI threats</li>
<li><a href="/api/test/atlas/tactics">/api/test/atlas/tactics</a> &mdash; All ATLAS tactics</li>
</ul>

<h2>Available MCP Tools</h2>
<pre>
1. lookup_cve            &mdash; Full CVE enrichment (NVD + KEV + EPSS)
2. check_kev_status      &mdash; Search CISA KEV catalog
3. get_epss_scores       &mdash; Exploit probability scores
4. search_threats        &mdash; MITRE ATT&CK + threat actors
5. generate_poam         &mdash; POA&M entry generation
6. lookup_atlas_technique &mdash; MITRE ATLAS technique lookup with SAFE-AI controls
7. search_atlas_threats  &mdash; Search SAFE-AI threats and NIST 800-53 mappings
8. get_atlas_overview    &mdash; ATLAS tactics and techniques summary
</pre>

<h2>Data Sources</h2>
<pre>
- NIST NVD (National Vulnerability Database)
- CISA KEV (Known Exploited Vulnerabilities)
- FIRST.org EPSS (Exploit Prediction Scoring System)
- MITRE ATT&CK Framework
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- MITRE SAFE-AI Framework (NIST 800-53 control mappings for AI)
</pre>
<div class="footer">Powered by <a href="https://cyberiq.co">CyberIQ</a> &mdash; AI-Powered Cybersecurity Intelligence</div>
</div>
</body></html>"""
    return HTMLResponse(html)

async def test_lookup(request):
    cve_id = request.path_params["cve_id"]
    result = await lookup_cve(cve_id)
    return JSONResponse(result)

async def test_kev(request):
    query = request.path_params["query"]
    result = await check_kev_status(query)
    return JSONResponse(result)

async def test_epss(request):
    cve_ids = request.path_params["cve_ids"]
    result = await get_epss_scores(cve_ids)
    return JSONResponse(result)

async def test_threat(request):
    query = request.path_params["query"]
    result = await search_threats(query)
    return JSONResponse(result)

async def test_atlas_technique(request):
    technique_id = request.path_params["technique_id"]
    result = await lookup_atlas_technique(technique_id)
    return JSONResponse(result)

async def test_atlas_threats(request):
    result = await search_atlas_threats("all")
    return JSONResponse(result)

async def test_atlas_tactics(request):
    result = await get_atlas_overview()
    return JSONResponse(result)

# Mount test routes on the MCP server's underlying Starlette app
_test_routes = [
    Route("/", test_page),
    Route("/api/test/lookup/{cve_id}", test_lookup),
    Route("/api/test/kev/{query:path}", test_kev),
    Route("/api/test/epss/{cve_ids}", test_epss),
    Route("/api/test/threat/{query:path}", test_threat),
    Route("/api/test/atlas/technique/{technique_id}", test_atlas_technique),
    Route("/api/test/atlas/threats", test_atlas_threats),
    Route("/api/test/atlas/tactics", test_atlas_tactics),
]

# Optional: Anthropic API key for POA&M generation
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ========================================
# Data Fetching Helpers
# ========================================

# Simple in-memory cache
_cache = {}
_cache_ttl = {}

def cache_get(key):
    if key in _cache and _cache_ttl.get(key, 0) > datetime.now().timestamp():
        return _cache[key]
    return None

def cache_set(key, value, ttl=3600):
    _cache[key] = value
    _cache_ttl[key] = datetime.now().timestamp() + ttl


async def fetch_kev_data() -> dict:
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    cached = cache_get("kev_data")
    if cached:
        return cached

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        resp.raise_for_status()
        data = resp.json()
        cache_set("kev_data", data, 3600)
        return data


async def fetch_epss_score(cve_id: str) -> dict:
    """Fetch EPSS score from FIRST.org"""
    cached = cache_get(f"epss_{cve_id}")
    if cached:
        return cached

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"https://api.first.org/data/v1/epss?cve={cve_id}")
        if resp.status_code == 200:
            data = resp.json()
            if data.get("data"):
                item = data["data"][0]
                result = {
                    "score": round(float(item["epss"]) * 100, 2),
                    "percentile": round(float(item.get("percentile", 0)) * 100, 1)
                }
                cache_set(f"epss_{cve_id}", result, 3600)
                return result
    return {"score": "N/A", "percentile": "N/A"}


async def fetch_nvd_cve(cve_id: str) -> Optional[dict]:
    """Fetch CVE details from NVD API"""
    cached = cache_get(f"nvd_{cve_id}")
    if cached:
        return cached

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
            headers={"User-Agent": "CyberIQ-MCP/1.0 (+https://cyberiq.co)"}
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        # Description
        desc = ""
        for d in cve_data.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS
        metrics = cve_data.get("metrics", {})
        cvss_score = 0
        cvss_severity = "UNKNOWN"
        for key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_score = metrics[key][0]["cvssData"].get("baseScore", 0)
                cvss_severity = metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                break

        # Vendor/Product from CPE
        vendors, products = set(), set()
        for config in cve_data.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    if cpe.get("vulnerable"):
                        parts = cpe.get("criteria", "").split(":")
                        if len(parts) >= 5:
                            if parts[3] and parts[3] != "*": vendors.add(parts[3])
                            if parts[4] and parts[4] != "*": products.add(parts[4])

        # CWEs
        cwes = []
        for weakness in cve_data.get("weaknesses", []):
            for wd in weakness.get("description", []):
                if wd.get("value", "").startswith("CWE-"):
                    cwes.append(wd["value"])

        result = {
            "cve_id": cve_id,
            "description": desc,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "vendor": sorted(vendors)[0] if vendors else "Unknown",
            "product": sorted(products)[0] if products else "Unknown",
            "cwes": cwes,
            "published": cve_data.get("published", "")[:10],
        }
        cache_set(f"nvd_{cve_id}", result, 3600)
        return result


# ========================================
# MITRE ATT&CK Knowledge Base
# ========================================

MITRE_TECHNIQUES = {
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion, Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution, Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1556": {"name": "Modify Authentication Process", "tactic": "Credential Access"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
}

APT_GROUPS = {
    "volt typhoon": {
        "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda"],
        "origin": "China (PRC)",
        "targets": "US critical infrastructure — energy, water, telecom, transportation",
        "techniques": ["T1190", "T1133", "T1078", "T1059", "T1027"],
        "tools": "Living-off-the-land (LOTL), ntdsutil, netsh, PowerShell"
    },
    "salt typhoon": {
        "aliases": ["GhostEmperor", "FamousSparrow"],
        "origin": "China (PRC)",
        "targets": "Telecommunications providers, ISPs, government agencies",
        "techniques": ["T1190", "T1078", "T1021", "T1071"],
        "tools": "Demodex rootkit, SparrowDoor, custom backdoors"
    },
    "lazarus group": {
        "aliases": ["HIDDEN COBRA", "Zinc", "APT38"],
        "origin": "North Korea (DPRK)",
        "targets": "Financial institutions, cryptocurrency, defense, healthcare",
        "techniques": ["T1190", "T1059", "T1055", "T1486"],
        "tools": "FALLCHILL, Manuscrypt, BLINDINGCAN, custom RATs"
    },
    "cozy bear": {
        "aliases": ["APT29", "Midnight Blizzard", "The Dukes"],
        "origin": "Russia (SVR)",
        "targets": "Government, think tanks, NGOs, technology companies",
        "techniques": ["T1078", "T1556", "T1027", "T1071"],
        "tools": "SUNBURST, Cobalt Strike, EnvyScout, custom loaders"
    },
    "scattered spider": {
        "aliases": ["UNC3944", "Octo Tempest", "0ktapus"],
        "origin": "US/UK (financially motivated)",
        "targets": "Telecom, hospitality, tech, financial services",
        "techniques": ["T1078", "T1110", "T1548", "T1486"],
        "tools": "Social engineering, SIM swapping, ALPHV/BlackCat ransomware"
    },
}


# ========================================
# MCP TOOLS
# ========================================

@mcp.tool()
async def lookup_cve(cve_id: str) -> dict:
    """
    Look up a CVE by ID and return enriched data including NVD details,
    CISA KEV status, EPSS exploit probability, and CVSS score.
    Use this for any question about a specific vulnerability.

    Args:
        cve_id: The CVE identifier (e.g., CVE-2024-3400)
    """
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        return {"error": f"Invalid CVE ID format: {cve_id}. Expected format: CVE-YYYY-NNNNN"}

    result = {"cve_id": cve_id}

    # NVD data
    nvd = await fetch_nvd_cve(cve_id)
    if nvd:
        result.update({
            "description": nvd["description"],
            "cvss_score": nvd["cvss_score"],
            "cvss_severity": nvd["cvss_severity"],
            "vendor": nvd["vendor"],
            "product": nvd["product"],
            "cwes": nvd["cwes"],
            "published": nvd["published"],
        })
    else:
        result["nvd_status"] = "Not found in NVD"

    # CISA KEV
    kev_data = await fetch_kev_data()
    kev_match = next(
        (v for v in kev_data.get("vulnerabilities", [])
         if v.get("cveID", "").upper() == cve_id),
        None
    )
    if kev_match:
        result["kev_listed"] = True
        result["kev_due_date"] = kev_match.get("dueDate", "N/A")
        result["kev_required_action"] = kev_match.get("requiredAction", "N/A")
        result["kev_ransomware_use"] = kev_match.get("knownRansomwareCampaignUse", "Unknown")
        result["kev_date_added"] = kev_match.get("dateAdded", "N/A")
        result["bod_22_01"] = "MANDATORY remediation required"
    else:
        result["kev_listed"] = False

    # EPSS
    epss = await fetch_epss_score(cve_id)
    result["epss_score_percent"] = epss["score"]
    result["epss_percentile"] = epss["percentile"]

    # Priority assessment
    cvss = result.get("cvss_score", 0)
    if result.get("kev_listed"):
        result["priority"] = "CRITICAL — On CISA KEV, mandatory remediation"
    elif cvss >= 9.0:
        result["priority"] = "CRITICAL — CVSS 9.0+"
    elif cvss >= 7.0:
        result["priority"] = "HIGH"
    elif cvss >= 4.0:
        result["priority"] = "MEDIUM"
    else:
        result["priority"] = "LOW"

    return result


@mcp.tool()
async def check_kev_status(query: str) -> dict:
    """
    Check the CISA Known Exploited Vulnerabilities (KEV) catalog.
    Can search by CVE ID, vendor name, or product name.
    Returns matching KEV entries with BOD 22-01 remediation details.

    Args:
        query: CVE ID (e.g., CVE-2024-3400), vendor (e.g., Microsoft), or product name
    """
    kev_data = await fetch_kev_data()
    vulns = kev_data.get("vulnerabilities", [])
    query_upper = query.upper().strip()
    query_lower = query.lower().strip()

    matches = []

    # Direct CVE lookup
    if re.match(r'^CVE-\d{4}-\d+$', query_upper):
        matches = [v for v in vulns if v.get("cveID", "").upper() == query_upper]
    else:
        # Search vendor, product, name, description
        for v in vulns:
            searchable = f"{v.get('vendorProject', '')} {v.get('product', '')} {v.get('vulnerabilityName', '')} {v.get('shortDescription', '')}".lower()
            if query_lower in searchable:
                matches.append(v)

    # Also check ransomware filter
    if "ransomware" in query_lower:
        matches = [v for v in vulns if v.get("knownRansomwareCampaignUse", "").lower() == "known"]

    return {
        "query": query,
        "total_kev_entries": len(vulns),
        "matches_found": len(matches),
        "results": matches[:25],  # Cap at 25 for readability
        "note": f"Showing first 25 of {len(matches)} results" if len(matches) > 25 else None
    }


@mcp.tool()
async def get_epss_scores(cve_ids: str) -> dict:
    """
    Get EPSS (Exploit Prediction Scoring System) scores for one or more CVEs.
    EPSS predicts the probability a CVE will be exploited in the next 30 days.

    Args:
        cve_ids: Comma-separated CVE IDs (e.g., "CVE-2024-3400,CVE-2024-21887")
    """
    ids = [c.strip().upper() for c in cve_ids.split(",") if c.strip()]
    results = {}

    for cve_id in ids[:20]:  # Cap at 20
        if re.match(r'^CVE-\d{4}-\d+$', cve_id):
            epss = await fetch_epss_score(cve_id)
            results[cve_id] = epss

    return {
        "scores": results,
        "interpretation": {
            "above_90": "Extremely high exploitation probability",
            "above_50": "High exploitation probability — prioritize remediation",
            "above_10": "Moderate exploitation probability",
            "below_10": "Lower exploitation probability but not zero risk"
        }
    }


@mcp.tool()
async def search_threats(query: str) -> dict:
    """
    Search for threat actors, APT groups, or MITRE ATT&CK techniques.
    Returns threat actor profiles, associated techniques, and detection guidance.

    Args:
        query: Threat actor name (e.g., Volt Typhoon), technique ID (e.g., T1190), or keyword
    """
    query_lower = query.lower().strip()
    result = {}

    # Check for technique ID
    technique_match = re.search(r'T\d{4}(?:\.\d{3})?', query, re.IGNORECASE)
    if technique_match:
        tid = technique_match.group(0).upper()
        if tid in MITRE_TECHNIQUES:
            tech = MITRE_TECHNIQUES[tid]
            result["technique"] = {
                "id": tid,
                "name": tech["name"],
                "tactic": tech["tactic"],
                "mitre_url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }

    # Check for APT group
    for group_key, group_data in APT_GROUPS.items():
        if group_key in query_lower or any(a.lower() in query_lower for a in group_data.get("aliases", [])):
            techniques_detail = []
            for tid in group_data.get("techniques", []):
                if tid in MITRE_TECHNIQUES:
                    t = MITRE_TECHNIQUES[tid]
                    techniques_detail.append({
                        "id": tid,
                        "name": t["name"],
                        "tactic": t["tactic"],
                        "mitre_url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                    })

            result["threat_actor"] = {
                "name": group_key.title(),
                "aliases": group_data["aliases"],
                "origin": group_data["origin"],
                "targets": group_data["targets"],
                "tools": group_data["tools"],
                "mitre_techniques": techniques_detail,
            }
            break

    if not result:
        # General keyword search across techniques
        matching_techniques = []
        for tid, tech in MITRE_TECHNIQUES.items():
            if query_lower in tech["name"].lower() or query_lower in tech["tactic"].lower():
                matching_techniques.append({
                    "id": tid,
                    "name": tech["name"],
                    "tactic": tech["tactic"]
                })
        if matching_techniques:
            result["matching_techniques"] = matching_techniques
        else:
            result["message"] = f"No exact match found for '{query}'. Try a specific APT name (e.g., Volt Typhoon) or technique ID (e.g., T1190)."

    return result


@mcp.tool()
async def generate_poam(
    cve_id: str,
    system_name: str = "Information System",
    impact_level: str = "Moderate",
    cvss_score: float = 0.0
) -> dict:
    """
    Generate a Plan of Action & Milestones (POA&M) entry for a CVE.
    Includes NIST 800-53 control mapping, remediation timeline based on
    BOD 22-01, EPSS score, and KEV status. Output is formatted for
    eMASS or XACTA entry.

    Args:
        cve_id: The CVE identifier (e.g., CVE-2024-3400)
        system_name: Name of the affected system (e.g., DCSA Border Gateway)
        impact_level: System impact level — Low, Moderate, or High
        cvss_score: CVSS score if known (0 to auto-detect)
    """
    cve_id = cve_id.upper().strip()

    # Fetch enrichment data
    cve_data = await lookup_cve(cve_id)
    if cvss_score == 0 and cve_data.get("cvss_score"):
        cvss_score = cve_data["cvss_score"]

    kev_listed = cve_data.get("kev_listed", False)
    epss_score = cve_data.get("epss_score_percent", "N/A")
    epss_pct = cve_data.get("epss_percentile", "N/A")

    # Calculate remediation deadline
    if kev_listed:
        due_date = cve_data.get("kev_due_date", "Per BOD 22-01")
        urgency = "MANDATORY per BOD 22-01"
    elif cvss_score >= 9.0:
        due_date = (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d")
        urgency = "Critical — 15 days recommended"
    elif cvss_score >= 7.0:
        due_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        urgency = "High — 30 days recommended"
    else:
        due_date = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
        urgency = "Standard — 90 days recommended"

    # Determine NIST control
    desc_lower = (cve_data.get("description", "") or "").lower()
    if "authentication" in desc_lower or "credential" in desc_lower:
        nist_control = "IA-5 (Authenticator Management)"
    elif "injection" in desc_lower or "code execution" in desc_lower:
        nist_control = "SI-10 (Information Input Validation)"
    elif "overflow" in desc_lower:
        nist_control = "SI-16 (Memory Protection)"
    elif "privilege" in desc_lower or "escalation" in desc_lower:
        nist_control = "AC-6 (Least Privilege)"
    elif "traversal" in desc_lower:
        nist_control = "AC-3 (Access Enforcement)"
    else:
        nist_control = "SI-2 (Flaw Remediation)"

    severity_cat = "I" if cvss_score >= 9.0 else "II" if cvss_score >= 7.0 else "III"

    # Generate POA&M entry using Claude if available
    poam_narrative = None
    if ANTHROPIC_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": "claude-sonnet-4-20250514",
                        "max_tokens": 800,
                        "temperature": 0.2,
                        "system": "You are a cybersecurity compliance expert. Generate concise POA&M narrative entries suitable for eMASS or XACTA.",
                        "messages": [{"role": "user", "content": f"""Generate a POA&M weakness description and remediation plan for:
CVE: {cve_id}
Description: {cve_data.get('description', 'N/A')[:300]}
CVSS: {cvss_score} ({cve_data.get('cvss_severity', 'N/A')})
CISA KEV: {'YES' if kev_listed else 'No'}
EPSS: {epss_score}%
System: {system_name}
Impact Level: {impact_level}

Return ONLY a JSON object with keys: weakness_description, remediation_plan, milestones (array of strings)"""}]
                    }
                )
                if resp.status_code == 200:
                    text = resp.json()["content"][0]["text"]
                    cleaned = re.sub(r'^```json?\s*', '', text.strip())
                    cleaned = re.sub(r'\s*```$', '', cleaned)
                    poam_narrative = json.loads(cleaned)
        except Exception as e:
            poam_narrative = None

    return {
        "poam_entry": {
            "poam_id": f"POAM-{cve_id}",
            "weakness_id": cve_id,
            "weakness_source": "CISA KEV" if kev_listed else "NVD",
            "weakness_description": (poam_narrative or {}).get(
                "weakness_description",
                f"Vulnerability {cve_id} in {cve_data.get('vendor', 'Unknown')} {cve_data.get('product', 'Unknown')}: {(cve_data.get('description', '') or '')[:200]}"
            ),
            "security_control": nist_control,
            "system_name": system_name,
            "impact_level": impact_level,
            "cvss_score": cvss_score,
            "cvss_severity": cve_data.get("cvss_severity", "N/A"),
            "epss_score": f"{epss_score}%",
            "epss_percentile": epss_pct,
            "cisa_kev": kev_listed,
            "kev_ransomware_use": cve_data.get("kev_ransomware_use", "Unknown"),
            "severity_category": severity_cat,
            "remediation_plan": (poam_narrative or {}).get(
                "remediation_plan",
                f"Apply vendor patch for {cve_id}. Verify remediation through vulnerability scanning."
            ),
            "scheduled_completion": due_date,
            "urgency": urgency,
            "milestones": (poam_narrative or {}).get("milestones", [
                f"1. Identify affected {system_name} components",
                f"2. Test vendor patch in staging environment",
                f"3. Deploy patch to production",
                f"4. Verify remediation via scan"
            ]),
            "point_of_contact": "ISSO / System Owner",
            "status": "Ongoing"
        },
        "enrichment": {
            "cve_data": cve_data,
            "generated_at": datetime.now().isoformat()
        }
    }


# ========================================
# MITRE ATLAS / SAFE-AI TOOLS
# ========================================

@mcp.tool()
async def lookup_atlas_technique(technique_id: str) -> dict:
    """
    Look up a MITRE ATLAS technique by ID (e.g., AML.T0051).
    Returns technique details, tactic mapping, ATT&CK cross-references,
    and SAFE-AI NIST 800-53 control recommendations by system element.
    """
    tid = technique_id.upper().strip()
    tech = ATLAS_TECHNIQUES.get(tid)
    if not tech:
        # Try partial match
        matches = [(k, v) for k, v in ATLAS_TECHNIQUES.items()
                   if tid in k or tid.lower() in v.get("name", "").lower()]
        if matches:
            tid, tech = matches[0]
        else:
            return {"error": f"Technique {technique_id} not found", "available_count": len(ATLAS_TECHNIQUES)}

    # Find related SAFE-AI threats
    related_threats = []
    for tname, threat in SAFE_AI_THREATS.items():
        if threat.get("atlas_id") == tid:
            related_threats.append({
                "threat_name": tname,
                "description": threat.get("description", ""),
                "controls_by_element": threat.get("controls", {}),
                "residual_risk": threat.get("residual_risk", "")
            })

    return {
        "technique_id": tid,
        "name": tech.get("name", ""),
        "tactic": tech.get("tactic", ""),
        "tactic_id": tech.get("tactic_id", ""),
        "description": tech.get("description", ""),
        "attck_shared": tech.get("attck_shared", False),
        "also_in_tactics": tech.get("also_in_tactics", []),
        "safe_ai_controls": tech.get("safe_ai_controls", {}),
        "safe_ai_threats": related_threats,
        "source": "MITRE ATLAS v5.1.0 + SAFE-AI Framework"
    }


@mcp.tool()
async def search_atlas_threats(query: str) -> dict:
    """
    Search SAFE-AI threat categories and get NIST 800-53 control mappings.
    Returns threats matching the query with controls organized by system element
    (Environment, AI Platform, AI Models, AI Data) and residual risk assessment.
    Use 'all' to list all threats.
    """
    query_lower = query.lower().strip()
    results = []

    for tname, threat in SAFE_AI_THREATS.items():
        if (query_lower == "all" or
            query_lower in tname.lower() or
            query_lower in threat.get("description", "").lower() or
            query_lower in threat.get("atlas_id", "").lower()):
            results.append({
                "threat_name": tname,
                "atlas_id": threat.get("atlas_id", ""),
                "description": threat.get("description", ""),
                "controls_by_system_element": threat.get("controls", {}),
                "residual_risk": threat.get("residual_risk", "")
            })

    if not results:
        return {
            "query": query,
            "count": 0,
            "message": "No matching threats found. Try: prompt injection, data poisoning, supply chain, model exposure, insider threat, jailbreak, bias, denial of service",
            "available_threats": list(SAFE_AI_THREATS.keys())
        }

    return {
        "query": query,
        "count": len(results),
        "threats": results,
        "source": "MITRE SAFE-AI Framework (MP250397, April 2025)"
    }


@mcp.tool()
async def get_atlas_overview() -> dict:
    """
    Get an overview of the MITRE ATLAS framework including all 14 tactic
    categories with descriptions, technique counts, and LLM-specific
    technique highlights. Use this for understanding the AI threat landscape.
    """
    # Count techniques per tactic
    tactic_techniques = {}
    for tid, tech in ATLAS_TECHNIQUES.items():
        tac_id = tech.get("tactic_id", "")
        if tac_id not in tactic_techniques:
            tactic_techniques[tac_id] = []
        tactic_techniques[tac_id].append({"id": tid, "name": tech.get("name", ""), "attck_shared": tech.get("attck_shared", False)})

    tactics_summary = []
    for tac_id, tac in ATLAS_TACTICS.items():
        techniques = tactic_techniques.get(tac_id, [])
        tactics_summary.append({
            "tactic_id": tac_id,
            "name": tac["name"],
            "description": tac["description"],
            "technique_count": len(techniques),
            "techniques": techniques
        })

    # Highlight LLM-specific techniques
    llm_techniques = []
    for tid, tech in ATLAS_TECHNIQUES.items():
        if "LLM" in tech.get("name", ""):
            llm_techniques.append({
                "id": tid,
                "name": tech.get("name", ""),
                "tactic": tech.get("tactic", ""),
                "description": tech.get("description", "")[:200]
            })

    return {
        "framework": "MITRE ATLAS v5.1.0",
        "total_tactics": len(ATLAS_TACTICS),
        "total_techniques": len(ATLAS_TECHNIQUES),
        "total_safe_ai_threats": len(SAFE_AI_THREATS),
        "tactics": tactics_summary,
        "llm_specific_techniques": llm_techniques,
        "source": "MITRE ATLAS + SAFE-AI Framework (MP250397)"
    }


# ========================================
# MCP RESOURCES
# ========================================

@mcp.resource("cyberiq://kev/stats")
async def kev_statistics() -> str:
    """Current CISA KEV catalog statistics"""
    kev_data = await fetch_kev_data()
    vulns = kev_data.get("vulnerabilities", [])
    ransomware_count = sum(1 for v in vulns if v.get("knownRansomwareCampaignUse", "").lower() == "known")

    return json.dumps({
        "total_kev_entries": len(vulns),
        "ransomware_associated": ransomware_count,
        "catalog_title": kev_data.get("title", "CISA KEV"),
        "last_updated": kev_data.get("catalogVersion", "Unknown"),
        "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    }, indent=2)


@mcp.resource("cyberiq://info")
def server_info() -> str:
    """CyberIQ MCP Server information and capabilities"""
    return json.dumps({
        "name": "CyberIQ Security MCP Server",
        "version": "1.0.0",
        "provider": "CyberIQ (cyberiq.co)",
        "description": "AI-powered cybersecurity intelligence for security teams and organizations",
        "tools": [
            "lookup_cve — Full CVE enrichment with NVD, KEV, EPSS",
            "check_kev_status — Search CISA KEV catalog",
            "get_epss_scores — Exploit probability scores",
            "search_threats — MITRE ATT&CK and threat actor lookup",
            "generate_poam — POA&M entry generation",
            "lookup_atlas_technique — MITRE ATLAS technique lookup with SAFE-AI controls",
            "search_atlas_threats — Search SAFE-AI threats and NIST 800-53 mappings",
            "get_atlas_overview — ATLAS tactics and techniques summary"
        ],
        "data_sources": [
            "NIST NVD (National Vulnerability Database)",
            "CISA KEV (Known Exploited Vulnerabilities)",
            "FIRST.org EPSS (Exploit Prediction Scoring System)",
            "MITRE ATT&CK Framework",
            "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)",
            "MITRE SAFE-AI Framework (NIST 800-53 control mappings for AI)"
        ],
        "compliance_frameworks": [
            "NIST SP 800-53 Rev 5",
            "NIST SP 800-171",
            "NIST CSF 2.0",
            "BOD 22-01",
            "BOD 25-01 (SCuBA)",
            "FedRAMP",
            "FISMA"
        ]
    }, indent=2)


# ========================================
# Run Server
# ========================================

if __name__ == "__main__":
    import sys
    import uvicorn
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount

    transport = "stdio"
    port = int(os.environ.get("PORT", 8100))

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg in ("--transport", "-t") and i < len(sys.argv) - 1:
            transport = sys.argv[i + 1]
        if arg in ("--port", "-p") and i < len(sys.argv) - 1:
            port = int(sys.argv[i + 1])

    # Default to HTTP if PORT env is set (Railway/cloud deployment)
    if os.environ.get("PORT"):
        transport = "sse"

    if transport in ("http", "sse"):
        print(f"🚀 Starting CyberIQ MCP Server on port {port}")
        
        # Allow Railway proxy domain
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port
        mcp.settings.transport_security.enable_dns_rebinding_protection = False
        mcp.settings.transport_security.allowed_hosts = ["*"]
        mcp.settings.transport_security.allowed_origins = ["*"]
        
        # Get MCP's SSE app
        mcp_app = mcp.sse_app()
        
        # Build combined app: test routes + MCP SSE
        app = Starlette(
            routes=_test_routes + [Mount("/", app=mcp_app)]
        )
        
        uvicorn.run(app, host="0.0.0.0", port=port)
    else:
        mcp.run(transport="stdio")
