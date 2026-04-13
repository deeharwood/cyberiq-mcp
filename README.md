# CyberIQ Security MCP Server

An MCP (Model Context Protocol) server that gives any AI agent instant access to cybersecurity intelligence — vulnerability data, threat intelligence, adversarial AI analysis, and compliance automation.

**Live at:** [https://mcp.cyberiq.co](https://mcp.cyberiq.co)

[![LIVE](https://img.shields.io/badge/status-LIVE-brightgreen)](https://mcp.cyberiq.co)
[![MCP](https://img.shields.io/badge/protocol-MCP-blue)](https://modelcontextprotocol.io)
[![NVIDIA Inception](https://img.shields.io/badge/NVIDIA-Inception-76B900)](https://www.nvidia.com/en-us/startups/)

## Connect

Add to any MCP client (Claude Desktop, ChatGPT, Cursor, etc.):

```json
{
  "mcpServers": {
    "cyberiq": {
      "url": "https://mcp.cyberiq.co/sse"
    }
  }
}
```

## 10 Tools

| Tool | Description |
|------|-------------|
| `lookup_cve` | Full CVE enrichment — NVD + CISA KEV + EPSS exploit probability |
| `check_kev_status` | Search CISA Known Exploited Vulnerabilities catalog |
| `get_epss_scores` | Batch EPSS exploit prediction scores |
| `search_threats` | MITRE ATT&CK technique mapping + threat actor lookup |
| `generate_poam` | Plan of Action & Milestones entry generation (eMASS/XACTA format) |
| `lookup_atlas_technique` | MITRE ATLAS technique lookup with SAFE-AI NIST 800-53 controls |
| `search_atlas_threats` | Search SAFE-AI threats with control mappings by system element |
| `get_atlas_overview` | ATLAS framework summary — 16 tactics, 167 techniques, 35 mitigations |
| `lookup_threat_actor` | Look up APT groups by name/alias — 187 threat actors with ATT&CK techniques |
| `lookup_malware` | Search 696 malware families with MITRE ATT&CK IDs and descriptions |

## Data Sources

- **NIST NVD** — National Vulnerability Database (CVE details, CVSS scores)
- **CISA KEV** — Known Exploited Vulnerabilities catalog with BOD 22-01 deadlines
- **FIRST.org EPSS** — Exploit Prediction Scoring System (real-world exploit probability)
- **MITRE ATT&CK** — Adversary tactics, techniques, and procedures
- **MITRE ATLAS** — Adversarial Threat Landscape for AI Systems (v5.1.0, 167 attack patterns)
- **MITRE SAFE-AI** — Framework for securing AI-enabled systems (NIST 800-53 control mappings)

### ATLAS Data

ATLAS technique data is sourced from the [MITRE ATLAS Navigator Data](https://github.com/mitre-atlas/atlas-navigator-data) repository (`stix-atlas.json`, STIX 2.1 format). SAFE-AI threat-to-control mappings are sourced from the MITRE SAFE-AI Framework (MP250397, April 2025).

## REST Test Endpoints

Test the tools directly in your browser:

| Endpoint | Description |
|----------|-------------|
| [`/api/test/lookup/CVE-2024-3400`](https://mcp.cyberiq.co/api/test/lookup/CVE-2024-3400) | CVE lookup with KEV + EPSS |
| [`/api/test/kev/ransomware`](https://mcp.cyberiq.co/api/test/kev/ransomware) | Ransomware-associated KEVs |
| [`/api/test/kev/Microsoft`](https://mcp.cyberiq.co/api/test/kev/Microsoft) | Microsoft KEVs |
| [`/api/test/epss/CVE-2024-3400,CVE-2024-21887`](https://mcp.cyberiq.co/api/test/epss/CVE-2024-3400,CVE-2024-21887) | Batch EPSS scores |
| [`/api/test/threat/Volt Typhoon`](https://mcp.cyberiq.co/api/test/threat/Volt%20Typhoon) | Threat actor lookup |
| [`/api/test/threat/T1190`](https://mcp.cyberiq.co/api/test/threat/T1190) | ATT&CK technique |
| [`/api/test/atlas/technique/AML.T0051`](https://mcp.cyberiq.co/api/test/atlas/technique/AML.T0051) | ATLAS: Prompt Injection |
| [`/api/test/atlas/technique/AML.T0054`](https://mcp.cyberiq.co/api/test/atlas/technique/AML.T0054) | ATLAS: LLM Jailbreak |
| [`/api/test/atlas/threats`](https://mcp.cyberiq.co/api/test/atlas/threats) | All SAFE-AI threats |
| [`/api/test/atlas/tactics`](https://mcp.cyberiq.co/api/test/atlas/tactics) | All ATLAS tactics |

## Compliance Frameworks

Controls and mappings reference these frameworks:

- NIST SP 800-53 Rev 5
- NIST SP 800-171
- NIST CSF 2.0
- NIST AI RMF 1.0
- BOD 22-01 (CISA KEV mandatory remediation)
- BOD 25-01 (SCuBA cloud baselines)
- FedRAMP / FISMA
- MITRE ATLAS / SAFE-AI

## Local Development

```bash
# Clone
git clone https://github.com/deeharwood/cyberiq-mcp.git
cd cyberiq-mcp

# Install dependencies
pip install -r requirements.txt

# Run locally (stdio for Claude Desktop)
python cyberiq_mcp_server.py

# Run as HTTP server
python cyberiq_mcp_server.py --transport http --port 8100
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | Auto-set by Railway | Server port (defaults to 8100) |
| `ANTHROPIC_API_KEY` | For POA&M generation | Claude API key for AI-generated POA&M narratives |

## Deployment

Deployed on [Railway](https://railway.app) with custom domain via Cloudflare DNS.

```
CNAME: mcp → ur8594qb.up.railway.app (DNS only)
TXT: _railway-verify.mcp → railway-verify=...
```

## Architecture

```
┌─────────────────────────────────┐
│  AI Agent (Claude, ChatGPT,     │
│  Cursor, custom)                │
└────────────┬────────────────────┘
             │ MCP (SSE)
             ▼
┌─────────────────────────────────┐
│  CyberIQ MCP Server            │
│  mcp.cyberiq.co                │
│                                 │
│  8 Tools:                       │
│  ├── CVE/KEV/EPSS pipeline     │──► NIST NVD API
│  ├── ATT&CK threat lookup      │──► MITRE ATT&CK
│  ├── ATLAS technique lookup    │──► ATLAS STIX data
│  ├── SAFE-AI control mapping   │──► NIST 800-53
│  └── POA&M generation          │──► Claude API
└─────────────────────────────────┘
```

## About CyberIQ

CyberIQ is an AI-powered cybersecurity intelligence platform. Built by a 30-year cybersecurity veteran. NVIDIA Inception Program member.

- **Platform:** [cyberiq.co](https://cyberiq.co)
- **MCP Server:** [mcp.cyberiq.co](https://mcp.cyberiq.co)
- **Contact:** [deeharwood@outlook.com](mailto:deeharwood@outlook.com)

## License

Proprietary. Patent Pending. © 2026 CyberIQ LLC.

ATLAS data is sourced from [MITRE ATLAS](https://atlas.mitre.org) under the MITRE ATLAS Terms of Use.
ATT&CK® is a registered trademark of The MITRE Corporation.
