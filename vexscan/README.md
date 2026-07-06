# VexScan 🔍
> AI-Powered OSINT Threat Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

VexScan is an automated threat intelligence aggregator and AI analysis engine. It accepts an IP address, domain, or file hash, queries multiple OSINT sources for raw telemetry, and feeds the aggregated data into a large language model to produce a final analyst-grade threat report — in seconds.

---

## How It Works

**1. Intelligence Gathering**
VexScan automatically queries three sources:
- **VirusTotal** — engine detections, reputation score, malicious/suspicious/harmless breakdown
- **AbuseIPDB** — abuse confidence score, historical report count, ISP, Tor node detection
- **Shodan** — open ports, running services, OS fingerprint, known CVEs, geolocation

**2. The AI Layer**
The aggregated JSON telemetry is fed into the **Groq API (Llama 3.3 70B)**, prompted to act as a SOC analyst. The model generates:
- Threat verdict (Malicious / Suspicious / Clean / Unknown)
- Risk score (0–100)
- Key findings from all sources
- Recommended analyst action
- MITRE ATT&CK technique mappings

**3. Architecture**
VexScan is a full platform — not just a script. The core scanning logic is wrapped in a **FastAPI REST backend**, exposing clean endpoints for programmatic access. A custom **Cyber-Neumorphic web dashboard** provides a UI-driven interface for threat hunting without touching the CLI.

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│           Web Dashboard (UI)            │
│     Dark Cyber-Neumorphic Interface     │
└────────────────┬────────────────────────┘
                 │ HTTP
┌────────────────▼────────────────────────┐
│         FastAPI REST Backend            │
│  POST /scan/ip  /scan/domain  /scan/auto│
└───┬────────────┬───────────────┬────────┘
    │            │               │
┌───▼───┐  ┌────▼────┐  ┌───────▼──────┐
│  VT   │  │AbuseIPDB│  │    Shodan    │
└───┬───┘  └────┬────┘  └───────┬──────┘
    └───────────┴───────────────┘
                │ Aggregated JSON
┌───────────────▼─────────────────────────┐
│         Groq API — Llama 3.3 70B        │
│         SOC Analyst AI Verdict          │
└─────────────────────────────────────────┘
```

---

## Demo

```
╭──────────────────────────── OSINT Threat Intelligence ────────────────────────────╮
│ VexScan | Target: malware.wicar.org | Type: DOMAIN                                │
╰───────────────────────────────────────────────────────────────────────────────────╯
✓ VirusTotal → Malicious: 14 | Suspicious: 1

╭────────────────────────────── AI Threat Analysis ─────────────────────────────────╮
│ THREAT VERDICT: Malicious                                                         │
│ RISK SCORE: 80                                                                    │
│                                                                                   │
│ KEY FINDINGS:                                                                     │
│ • 14 VirusTotal engines flagged domain as malicious                               │
│ • Reputation score: -59 (highly malicious)                                        │
│ • Likely used for malware distribution or C2 communications                       │
│                                                                                   │
│ ANALYST RECOMMENDATION: Block access immediately                                  │
│                                                                                   │
│ MITRE ATT&CK:                                                                     │
│ • T1189 – Drive-by Compromise                                                     │
│ • T1071 – Application Layer Protocol (C2)                                         │
╰───────────────────────────────────────────────────────────────────────────────────╯
Report saved → reports/malware_wicar_org_20260516_142301.json
```

---

## Installation

```bash
git clone https://github.com/MohammedRoshanT/vexscan.git
cd vexscan
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file in the project root:

```env
VT_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
GROQ_API_KEY=your_groq_key
```

| API | Free Tier | Link |
|-----|-----------|------|
| VirusTotal | ✅ | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ✅ | [abuseipdb.com](https://www.abuseipdb.com/register) |
| Shodan | ✅ | [account.shodan.io](https://account.shodan.io) |
| Groq | ✅ | [console.groq.com](https://console.groq.com) |

---

## Usage

**CLI**
```bash
python main.py 45.33.32.156
python main.py malware.wicar.org
python main.py 44d88612fea8a8f36de82e1278abb02f --output txt
```

**API**
```bash
uvicorn api:app --reload --port 8000
```
```bash
curl -X POST http://localhost:8000/scan/auto \
  -H "Content-Type: application/json" \
  -d '{"target": "45.33.32.156"}'
```

**Dashboard**
```bash
# Start API then open dashboard/index.html in browser
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health check |
| POST | `/scan/ip` | Scan an IP address |
| POST | `/scan/domain` | Scan a domain |
| POST | `/scan/hash` | Scan a file hash |
| POST | `/scan/auto` | Auto-detect type and scan |

---

## Project Structure

```
vexscan/
├── api.py                  # FastAPI REST backend
├── main.py                 # CLI entry point
├── requirements.txt
├── .env
├── dashboard/
│   └── index.html          # Web dashboard
├── modules/
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── shodan_lookup.py
│   └── ai_analyst.py
└── reports/
```

---

## Disclaimer

VexScan is built for educational purposes and authorized security research only.
Do not use against targets you do not have permission to investigate.

---

## Author

**Mohammed Roshan T**
[LinkedIn](https://linkedin.com/in/mohammed-roshan-t) · [GitHub](https://github.com/MohammedRoshanT) · TryHackMe: r0x404 (Top 5% Global)