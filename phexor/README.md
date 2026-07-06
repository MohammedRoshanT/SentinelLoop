# Phexor 🎣
> AI-Powered Phishing Email Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

Phexor is a digital forensics tool for analyzing suspicious `.eml` files. It statically parses email structure, runs anomaly detection on authentication records, scans extracted URLs against threat intelligence sources, and uses an LLM to identify the specific attack vector — all from a drag-and-drop web interface.

---

## How It Works

**1. Static Email Parsing**
Phexor parses the raw `.eml` structure to extract:
- Routing headers (From, Reply-To, Received chain, Message-ID)
- Embedded URLs from the email body
- Attachments (filename and MIME type)
- Sender IP from the outermost Received header

**2. Authentication Anomaly Detection**
Custom detection logic flags:
- **SPF failures** — domain spoofing indicators
- **DKIM missing/failing** — unsigned or tampered messages
- **DMARC failures** — policy enforcement failures
- **Reply-To mismatches** — sender vs reply address divergence
- **Suspicious subject keywords** — urgency-driven phishing language

**3. URL Reputation Scanning**
All extracted URLs are submitted to:
- **VirusTotal** — multi-engine malicious URL detection
- **URLscan.io** — behavioral scan with final redirect, IP, and verdict

**4. The AI Layer**
The Groq LLM (Llama 3.3 70B) evaluates the header anomalies, URL reputations, and email body context to output:
- Phishing verdict with confidence score (0–100%)
- Specific attack vector identification (credential harvesting, malware delivery, BEC, spam)
- Recommended analyst action (block / quarantine / investigate)
- MITRE ATT&CK technique mappings

**5. Architecture**
A **FastAPI backend** handles `.eml` file uploads and orchestrates all analysis modules. The frontend is a custom **Glassmorphic Cyber-Defense dashboard** with a drag-and-drop upload zone for seamless email analysis.

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│        Web Dashboard (UI)               │
│   Frosted Glassmorphic Interface        │
│   Drag-and-Drop .eml Upload Zone        │
└────────────────┬────────────────────────┘
                 │ multipart/form-data
┌────────────────▼────────────────────────┐
│         FastAPI REST Backend            │
│         POST /analyze/email             │
└───┬─────────────┬──────────────┬────────┘
    │             │              │
┌───▼──────┐ ┌───▼──────┐ ┌────▼──────┐
│  Email   │ │  Header  │ │   URL     │
│  Parser  │ │ Analyzer │ │  Scanner  │
└───┬──────┘ └───┬──────┘ └────┬──────┘
    └────────────┴─────────────┘
                 │ Aggregated Analysis
┌────────────────▼────────────────────────┐
│         Groq API — Llama 3.3 70B        │
│     Phishing Verdict + Attack Vector    │
└─────────────────────────────────────────┘
```

---

## Demo

```
╭──────────────────────────── Phishing Email Analyzer ──────────────────────────────╮
│ Phexor | File: suspicious_email.eml                                               │
╰───────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────── Email Summary ─────────────────────────────────────────╮
│  From       PayPal Security <security@paypa1-support.com>                         │
│  Reply-To   collect@harvester-domain.ru                                           │
│  Subject    URGENT: Your account has been suspended                               │
│  Sender IP  185.220.101.45                                                        │
│  SPF        FAIL  |  DKIM  Missing  |  URLs Found  2                              │
╰───────────────────────────────────────────────────────────────────────────────────╯
⚠ Header Anomalies Found: 5
  → SPF check failed
  → DKIM signature missing
  → DMARC check failed
  → Reply-To mismatch: sender != reply_to
  → Suspicious subject keywords: ['urgent', 'verify', 'suspended']

╭────────────────────────── AI Phishing Analysis ───────────────────────────────────╮
│ PHISHING VERDICT: Phishing                                                        │
│ CONFIDENCE SCORE: 95%                                                             │
│ ATTACK TYPE: Credential Harvesting                                                │
│ RECOMMENDED ACTION: Block                                                         │
│                                                                                   │
│ MITRE ATT&CK:                                                                     │
│ • T1566 – Phishing (Spearphishing Link)                                           │
│ • T1598 – Phishing for Information                                                │
╰───────────────────────────────────────────────────────────────────────────────────╯
```

---

## Installation

```bash
git clone https://github.com/MohammedRoshanT/phexor.git
cd phexor
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## Configuration

```env
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
GROQ_API_KEY=your_groq_key
URLSCAN_API_KEY=your_urlscan_key
```

| API | Free Tier | Link |
|-----|-----------|------|
| VirusTotal | ✅ | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| AbuseIPDB | ✅ | [abuseipdb.com](https://www.abuseipdb.com/register) |
| URLscan.io | ✅ | [urlscan.io](https://urlscan.io) |
| Groq | ✅ | [console.groq.com](https://console.groq.com) |

---

## Usage

**CLI**
```bash
python main.py suspicious_email.eml
python main.py suspicious_email.eml --output txt
```

**API**
```bash
uvicorn api:app --reload --port 8001
curl -X POST http://localhost:8001/analyze/email -F "file=@suspicious_email.eml"
```

**Dashboard**
```bash
# Start API then open dashboard/index.html in browser
```

---

## Detection Capabilities

| Check | What It Catches |
|-------|----------------|
| SPF | Domain spoofing via forged sender |
| DKIM | Unsigned or tampered messages |
| DMARC | Policy enforcement failures |
| Reply-To Mismatch | Harvester redirect addresses |
| Subject Keywords | Urgency-driven phishing language |
| URL Scanning | Malicious links via VT + URLscan |
| Sender IP | Extracted from Received chain |
| Attachments | Malicious file type detection |

---

## Project Structure

```
phexor/
├── api.py                   # FastAPI REST backend
├── main.py                  # CLI entry point
├── requirements.txt
├── .env
├── dashboard/
│   └── index.html           # Glassmorphic web dashboard
├── modules/
│   ├── email_parser.py
│   ├── header_analyzer.py
│   ├── url_scanner.py
│   └── ai_analyst.py
└── reports/
```

---

## Disclaimer

Phexor is built for educational purposes and authorized security research only.
Only analyze emails you have permission to investigate.

---

## Author

**Mohammed Roshan T**
 [LinkedIn](https://linkedin.com/in/mohammed-roshan-t) · [GitHub](https://github.com/MohammedRoshanT) · TryHackMe: r0x404 (Top 5% Global)