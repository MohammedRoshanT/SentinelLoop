# SentinelLoop Capstone

SentinelLoop is an automated Security Operations Center (SOC) triage pipeline. It combines Google's Agent Development Kit (ADK) with two custom security analysis backends to automatically investigate alerts, perform threat intelligence lookups, execute email forensics, and generate structured SOC analyst reports.

This repository is structured as a monorepo containing three core components.

## Project Structure

- **`soc_triage_agent/`**: The main orchestration component. It runs a sequential multi-agent pipeline (Reconnaissance -> Analysis -> Reporting) using ADK and connects to the backend services via a custom FastMCP server. It also hosts the ADK Web UI.
- **`vexscan/`**: The OSINT reconnaissance API. It queries external threat intelligence sources (VirusTotal, AbuseIPDB, Shodan) to validate IPs, domains, and file hashes.
- **`phexor/`**: The phishing and forensics API. It parses raw `.eml` files, analyzes email headers (SPF/DKIM/DMARC), extracts malicious URLs, and interacts with Groq/Llama models for security assessment.
- **`.agents/`**: Contains the workspace customization rules and skills (like the `soc-triage-reporting` markdown format) that dynamically configure the agents.

---

## 🚀 Built with Antigravity

This project was developed with the assistance of **Antigravity**, Google's advanced agentic coding AI. Antigravity acted as a pair-programmer to help design the multi-agent orchestration, configure the MCP tools, and debug cross-service communication. By leveraging Antigravity's capabilities, SentinelLoop demonstrates the power of combining human domain expertise in cybersecurity with AI-driven development.

---

## Setup Instructions

### 1. Prerequisites
You will need Python 3.11+ installed. We highly recommend using `uv` (a fast Python package installer and resolver) to manage the virtual environment.

### 2. Configure Environment Variables
You must configure a `.env` file in the root directory (or inside each respective folder) with your API keys.

```env
# Google & Groq Models
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key

# Threat Intelligence APIs
VT_API_KEY=your_virustotal_api_key
SHODAN_API_KEY=your_shodan_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
URLSCAN_API_KEY=your_urlscan_api_key
```

### 3. Install Dependencies
You can install the dependencies for all three services using `uv`:

```bash
cd soc_triage_agent
uv venv
uv pip install -r requirements.txt

cd ../vexscan
uv venv
uv pip install -r requirements.txt

cd ../phexor
uv venv
uv pip install -r requirements.txt
```

---

## Running the Pipeline

To prevent port conflicts, each service runs on a dedicated port. 

### Step 1: Start VexScan API (Port 8003)
The MCP server expects VexScan to be running on port 8003. Open a terminal and run:
```bash
cd vexscan
uv run uvicorn api:app --port 8003
```

### Step 2: Start Phexor API (Port 8001)
Open a second terminal and run:
```bash
cd phexor
uv run uvicorn api:app --port 8001
```

### Step 3: Start the ADK Web UI (Port 8000)
Open a third terminal and run the main orchestration agent:
```bash
cd soc_triage_agent
uv run adk web
```

Once all three services are running, open your browser to **http://127.0.0.1:8000** to access the SentinelLoop Web UI and begin triaging security alerts!
