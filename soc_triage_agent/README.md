# SOC Triage Agent Pipeline

An automated security alert triage system built using Google's Agent Development Kit (ADK) and a custom Model Context Protocol (MCP) server. The pipeline orchestrates three agents sequentially:
1. **Reconnaissance Agent**: Runs threat intelligence searches (IP, Domain, Hash, Email) using VexScan OSINT tools.
2. **Analysis Agent**: Executes static and dynamic email forensics using Phexor Phishing Analyzer.
3. **Reporting Agent**: Compiles structured SOC triage reports and ticket notes based on `.agents/skills/soc-triage-reporting/SKILL.md`.

---

## Deployment Guide (Google Cloud Run)

To deploy the agent pipeline along with its web UI, Google Cloud recommends using ADK's built-in deploy command. This compiles, packages, and deploys the agent in a single step without needing a hand-written Dockerfile.

### Prerequisites

1.  Create the following secrets in Google Secret Manager:
    -   `GEMINI_API_KEY`
    -   `GROQ_API_KEY`
    -   `VT_API_KEY`
    -   `SHODAN_API_KEY`
    -   `ABUSEIPDB_API_KEY`
    -   `URLSCAN_API_KEY`
2.  Ensure that the service account used by Google Cloud Run has the **Secret Manager Secret Accessor** (`roles/secretmanager.secretAccessor`) role granted.

### Deploy Command

Deploy the agent to Cloud Run using the `adk deploy` command, mounting the Secret Manager secrets directly:

```bash
adk deploy cloud_run \
    --project=$GOOGLE_CLOUD_PROJECT \
    --region=$GOOGLE_CLOUD_LOCATION \
    --service_name=soc-triage-service \
    --with_ui \
    --set-secrets="GEMINI_API_KEY=GEMINI_API_KEY:latest,GROQ_API_KEY=GROQ_API_KEY:latest,VT_API_KEY=VT_API_KEY:latest,SHODAN_API_KEY=SHODAN_API_KEY:latest,ABUSEIPDB_API_KEY=ABUSEIPDB_API_KEY:latest,URLSCAN_API_KEY=URLSCAN_API_KEY:latest" \
    soc_triage_agent
```


---

## Environment Variables

| Variable | Description |
|---|---|
| `GEMINI_API_KEY` | Google Gemini API Key (Studio/Vertex) |
| `GROQ_API_KEY` | Groq Llama 3.3 API key |
| `VT_API_KEY` | VirusTotal API Key |
| `SHODAN_API_KEY` | Shodan API Key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API Key |
| `URLSCAN_API_KEY` | URLScan.io API Key (Required for Phexor) |

---

## Observability & Agent Logging

For auditability and transparency, all tool calls, agent hops, and LLM completions must be logged in a structured format readable by Cloud Logging.

### Structured Logging Configuration
Add structured JSON logging to standard output in your execution harness:

```python
import logging
import json
import sys

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "timestamp": self.formatTime(record, self.datefmt)
        }
        if hasattr(record, "agent"):
            log_entry["agent"] = record.agent
        if hasattr(record, "tool_call"):
            log_entry["tool_call"] = record.tool_call
        return json.dumps(log_entry)

logger = logging.getLogger("soc_triage")
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

### Telemetry & Tracing Traceability
ADK's telemetry records:
1. **Agent State Transitions**: Logged as `[recon_agent] -> [analysis_agent] -> [report_agent]`.
2. **Tool Invocations**: Logged with the inputs (e.g. `osint_lookup(indicator='8.8.8.8')`) and outputs, so analysts can verify what data the LLM worked on.
