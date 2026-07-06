import re
import requests
import os
from fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("SOC Triage Helper")

VEXSCAN_URL = os.getenv("VEXSCAN_URL", "http://localhost:8003")
PHEXOR_URL = os.getenv("PHEXOR_URL", "http://localhost:8001")

@mcp.tool()
def osint_lookup(indicator: str) -> str:
    """Investigate a security indicator (IP address, domain, or file hash) using VexScan OSINT tools."""
    indicator = indicator.strip()
    
    # Input Validation
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    
    if not (re.match(ip_pattern, indicator) or re.match(hash_pattern, indicator) or re.match(domain_pattern, indicator)):
        return "Error: Invalid indicator format. Must be a valid IPv4 address, domain, or MD5/SHA1/SHA256 hash."
        
    try:
        url = f"{VEXSCAN_URL}/scan/auto"
        response = requests.post(url, json={"target": indicator}, timeout=120)
        if response.status_code != 200:
            return f"Error: VexScan returned status code {response.status_code}: {response.text}"
        return response.text
    except Exception as e:
        return f"Error: Failed to connect to VexScan API on {VEXSCAN_URL}. Is VexScan running? Details: {e}"

@mcp.tool()
def batch_ioc_scan(iocs: list[str]) -> str:
    """Investigate a batch of up to 10 security indicators (IP addresses, domains, or file hashes) simultaneously."""
    if not iocs:
        return "Error: No indicators provided."
        
    try:
        url = f"{VEXSCAN_URL}/scan/batch"
        response = requests.post(url, json={"targets": iocs}, timeout=120)
        if response.status_code != 200:
            return f"Error: VexScan returned status code {response.status_code}: {response.text}"
        return response.text
    except Exception as e:
        return f"Error: Failed to connect to VexScan API on {VEXSCAN_URL}. Is VexScan running? Details: {e}"

@mcp.tool()
def phishing_forensics(eml_content: str) -> str:
    """Analyze the raw content of an .eml email file using Phexor Phishing Analyzer to detect spoofing, header anomalies, and malicious URLs."""
    # Size limit: 500KB (500,000 characters)
    max_size = 500000
    if len(eml_content.encode('utf-8')) > max_size:
        return f"Error: EML content exceeds the limit of {max_size} bytes (size is {len(eml_content)} bytes)."
        
    if not eml_content.strip():
        return "Error: EML content cannot be empty."
        
    try:
        url = f"{PHEXOR_URL}/analyze"
        files = {'file': ('analysis.eml', eml_content, 'message/rfc822')}
        response = requests.post(url, files=files, timeout=120)
        if response.status_code != 200:
            return f"Error: Phexor returned status code {response.status_code}: {response.text}"
        return response.text
    except Exception as e:
        return f"Error: Failed to connect to Phexor API on {PHEXOR_URL}. Is Phexor running? Details: {e}"

@mcp.tool()
def save_report(report_content: str, indicator: str) -> str:
    """Save the final SOC triage report to the local file system for persistence."""
    try:
        os.makedirs("reports", exist_ok=True)
        filename = f"reports/triage_{indicator.replace('.', '_')}.md"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_content)
        return f"Success: Report saved to {filename}"
    except Exception as e:
        return f"Error saving report: {e}"

if __name__ == "__main__":
    mcp.run()
