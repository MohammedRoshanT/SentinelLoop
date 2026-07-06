# modules/virustotal.py

import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY
}

def scan_ip(ip: str) -> dict:
    url = f"{BASE_URL}/ip_addresses/{ip}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return {"error": f"VirusTotal IP lookup failed: {response.status_code}"}
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "source": "VirusTotal",
        "target": ip,
        "type": "ip",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": data["data"]["attributes"].get("country", "N/A"),
        "reputation": data["data"]["attributes"].get("reputation", 0),
    }

def scan_domain(domain: str) -> dict:
    url = f"{BASE_URL}/domains/{domain}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return {"error": f"VirusTotal domain lookup failed: {response.status_code}"}
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "source": "VirusTotal",
        "target": domain,
        "type": "domain",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": data["data"]["attributes"].get("reputation", 0),
    }

def scan_hash(file_hash: str) -> dict:
    url = f"{BASE_URL}/files/{file_hash}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        return {"error": f"VirusTotal hash lookup failed: {response.status_code}"}
    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    return {
        "source": "VirusTotal",
        "target": file_hash,
        "type": "hash",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "name": data["data"]["attributes"].get("meaningful_name", "N/A"),
    }