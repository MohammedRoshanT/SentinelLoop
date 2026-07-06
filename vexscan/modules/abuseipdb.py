# modules/abuseipdb.py

import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"

HEADERS = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

def check_ip(ip: str) -> dict:
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": True
    }
    response = requests.get(f"{BASE_URL}/check", headers=HEADERS, params=params)
    if response.status_code != 200:
        return {"error": f"AbuseIPDB lookup failed: {response.status_code}"}
    
    data = response.json()["data"]
    return {
        "source": "AbuseIPDB",
        "target": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode", "N/A"),
        "isp": data.get("isp", "N/A"),
        "domain": data.get("domain", "N/A"),
        "is_tor": data.get("isTor", False),
        "is_whitelisted": data.get("isWhitelisted", False),
        "last_reported": data.get("lastReportedAt", "Never"),
    }