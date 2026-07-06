# modules/url_scanner.py

import requests
import os
import time
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

def scan_url_virustotal(url: str) -> dict:
    headers = {"x-apikey": VT_API_KEY}

    # Submit URL
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )
    if response.status_code != 200:
        return {"error": f"VT submission failed: {response.status_code}"}

    analysis_id = response.json()["data"]["id"]

    # Poll for result
    time.sleep(5)
    result = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )
    if result.status_code != 200:
        return {"error": f"VT result fetch failed: {result.status_code}"}

    stats = result.json()["data"]["attributes"]["stats"]
    return {
        "source": "VirusTotal",
        "url": url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

def scan_url_urlscan(url: str) -> dict:
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    # Submit scan
    response = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers=headers,
        json={"url": url, "visibility": "private"}
    )
    if response.status_code not in [200, 201]:
        return {"error": f"URLscan submission failed: {response.status_code}"}

    uuid = response.json().get("uuid")
    result_url = f"https://urlscan.io/api/v1/result/{uuid}/"

    # Wait for scan to complete
    time.sleep(10)

    for _ in range(5):
        result = requests.get(result_url)
        if result.status_code == 200:
            data = result.json()
            verdicts = data.get("verdicts", {}).get("overall", {})
            page = data.get("page", {})
            return {
                "source": "URLscan.io",
                "url": url,
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "tags": verdicts.get("tags", []),
                "final_url": page.get("url", url),
                "ip": page.get("ip", "N/A"),
                "country": page.get("country", "N/A"),
                "result_link": f"https://urlscan.io/result/{uuid}/"
            }
        time.sleep(5)

    return {"error": "URLscan timed out", "url": url}

def scan_all_urls(urls: list) -> list:
    results = []
    for url in urls[:5]:  # limit to 5 URLs to avoid rate limits
        vt = scan_url_virustotal(url)
        us = scan_url_urlscan(url)
        results.append({"url": url, "virustotal": vt, "urlscan": us})
    return results