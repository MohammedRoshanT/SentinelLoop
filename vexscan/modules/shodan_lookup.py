import shodan
import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

def lookup_ip(ip: str) -> dict:
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        return {
            "source": "Shodan",
            "target": ip,
            "organization": host.get("org", "N/A"),
            "os": host.get("os", "N/A"),
            "country": host.get("country_name", "N/A"),
            "city": host.get("city", "N/A"),
            "open_ports": [item["port"] for item in host.get("data", [])],
            "hostnames": host.get("hostnames", []),
            "tags": host.get("tags", []),
            "vulns": list(host.get("vulns", {}).keys()),
        }
    except shodan.APIError as e:
        return {
            "source": "Shodan",
            "target": ip,
            "error": f"Shodan lookup failed: {str(e)}",
            "open_ports": [],
            "vulns": [],
            "note": "Free tier may not index all IPs"
        }