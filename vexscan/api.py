# api.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
import re
import os
from modules import virustotal, abuseipdb, shodan_lookup, ai_analyst

app = FastAPI(
    title="VexScan API",
    description="AI-powered OSINT Threat Intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure dashboard folder exists so FastAPI doesn't crash on startup
os.makedirs("dashboard", exist_ok=True)

class ScanRequest(BaseModel):
    target: str

def detect_type(target: str) -> str:
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if re.match(ip_pattern, target):
        return "ip"
    elif re.match(hash_pattern, target):
        return "hash"
    return "domain"

# Direct route to serve the dashboard at the root URL (http://127.0.0.1:8000/)
@app.get("/")
def serve_dashboard_root():
    index_path = os.path.join("dashboard", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"tool": "VexScan", "status": "running", "msg": "dashboard/index.html not found"}

# Direct route to serve the dashboard at http://127.0.0.1:8000/dashboard
@app.get("/dashboard")
def serve_dashboard_path():
    index_path = os.path.join("dashboard", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="dashboard/index.html not found")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan/ip")
def scan_ip(request: ScanRequest):
    ip = request.target.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")
    try:
        vt = virustotal.scan_ip(ip)
        abuse = abuseipdb.check_ip(ip)
        shodan = shodan_lookup.lookup_ip(ip)
        intel = [vt, abuse, shodan]
        ai_report = ai_analyst.analyze(ip, intel)
        return {
            "target": ip,
            "type": "ip",
            "virustotal": vt,
            "abuseipdb": abuse,
            "shodan": shodan,
            "ai_analysis": ai_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/domain")
def scan_domain(request: ScanRequest):
    domain = request.target.strip()
    try:
        vt = virustotal.scan_domain(domain)
        intel = [vt]
        ai_report = ai_analyst.analyze(domain, intel)
        return {
            "target": domain,
            "type": "domain",
            "virustotal": vt,
            "ai_analysis": ai_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/hash")
def scan_hash(request: ScanRequest):
    file_hash = request.target.strip()
    try:
        vt = virustotal.scan_hash(file_hash)
        intel = [vt]
        ai_report = ai_analyst.analyze(file_hash, intel)
        return {
            "target": file_hash,
            "type": "hash",
            "virustotal": vt,
            "ai_analysis": ai_report
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/auto")
def scan_auto(request: ScanRequest):
    target = request.target.strip()
    target_type = detect_type(target)
    if target_type == "ip":
        return scan_ip(request)
    elif target_type == "domain":
        return scan_domain(request)
    return scan_hash(request)

# Mount asset folder just in case you expand it later
app.mount("/static", StaticFiles(directory="dashboard"), name="static")