# api.py
import os
import shutil
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from modules import email_parser, header_analyzer, url_scanner, ai_analyst

app = FastAPI(
    title="Phexor API",
    description="AI-powered Phishing Email Analyzer",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure required directories exist
os.makedirs("dashboard", exist_ok=True)
os.makedirs("temp", exist_ok=True)

@app.get("/")
def serve_dashboard_root():
    index_path = os.path.join("dashboard", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"tool": "Phexor", "status": "running", "msg": "dashboard/index.html not found"}

@app.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename.endswith('.eml'):
        raise HTTPException(status_code=400, detail="Invalid file type. Only .eml files are accepted.")
    
    temp_path = os.path.join("temp", file.filename)
    
    try:
        # Save the uploaded file temporarily to run it through standard parsing
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Execute parsing and modules
        parsed = email_parser.parse_eml(temp_path)
        headers = header_analyzer.analyze_headers(parsed)
        
        urls = parsed.get("urls", [])
        url_results = []
        if urls:
            # Limits to 5 inside url_scanner to protect free tier rates
            url_results = url_scanner.scan_all_urls(urls)
            
        ai_report = ai_analyst.analyze(parsed, headers, url_results)
        
        return {
            "filename": file.filename,
            "parsed_email": parsed,
            "header_analysis": headers,
            "url_results": url_results,
            "ai_analysis": ai_report
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
    finally:
        # Always delete the temporary file from storage
        if os.path.exists(temp_path):
            os.remove(temp_path)

app.mount("/static", StaticFiles(directory="dashboard"), name="static")