# modules/ai_analyst.py

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze(parsed_email: dict, header_analysis: dict, url_results: list) -> str:
    prompt = f"""You are an expert email security analyst specializing in phishing detection.

Analyze the following email data and provide a structured phishing assessment.

--- EMAIL METADATA ---
From: {parsed_email.get('sender')}
Reply-To: {parsed_email.get('reply_to')}
Subject: {parsed_email.get('subject')}
Date: {parsed_email.get('date')}
Sender IP: {parsed_email.get('sender_ip')}
Attachments: {parsed_email.get('attachments')}

--- AUTHENTICATION ---
SPF: {parsed_email.get('spf')}
DKIM: {parsed_email.get('dkim')}
DMARC: {parsed_email.get('dmarc')}

--- HEADER ANOMALIES ---
{header_analysis.get('anomalies')}
Risk Indicators: {header_analysis.get('risk_indicators')}

--- URL SCAN RESULTS ---
{url_results}

--- EMAIL BODY PREVIEW ---
{parsed_email.get('body_preview')}

Based on all the above, provide:
1. PHISHING VERDICT: (Phishing / Suspicious / Legitimate / Unknown)
2. CONFIDENCE SCORE: (0-100%)
3. KEY INDICATORS: (bullet points of strongest phishing signals)
4. ATTACK TYPE: (credential harvesting / malware delivery / BEC / spam / other)
5. RECOMMENDED ACTION: (block / quarantine / release / investigate further)
6. MITRE ATT&CK MAPPING: (relevant techniques)

Be concise, technical, and actionable."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return response.choices[0].message.content