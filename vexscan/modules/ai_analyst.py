# modules/ai_analyst.py

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def analyze(target: str, intel_data: list) -> str:
    summary = "\n\n".join([str(d) for d in intel_data])
    
    prompt = f"""You are an expert threat intelligence analyst.
    
A security analyst has queried the following target: {target}

Here is the aggregated threat intelligence data from multiple sources:

{summary}

Based on this data, provide:
1. THREAT VERDICT: (Malicious / Suspicious / Clean / Unknown)
2. RISK SCORE: (0-100)
3. KEY FINDINGS: (bullet points of the most important indicators)
4. ANALYST RECOMMENDATION: (what action should be taken)
5. MITRE ATT&CK MAPPING: (relevant techniques if applicable)

Be concise, technical, and actionable. Format clearly."""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3,
    )
    return response.choices[0].message.content  