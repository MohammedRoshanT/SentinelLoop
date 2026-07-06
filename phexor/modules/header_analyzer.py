# modules/header_analyzer.py

def analyze_headers(parsed_email: dict) -> dict:
    anomalies = []
    risk_indicators = []

    sender = parsed_email.get("sender", "")
    reply_to = parsed_email.get("reply_to", "N/A")
    subject = parsed_email.get("subject", "")
    spf = parsed_email.get("spf", "N/A")
    dkim = parsed_email.get("dkim", "Missing")
    dmarc = parsed_email.get("dmarc", "N/A")

    # SPF check
    if "fail" in spf.lower():
        anomalies.append("SPF check failed")
        risk_indicators.append("SPF_FAIL")
    elif spf == "N/A":
        anomalies.append("SPF record missing")

    # DKIM check
    if dkim == "Missing":
        anomalies.append("DKIM signature missing")
        risk_indicators.append("DKIM_MISSING")

    # DMARC check
    if "fail" in dmarc.lower():
        anomalies.append("DMARC check failed")
        risk_indicators.append("DMARC_FAIL")

    # Reply-To mismatch
    if reply_to != "N/A" and reply_to != sender:
        anomalies.append(f"Reply-To mismatch: sender={sender}, reply_to={reply_to}")
        risk_indicators.append("REPLY_TO_MISMATCH")

    # Suspicious subject keywords
    phishing_keywords = [
        "urgent", "verify", "suspended", "account", "click",
        "confirm", "update", "password", "login", "bank",
        "winner", "prize", "free", "limited", "immediately"
    ]
    subject_lower = subject.lower()
    matched = [k for k in phishing_keywords if k in subject_lower]
    if matched:
        anomalies.append(f"Suspicious subject keywords: {matched}")
        risk_indicators.append("SUSPICIOUS_SUBJECT")

    return {
        "source": "Header Analysis",
        "anomalies": anomalies,
        "risk_indicators": risk_indicators,
        "spf_status": spf,
        "dkim_status": dkim,
        "dmarc_status": dmarc,
        "reply_to_mismatch": reply_to != sender and reply_to != "N/A"
    }