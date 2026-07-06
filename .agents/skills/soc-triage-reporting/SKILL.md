---
name: soc-triage-reporting
description: Document formatting guidelines, severity criteria, and analyst ticket note rules for reporting security alerts.
---

# SOC Triage Reporting Skill

## Report Structure

All reports must be formatted in clean markdown, containing exactly the following sections in order:

1. **Alert Summary**: A concise summary of the alert being triaged.
2. **OSINT Findings**: The intelligence gathered from VirusTotal, AbuseIPDB, Shodan, etc.
3. **Forensic Findings**: The results of email header analysis, URL scans, and file/payload analysis.
4. **Severity**: The assigned severity level (Critical, High, Medium, Low) based on the criteria below.
5. **Recommended Action**: Clear and actionable next steps.

## Severity Criteria

Assigned severity must follow these definitions:
- **Critical**: Confirmed malicious activity with active impact (e.g., confirmed phishing with clicked links, active C2 communication, known malware execution on a host).
- **High**: Suspicious activity with high likelihood of threat (e.g., spoofed email headers failing SPF/DKIM/DMARC with suspicious links, binary hash flagged by multiple VT engines, known bad IP from AbuseIPDB with >50% confidence).
- **Medium**: Activity requiring investigation but with no active malicious indicators (e.g., open ports on internal hosts, suspicious subject keywords but valid email authentication headers).
- **Low**: Legitimate activity or low-risk alerts (e.g., standard DNS servers like 8.8.8.8, false positives, clean reputation across all sources).

## Tone and Style

The report must conclude with a brief **Ticket Note** section. The note must:
- Mimic the tone of a professional SOC analyst's ticket comment.
- Be under 200 words.
- Be concise, technical, and objective.
