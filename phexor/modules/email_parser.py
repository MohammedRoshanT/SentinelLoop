# modules/email_parser.py

import email
import re
from email import policy
from email.parser import BytesParser

def parse_eml(file_path: str) -> dict:
    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # Basic headers
    sender = msg.get("From", "N/A")
    reply_to = msg.get("Reply-To", "N/A")
    to = msg.get("To", "N/A")
    subject = msg.get("Subject", "N/A")
    date = msg.get("Date", "N/A")
    message_id = msg.get("Message-ID", "N/A")

    # Auth headers
    spf = msg.get("Received-SPF", "N/A")
    dkim = msg.get("DKIM-Signature", "N/A")
    dmarc = msg.get("Authentication-Results", "N/A")

    # Extract sender IP from Received headers
    received = msg.get_all("Received", [])
    sender_ip = extract_sender_ip(received)

    # Extract body
    body = extract_body(msg)

    # Extract URLs from body
    urls = extract_urls(body)

    # Extract attachments
    attachments = extract_attachments(msg)

    return {
        "sender": sender,
        "reply_to": reply_to,
        "to": to,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "spf": spf,
        "dkim": "Present" if dkim != "N/A" else "Missing",
        "dmarc": dmarc,
        "sender_ip": sender_ip,
        "urls": urls,
        "attachments": attachments,
        "body_preview": body[:500] if body else "N/A"
    }

def extract_sender_ip(received_headers: list) -> str:
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    for header in received_headers:
        ips = re.findall(ip_pattern, header)
        for ip in ips:
            if not ip.startswith(("127.", "10.", "192.168.", "172.")):
                return ip
    return "N/A"

def extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body += part.get_content()
                except:
                    pass
    else:
        try:
            body = msg.get_content()
        except:
            pass
    return body

def extract_urls(text: str) -> list:
    url_pattern = r"https?://[^\s<>\"\'{}|\\^`\[\]]+"
    urls = re.findall(url_pattern, text)
    return list(set(urls))

def extract_attachments(msg) -> list:
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()
            content_type = part.get_content_type()
            if filename:
                attachments.append({
                    "filename": filename,
                    "content_type": content_type
                })
    return attachments