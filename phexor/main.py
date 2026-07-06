# main.py

import argparse
import json
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules import email_parser, header_analyzer, url_scanner, ai_analyst

console = Console()

def save_report(email_file: str, parsed: dict, headers: dict, urls: list, ai_report: str, output_format: str):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.basename(email_file).replace(".eml", "")

    if output_format == "json":
        filename = f"reports/{base_name}_{timestamp}.json"
        report = {
            "file": email_file,
            "timestamp": timestamp,
            "parsed_email": parsed,
            "header_analysis": headers,
            "url_results": urls,
            "ai_analysis": ai_report
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
    else:
        filename = f"reports/{base_name}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"Phexor Report\n{'='*50}\n")
            f.write(f"File: {email_file}\nTimestamp: {timestamp}\n\n")
            f.write("EMAIL METADATA\n" + "-"*50 + "\n")
            for k, v in parsed.items():
                f.write(f"{k}: {v}\n")
            f.write("\nHEADER ANALYSIS\n" + "-"*50 + "\n")
            for anomaly in headers.get("anomalies", []):
                f.write(f"  • {anomaly}\n")
            f.write("\nURL RESULTS\n" + "-"*50 + "\n")
            for r in urls:
                f.write(str(r) + "\n")
            f.write("\nAI ANALYSIS\n" + "-"*50 + "\n")
            f.write(ai_report)

    return filename

def display_email_summary(parsed: dict):
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan", width=15)
    table.add_column("Value", style="white")

    table.add_row("From", parsed.get("sender", "N/A"))
    table.add_row("Reply-To", parsed.get("reply_to", "N/A"))
    table.add_row("Subject", parsed.get("subject", "N/A"))
    table.add_row("Date", parsed.get("date", "N/A"))
    table.add_row("Sender IP", parsed.get("sender_ip", "N/A"))
    table.add_row("SPF", parsed.get("spf", "N/A"))
    table.add_row("DKIM", parsed.get("dkim", "N/A"))
    table.add_row("URLs Found", str(len(parsed.get("urls", []))))
    table.add_row("Attachments", str(len(parsed.get("attachments", []))))

    console.print(Panel(table, title="[bold cyan]Email Summary[/bold cyan]"))

def display_header_anomalies(headers: dict):
    anomalies = headers.get("anomalies", [])
    if not anomalies:
        console.print("[green]✓[/green] No header anomalies detected")
        return
    console.print(f"[red]⚠[/red] Header Anomalies Found: [red]{len(anomalies)}[/red]")
    for a in anomalies:
        console.print(f"  [yellow]→[/yellow] {a}")

def display_url_results(url_results: list):
    if not url_results:
        console.print("[yellow]⚠[/yellow] No URLs found in email body")
        return
    for r in url_results:
        url = r.get("url", "N/A")
        vt = r.get("virustotal", {})
        us = r.get("urlscan", {})
        malicious_vt = vt.get("malicious", 0)
        malicious_us = us.get("malicious", False)
        status = "[red]MALICIOUS[/red]" if malicious_vt > 0 or malicious_us else "[green]CLEAN[/green]"
        console.print(f"  [cyan]→[/cyan] {url[:60]}... | VT: [red]{malicious_vt}[/red] detections | URLscan: {status}")

def run_scan(email_file: str, output_format: str):
    if not os.path.exists(email_file):
        console.print(f"[red]Error:[/red] File not found: {email_file}")
        return

    console.print(Panel(
        f"[bold cyan]Phexor[/bold cyan] | File: [yellow]{email_file}[/yellow]",
        title="[bold red]Phishing Email Analyzer[/bold red]"
    ))

    # Parse email
    with console.status("[bold green]Parsing email..."):
        parsed = email_parser.parse_eml(email_file)
    display_email_summary(parsed)

    # Analyze headers
    with console.status("[bold green]Analyzing headers..."):
        headers = header_analyzer.analyze_headers(parsed)
    display_header_anomalies(headers)

    # Scan URLs
    urls = parsed.get("urls", [])
    url_results = []
    if urls:
        console.print(f"\n[bold green]Scanning {min(len(urls), 5)} URL(s)...[/bold green]")
        url_results = url_scanner.scan_all_urls(urls)
        display_url_results(url_results)
    else:
        console.print("[yellow]⚠[/yellow] No URLs found to scan")

    # AI Analysis
    console.print()
    with console.status("[bold magenta]AI Analyst generating phishing verdict..."):
        ai_report = ai_analyst.analyze(parsed, headers, url_results)

    console.print(Panel(
        ai_report,
        title="[bold magenta]AI Phishing Analysis[/bold magenta]",
        border_style="magenta"
    ))

    # Save report
    filename = save_report(email_file, parsed, headers, url_results, ai_report, output_format)
    console.print(f"\n[bold green]Report saved →[/bold green] {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Phexor — AI-powered Phishing Email Analyzer"
    )
    parser.add_argument("email_file", help="Path to .eml file to analyze")
    parser.add_argument(
        "--output",
        choices=["json", "txt"],
        default="json",
        help="Report output format (default: json)"
    )
    args = parser.parse_args()
    run_scan(args.email_file, args.output)

if __name__ == "__main__":
    main()