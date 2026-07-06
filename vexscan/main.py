import argparse
import json
import os
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from modules import virustotal, abuseipdb, shodan_lookup, ai_analyst

console = Console()

def detect_target_type(target: str) -> str:
    import re
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    hash_pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$"
    if re.match(ip_pattern, target):
        return "ip"
    elif re.match(hash_pattern, target):
        return "hash"
    else:
        return "domain"

def save_report(target: str, results: list, ai_report: str, output_format: str = "json"):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if output_format == "json":
        filename = f"reports/{target.replace('.', '_')}_{timestamp}.json"
        report = {
            "target": target,
            "timestamp": timestamp,
            "intel": results,
            "ai_analysis": ai_report
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
    else:
        filename = f"reports/{target.replace('.', '_')}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.write(f"VexScan Report\n{'='*50}\n")
            f.write(f"Target: {target}\nTimestamp: {timestamp}\n\n")
            f.write("INTEL DATA\n" + "-"*50 + "\n")
            for r in results:
                f.write(str(r) + "\n\n")
            f.write("AI ANALYSIS\n" + "-"*50 + "\n")
            f.write(ai_report)

    return filename

def run_scan(target: str, output_format: str = "json"):
    target_type = detect_target_type(target)
    intel_results = []

    console.print(Panel(
        f"[bold cyan]VexScan[/bold cyan] | Target: [yellow]{target}[/yellow] | Type: [green]{target_type.upper()}[/green]",
        title="[bold red]OSINT Threat Intelligence[/bold red]"
    ))

    with console.status("[bold green]Querying VirusTotal..."):
        if target_type == "ip":
            vt = virustotal.scan_ip(target)
        elif target_type == "domain":
            vt = virustotal.scan_domain(target)
        else:
            vt = virustotal.scan_hash(target)
        intel_results.append(vt)
    console.print(f"[green]✓[/green] VirusTotal → Malicious: [red]{vt.get('malicious', 'N/A')}[/red] | Suspicious: [yellow]{vt.get('suspicious', 'N/A')}[/yellow]")

    if target_type == "ip":
        with console.status("[bold green]Querying AbuseIPDB..."):
            abuse = abuseipdb.check_ip(target)
            intel_results.append(abuse)
        console.print(f"[green]✓[/green] AbuseIPDB → Confidence Score: [red]{abuse.get('abuse_confidence_score', 'N/A')}%[/red] | Reports: {abuse.get('total_reports', 'N/A')}")

        with console.status("[bold green]Querying Shodan..."):
            shodan = shodan_lookup.lookup_ip(target)
            intel_results.append(shodan)
        if "error" in shodan:
            console.print(f"[yellow]⚠[/yellow] Shodan → {shodan['error']} ({shodan.get('note', '')})")
        else:
            ports = shodan.get('open_ports', [])
            vulns = shodan.get('vulns', [])
            console.print(f"[green]✓[/green] Shodan → Open Ports: [cyan]{ports}[/cyan] | Vulns: [red]{vulns if vulns else 'None found'}[/red]")

    console.print()
    with console.status("[bold magenta]AI Analyst generating threat report..."):
        ai_report = ai_analyst.analyze(target, intel_results)

    console.print(Panel(
        ai_report,
        title="[bold magenta]AI Threat Analysis[/bold magenta]",
        border_style="magenta"
    ))

    filename = save_report(target, intel_results, ai_report, output_format)
    console.print(f"\n[bold green]Report saved →[/bold green] {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="VexScan — AI-powered OSINT Threat Intelligence Tool"
    )
    parser.add_argument("target", help="IP address, domain, or file hash to scan")
    parser.add_argument(
        "--output",
        choices=["json", "txt"],
        default="json",
        help="Report output format (default: json)"
    )
    args = parser.parse_args()
    run_scan(args.target, args.output)

if __name__ == "__main__":
    main()