#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║           NetSentinel v1.0                          ║
║     AI-Powered Network Vulnerability Scanner        ║
║     Domain: Pentesting / Network Security           ║
╚══════════════════════════════════════════════════════╝

LEGAL DISCLAIMER:
  Use NetSentinel only on networks you own or have
  explicit written permission to test. Unauthorized
  scanning is illegal and unethical.

Usage:
  python main.py --target 192.168.1.1
  python main.py --target 192.168.1.0/24 --ports 1-65535
  python main.py --target scanme.nmap.org --type aggressive
"""

import argparse
import sys
import os
import json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import box
from rich.rule import Rule

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.scanner import NetworkScanner
from ml.model import NetSentinelAI
from report.report import generate_html_report, generate_json_report

console = Console()

BANNER = """
[bold cyan]
 ███╗   ██╗███████╗████████╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
 ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
 ██║ ╚████║███████╗   ██║   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
[/bold cyan]
[dim]         AI-Powered Network Vulnerability Scanner · Pentesting Domain · v1.0[/dim]
"""

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "NONE": "dim",
    "UNKNOWN": "dim"
}


def print_banner():
    console.print(BANNER)
    console.print(
        Panel(
            "[yellow]⚠️  LEGAL NOTICE:[/yellow] Use only on networks you [bold]own[/bold] or have "
            "[bold]explicit written permission[/bold] to test.\n"
            "Unauthorized scanning is illegal. The author assumes no liability.",
            border_style="yellow",
            expand=False
        )
    )
    console.print()


def print_host_results(host: dict, ai: dict):
    """Pretty print results for a single host."""
    risk = ai.get("risk_level", "UNKNOWN")
    risk_style = RISK_COLORS.get(risk, "dim")
    is_anomaly = ai.get("is_anomaly", False)

    console.print(Rule(f"[bold cyan]{host['ip']}[/bold cyan] · {host.get('hostname', 'N/A')}"))

    # Risk summary
    anomaly_str = " [bold red]⚠ ANOMALY![/bold red]" if is_anomaly else ""
    console.print(
        f"  Risk Level: [{risk_style}]{risk}[/{risk_style}]  |  "
        f"AI Confidence: [cyan]{ai.get('confidence', 0)}%[/cyan]  |  "
        f"OS: [dim]{host.get('os_guess', 'Unknown')}[/dim]"
        f"{anomaly_str}"
    )
    console.print()

    # Ports table
    if host.get("open_ports"):
        table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold cyan",
            border_style="dim"
        )
        table.add_column("Port", style="bold", width=10)
        table.add_column("Service", width=12)
        table.add_column("Version", width=25)
        table.add_column("Risk", width=10)
        table.add_column("Reason", style="dim")

        for p in host["open_ports"]:
            rs = RISK_COLORS.get(p["known_risk"], "dim")
            table.add_row(
                f"{p['port']}/{p['protocol']}",
                p["service"],
                f"{p.get('product', '')} {p.get('version', '')}".strip() or "—",
                f"[{rs}]{p['known_risk']}[/{rs}]",
                p.get("risk_reason", "N/A")
            )

        console.print(table)
    else:
        console.print("  [dim]No open ports found.[/dim]\n")

    # AI Explanation
    console.print("  [bold]🤖 AI Analysis:[/bold]")
    for line in ai.get("explanation", []):
        console.print(f"   • {line}")
    console.print()


def run_scan(args):
    """Main scan orchestration."""
    print_banner()

    # Init components
    console.print("[bold]Initializing AI engine...[/bold]")
    ai_engine = NetSentinelAI()
    model_info = ai_engine.get_model_info()
    console.print(
        f"  [green]✓[/green] {model_info['classifier']} loaded\n"
        f"  [green]✓[/green] {model_info['anomaly_detector']} loaded\n"
        f"  [green]✓[/green] Trained on {model_info['training_samples']} samples\n"
    )

    scanner = NetworkScanner()
    ai_results = {}

    # Run scan
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Scanning [cyan]{args.target}[/cyan] (ports {args.ports})...", total=None)
        scan_data = scanner.scan(args.target, args.ports, args.type)
        progress.update(task, completed=True)

    console.print(f"\n  [green]✓[/green] Scan complete. Found [bold]{len(scan_data['hosts'])}[/bold] host(s).\n")

    # AI Analysis per host
    console.print("[bold]Running AI analysis...[/bold]\n")
    for host in scan_data["hosts"]:
        feature_vec = scanner.get_feature_vector(host.get("open_ports", []))
        ai_result = ai_engine.analyze(feature_vec, host.get("open_ports", []))
        ai_results[host["ip"]] = ai_result
        print_host_results(host, ai_result)

    # Generate reports
    console.print(Rule("[bold]Reports[/bold]"))
    os.makedirs(args.output, exist_ok=True)
    html_path = os.path.join(args.output, "report.html")
    json_path = os.path.join(args.output, "report.json")

    generate_html_report(scan_data, ai_results, html_path)
    generate_json_report(scan_data, ai_results, json_path)

    console.print(f"\n  [bold green]✓ Reports saved to:[/bold green] [cyan]{args.output}/[/cyan]")
    console.print(f"    → HTML: {html_path}")
    console.print(f"    → JSON: {json_path}\n")

    console.print(
        Panel(
            "[green]Scan complete![/green] Open the HTML report in your browser for the full visual analysis.",
            border_style="green"
        )
    )


def main():
    parser = argparse.ArgumentParser(
        prog="netsentinel",
        description="NetSentinel — AI-Powered Network Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 192.168.1.1
  python main.py --target 192.168.1.0/24 --ports 1-65535
  python main.py --target scanme.nmap.org --type aggressive --output results/
        """
    )
    parser.add_argument("--target", required=True, help="Target IP, hostname, or CIDR range")
    parser.add_argument("--ports", default="1-1024", help="Port range (default: 1-1024)")
    parser.add_argument(
        "--type", choices=["basic", "aggressive"], default="basic",
        help="Scan type: basic (TCP+version) or aggressive (OS+version) [default: basic]"
    )
    parser.add_argument("--output", default="output", help="Output directory for reports [default: output/]")

    args = parser.parse_args()

    try:
        run_scan(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
