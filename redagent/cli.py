"""Command Line Interface (CLI) for RedAgent platform."""
import argparse
import asyncio
import importlib.util
import json
import os
import sys
from typing import Any, Dict, Optional

from redagent import __version__
from redagent.core.graph import RedTeamGraphEngine
from redagent.schemas.state import RedTeamState
from redagent.schemas.target import (
    EndpointType,
    TargetInfo,
    TargetToolDefinition,
    TargetToolParameter,
)

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    class PlainConsole:
        def print(self, *args: Any, **kwargs: Any) -> None:
            import re
            clean = [re.sub(r"\[.*?\]", "", str(a)) for a in args]
            print(*clean)
    console = PlainConsole()  # type: ignore


BANNER_ART = r"""
  ____          _   _                    _   
 |  _ \ ___  __| | / \   __ _  ___ _ __ | |_ 
 | |_) / _ \/ _` |/ _ \ / _` |/ _ \ '_ \| __|
 |  _ <  __/ (_| / ___ \ (_| |  __/ | | | |_ 
 |_| \_\___|\__,_/_/   \_\__, |\___|_| |_|\__|
                         |___/                
"""


def print_banner() -> None:
    """Renders the ASCII banner and compliance disclaimer to the console."""
    if HAS_RICH:
        console.print(f"[bold red]{BANNER_ART}[/bold red]")
        console.print(
            Panel.fit(
                f"[bold white]RedAgent v{__version__}[/bold white] | [cyan]Automated AI Agent Red Teaming Platform (OWASP Top 10 for LLM)[/cyan]\n"
                "[dim]Notice: Intended for authorized security auditing & research. Operator assumes all legal responsibility.[/dim]",
                border_style="red",
            )
        )
    else:
        print(BANNER_ART)
        print("=" * 70)
        print(f"RedAgent v{__version__} - Automated AI Agent Red Teaming Platform")
        print("Stateful Multi-Agent Security Auditing Engine (OWASP Top 10 for LLM)")
        print("Notice: Intended for authorized security auditing & research. Operator assumes all legal responsibility.")
        print("=" * 70)


def display_report(final_state: RedTeamState) -> None:
    """Formats and prints executive audit posture and findings to the console.

    Args:
        final_state: Graph state containing evaluated findings and metrics.
    """
    report = final_state.audit_report
    if not report:
        console.print("[bold red]Audit did not produce a report.[/bold red]")
        return

    if HAS_RICH:
        summary_table = Table(title="Security Audit Posture Summary", border_style="cyan")
        summary_table.add_column("Metric", style="bold white")
        summary_table.add_column("Value", style="bold yellow")

        rating_color = "green" if report.overall_rating.value == "SECURE" else "red"
        summary_table.add_row("Target Name", report.target_name)
        summary_table.add_row("Overall Rating", f"[{rating_color}]{report.overall_rating.value}[/]")
        summary_table.add_row("Max Risk Score", f"{report.overall_risk_score:.1f} / 10.0")
        summary_table.add_row("Total Test Cases", str(report.total_tests_executed))
        summary_table.add_row("Findings Detected", str(report.vulnerabilities_found))

        console.print(summary_table)
        console.print()

        if report.findings:
            findings_table = Table(title="Vulnerability Findings & Evaluator Analysis", border_style="red")
            findings_table.add_column("Finding ID", style="dim")
            findings_table.add_column("Category", style="cyan")
            findings_table.add_column("Severity", style="bold red")
            findings_table.add_column("Status", style="yellow")
            findings_table.add_column("Remediation Action", style="white")

            for f in report.findings:
                findings_table.add_row(
                    f.finding_id,
                    f.category.value[:30],
                    f.severity.value,
                    f.status.value,
                    f.remediation_suggestion[:60] + "...",
                )

            console.print(findings_table)
            console.print()
    else:
        print("\n--- SECURITY AUDIT POSTURE SUMMARY ---")
        print(f"Target: {report.target_name} ({report.target_id})")
        print(f"Overall Rating: {report.overall_rating.value} (Risk Score: {report.overall_risk_score:.1f}/10.0)")
        print(f"Total Tests Executed: {report.total_tests_executed}")
        print(f"Findings Detected: {report.vulnerabilities_found}")
        print("\n--- FINDINGS ---")
        for f in report.findings:
            print(f"[{f.severity.value}] {f.title} ({f.category.value}) - Status: {f.status.value}")
            print(f"   Remediation: {f.remediation_suggestion}")

    if report.remediation_roadmap:
        console.print("[bold magenta]=> Hardening & Guardrail Remediation Roadmap:[/bold magenta]")
        for action in report.remediation_roadmap:
            console.print(f"  [bold cyan]#{action.priority}[/bold cyan] [bold white][{action.target_component}][/bold white]: {action.recommendation}")
            if action.example_mitigation:
                console.print(f"     [dim green]Suggested Rule/Mitigation: {action.example_mitigation}[/dim green]")
        console.print()


def export_audit_report(
    report: Any,
    output_path: str,
    report_format: str = "auto",
) -> None:
    """Exports an evaluated audit report to the requested filesystem destination.

    Args:
        report: Evaluated audit report model instance.
        output_path: Destination file path.
        report_format: Export format ('auto', 'json', 'markdown', or 'html').
    """
    out_lower = output_path.lower()
    is_html = report_format == "html" or (
        report_format == "auto" and out_lower.endswith(".html")
    )
    is_md = report_format == "markdown" or (
        report_format == "auto" and (out_lower.endswith(".md") or out_lower.endswith(".markdown"))
    )

    if is_html:
        html_content = report.to_html()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        console.print(f"[bold green][OK] Standalone HTML audit report exported to: {output_path}[/bold green]\n")
    elif is_md:
        md_content = report.to_markdown()
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"[bold green][OK] Markdown audit report exported to: {output_path}[/bold green]\n")
    else:
        report_data = report.model_dump(mode="json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green][OK] JSON audit report exported to: {output_path}[/bold green]\n")


async def run_scan_async(
    target: TargetInfo,
    output_path: Optional[str] = None,
    report_format: str = "auto",
) -> RedTeamState:
    """Executes the red team DAG and exports audit reports.

    Args:
        target: Target AI agent profile and boundary specifications.
        output_path: Optional destination filesystem path for export.
        report_format: Export format ('auto', 'json', 'markdown', or 'html').

    Returns:
        RedTeamState: Completed state containing audit reports and logs.
    """
    engine = RedTeamGraphEngine()
    final_state = await engine.run(target=target)
    display_report(final_state)

    if output_path and final_state.audit_report:
        export_audit_report(final_state.audit_report, output_path, report_format)

    return final_state


def cmd_scan(args: argparse.Namespace) -> None:
    """Dispatches a full security audit against the configured target profile.

    Args:
        args: Parsed command line arguments from the scan parser.
    """
    print_banner()
    if not os.path.exists(args.target):
        console.print(f"[bold red]Error: Target config file not found: {args.target}[/bold red]")
        sys.exit(1)

    with open(args.target, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = TargetInfo.model_validate(data)

    if target.endpoint_url:
        console.print(f"[dim]Live target configured: {target.endpoint_url}[/dim]")

    console.print(f"[bold yellow]=> Loaded Target Profile:[/bold yellow] {target.name} ({target.target_id})")
    asyncio.run(run_scan_async(target, args.output, getattr(args, "format", "auto")))


def cmd_init(args: argparse.Namespace) -> None:
    """Scaffolds a new starter target AI agent configuration file.

    Args:
        args: Parsed command line arguments specifying target name and output path.
    """
    output_path = args.output or "target.json"
    if os.path.exists(output_path) and not args.force:
        console.print(f"[bold red]Error: '{output_path}' already exists. Use --force to overwrite.[/bold red]")
        sys.exit(1)

    starter_profile = {
        "target_id": "target_agent_01",
        "name": args.name or "Enterprise Assistant",
        "description": "Production customer query and operational assistant",
        "endpoint_type": "rest_api",
        "endpoint_url": "https://api.example.com/v1/chat",
        "auth_headers": {
            "Authorization": "Bearer YOUR_API_TOKEN_HERE"
        },
        "request_template": {
            "prompt": "{{prompt}}"
        },
        "has_rag": True,
        "rag_sources": ["knowledge_base_faq", "internal_policy_docs"],
        "accessible_tools": [
            {
                "name": "query_order_status",
                "description": "Fetch customer order details given order_id",
                "parameters": [
                    {
                        "name": "order_id",
                        "param_type": "string",
                        "description": "Customer order number",
                        "is_required": True
                    }
                ],
                "is_sensitive": False
            },
            {
                "name": "refund_transaction",
                "description": "Initiate financial refund transaction",
                "parameters": [
                    {
                        "name": "transaction_id",
                        "param_type": "string",
                        "description": "Transaction identifier",
                        "is_required": True
                    },
                    {
                        "name": "amount",
                        "param_type": "float",
                        "description": "Refund amount",
                        "is_required": True
                    }
                ],
                "is_sensitive": True,
                "risk_notes": "Financial state mutation capability"
            }
        ]
    }

    parent_dir = os.path.dirname(os.path.abspath(output_path))
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(starter_profile, f, indent=2, ensure_ascii=False)

    console.print(f"[bold green][OK] Target profile created: {output_path}[/bold green]")
    console.print(f"[dim]Run security audit with: redagent scan --target {output_path} -o audit_report.md[/dim]\n")


def cmd_demo(args: argparse.Namespace) -> None:
    """Executes the pre-configured mock banking assistant sandbox demo.

    Args:
        args: Parsed command line arguments.
    """
    from main import main as run_demo_main
    asyncio.run(run_demo_main())


def cmd_ui(args: argparse.Namespace) -> None:
    """Launches the interactive Streamlit security dashboard.

    Args:
        args: Parsed command line arguments specifying host and port bindings.
    """
    if importlib.util.find_spec("streamlit") is None:
        console.print("[bold red]Streamlit is not installed.[/bold red]")
        console.print(
            "Please install it using: [bold green]pip install \"redagent[ui]\"[/bold green] "
            "or [bold green]pip install streamlit[/bold green]"
        )
        sys.exit(1)

    import subprocess
    ui_script = os.path.join(os.path.dirname(__file__), "ui", "app.py")
    port = str(getattr(args, "port", 8501))
    host = str(getattr(args, "host", "localhost"))
    console.print(f"[bold green]Starting RedAgent Web Dashboard at http://{host}:{port}...[/bold green]")
    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        ui_script,
        f"--server.port={port}",
        f"--server.address={host}",
        "--server.headless=true",
        "--browser.gatherUsageStats=false",
    ]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[dim]Web Dashboard stopped by user.[/dim]")


def cmd_version(args: argparse.Namespace) -> None:
    """Displays the active RedAgent version string.

    Args:
        args: Parsed command line arguments.
    """
    print(f"RedAgent version {__version__}")


def cmd_update(args: argparse.Namespace) -> None:
    """Checks for newer releases and initiates automated package upgrades.

    Args:
        args: Parsed command line arguments.
    """
    from redagent.core.updater import (
        check_and_prompt_update,
        get_cached_latest_version,
        is_newer_version,
    )
    console.print(f"[dim]Checking for RedAgent updates (current: v{__version__})...[/dim]")
    latest = get_cached_latest_version(force=True)
    if not latest:
        console.print("[yellow]Unable to fetch latest release information. Please check network connection.[/yellow]")
        return
    if is_newer_version(__version__, latest):
        check_and_prompt_update(force=True)
    else:
        console.print(f"[bold green][OK] RedAgent is up to date (v{__version__}).[/bold green]")


def main() -> None:
    """Entry point for the RedAgent CLI command processor."""
    parser = argparse.ArgumentParser(
        prog="redagent",
        description="RedAgent: Automated AI Agent Red Teaming & Security Auditing Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: init
    init_parser = subparsers.add_parser("init", help="Generate a starter target AI agent configuration file")
    init_parser.add_argument("--output", "-o", default="target.json", help="Destination path (default: target.json)")
    init_parser.add_argument("--name", "-n", default="Enterprise Assistant", help="Target agent display name")
    init_parser.add_argument("--force", "-f", action="store_true", help="Overwrite file if it already exists")
    init_parser.set_defaults(func=cmd_init)

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run automated security audit against a target AI agent")
    scan_parser.add_argument("--target", "-t", required=True, help="Path to target agent JSON configuration file")
    scan_parser.add_argument("--output", "-o", help="Path to export audit report (e.g., report.html, report.md, or report.json)")
    scan_parser.add_argument(
        "--format",
        choices=["auto", "json", "markdown", "html"],
        default="auto",
        help="Report export format: auto (by file extension), html, markdown, or json",
    )
    scan_parser.add_argument(
        "--authorized",
        action="store_true",
        help="Optional compliance flag recording explicit test authorization in audit logs.",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # Command: ui
    ui_parser = subparsers.add_parser("ui", help="Launch the interactive Web UI dashboard (Streamlit)")
    ui_parser.add_argument("--port", "-p", type=int, default=8501, help="Port to bind dashboard server (default: 8501)")
    ui_parser.add_argument("--host", default="localhost", help="Host address to bind dashboard (default: localhost)")
    ui_parser.set_defaults(func=cmd_ui)

    # Command: update
    update_parser = subparsers.add_parser("update", help="Check for and install RedAgent platform updates")
    update_parser.set_defaults(func=cmd_update)

    # Command: demo
    demo_parser = subparsers.add_parser("demo", help="Run internal mock sandbox demonstration")
    demo_parser.set_defaults(func=cmd_demo)

    # Command: version
    version_parser = subparsers.add_parser("version", help="Print RedAgent version")
    version_parser.set_defaults(func=cmd_version)

    args = parser.parse_args()
    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    # Non-intrusive update notification for interactive terminal sessions
    if args.command not in ("version", "update"):
        try:
            from redagent.core.updater import check_and_prompt_update
            check_and_prompt_update()
        except Exception:
            pass

    args.func(args)


if __name__ == "__main__":
    main()
