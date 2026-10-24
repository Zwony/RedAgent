"""Command Line Interface (CLI) for RedAgent platform."""
import argparse
import asyncio
import json
import os
import sys
from typing import Any, Dict

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


def print_banner():
    if HAS_RICH:
        console.print(
            Panel.fit(
                f"[bold red]REDAGENT[/bold red] [white]v{__version__}[/white] - [bold white]Automated AI Agent Red Teaming Platform[/bold white]\n"
                "[cyan]Stateful Multi-Agent Security Auditing Engine (OWASP Top 10 for LLM)[/cyan]",
                border_style="red",
            )
        )
    else:
        print("=" * 70)
        print(f"REDAGENT v{__version__} - Automated AI Agent Red Teaming Platform")
        print("Stateful Multi-Agent Security Auditing Engine (OWASP Top 10 for LLM)")
        print("=" * 70)


def display_report(final_state: RedTeamState):
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


async def run_scan_async(target: TargetInfo, output_path: str = None) -> RedTeamState:
    engine = RedTeamGraphEngine()
    final_state = await engine.run(target=target)
    display_report(final_state)

    if output_path and final_state.audit_report:
        report_data = final_state.audit_report.model_dump(mode="json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        console.print(f"[bold green][OK] Audit report exported to: {output_path}[/bold green]\n")

    return final_state


def cmd_scan(args: argparse.Namespace):
    print_banner()
    if not os.path.exists(args.target):
        console.print(f"[bold red]Error: Target config file not found: {args.target}[/bold red]")
        sys.exit(1)

    with open(args.target, "r", encoding="utf-8") as f:
        data = json.load(f)

    target = TargetInfo.model_validate(data)

    # Authorization enforcement for live remote endpoints
    if target.endpoint_url and not args.authorized:
        console.print(
            "\n[bold red][!] AUTHORIZATION REQUIRED:[/bold red] "
            f"Target '{target.name}' specifies a live remote endpoint ({target.endpoint_url}).\n"
            "Testing systems without prior explicit written permission is strictly prohibited by law.\n"
            "To confirm that you have valid authorization to audit this system, re-run with: [bold cyan]--authorized[/bold cyan]\n"
        )
        sys.exit(1)

    console.print(f"[bold yellow]=> Loaded Target Profile:[/bold yellow] {target.name} ({target.target_id})")
    asyncio.run(run_scan_async(target, args.output))


def cmd_demo(args: argparse.Namespace):
    from main import main as run_demo_main
    asyncio.run(run_demo_main())


def cmd_version(args: argparse.Namespace):
    print(f"RedAgent version {__version__}")


def main():
    parser = argparse.ArgumentParser(
        prog="redagent",
        description="RedAgent: Automated AI Agent Red Teaming & Security Auditing Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run automated security audit against a target AI agent")
    scan_parser.add_argument("--target", "-t", required=True, help="Path to target agent JSON configuration file")
    scan_parser.add_argument("--output", "-o", help="Optional path to export JSON audit report (e.g., report.json)")
    scan_parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm that you have written authorization to conduct security testing on the target system.",
    )
    scan_parser.set_defaults(func=cmd_scan)

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

    args.func(args)


if __name__ == "__main__":
    main()
