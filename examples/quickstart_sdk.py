"""Quickstart example demonstrating how to run RedAgent programmatically as a Python SDK."""
import asyncio
from redagent import RedTeamGraphEngine, TargetInfo, TargetToolDefinition


async def main():
    # 1. Define your AI Agent profile
    target = TargetInfo(
        target_id="my_production_bot",
        name="Support Assistant",
        description="Customer facing AI bot with database tool access",
        endpoint_type="direct_prompt",
        accessible_tools=[
            TargetToolDefinition(
                name="query_database",
                description="Executes read-only SQL queries for customer support",
                is_sensitive=True,
            )
        ],
        has_rag=True,
        rag_sources=["product_knowledge_base"],
    )

    # 2. Initialize Red Teaming Engine
    engine = RedTeamGraphEngine()

    # 3. Execute the automated Red Team audit
    print(f"[*] Starting RedAgent Security Audit against: {target.name}...")
    final_state = await engine.run(target=target)

    # 4. Inspect report results
    report = final_state.audit_report
    print(f"\n[+] Audit Completed!")
    print(f"    Target Posture: {report.overall_rating.value}")
    print(f"    Risk Score: {report.overall_risk_score:.1f} / 10.0")
    print(f"    Vulnerabilities Detected: {report.vulnerabilities_found}")

    # 5. Review remediation actions
    print("\n[+] Recommended Hardening Actions:")
    for action in report.remediation_roadmap:
        print(f"    - [{action.target_component}] {action.recommendation}")


if __name__ == "__main__":
    asyncio.run(main())
