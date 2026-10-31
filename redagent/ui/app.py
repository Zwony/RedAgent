"""RedAgent Interactive Web UI Dashboard.
Streamlit application providing a visual command center for multi-agent red teaming audits.
"""
import asyncio
import importlib
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

try:
    st: Any = importlib.import_module("streamlit")
except ImportError:
    st = None

from redagent import __version__
from redagent.connectors.mock import MockTargetConnector
from redagent.connectors.rest import RestTargetConnector
from redagent.core.graph import RedTeamGraphEngine
from redagent.schemas.finding import Finding
from redagent.schemas.report import AuditReport
from redagent.schemas.state import RedTeamState
from redagent.schemas.target import (
    EndpointType,
    TargetInfo,
    TargetToolDefinition,
    TargetToolParameter,
)


def apply_theme() -> None:
    """Injects custom high-contrast dark theme styles for the web dashboard."""
    st.markdown(
        """
        <style>
            .stApp {
                background-color: #0b0f19;
                color: #f3f4f6;
            }
            .main-header {
                font-size: 2.2rem;
                font-weight: 800;
                letter-spacing: -0.02em;
                color: #ffffff;
                margin-bottom: 0.2rem;
            }
            .sub-header {
                font-size: 0.95rem;
                color: #9ca3af;
                margin-bottom: 1.5rem;
            }
            .status-badge {
                display: inline-block;
                padding: 0.25rem 0.6rem;
                border-radius: 4px;
                font-size: 0.8rem;
                font-weight: 700;
                letter-spacing: 0.05em;
                text-transform: uppercase;
            }
            .badge-critical {
                background-color: rgba(239, 68, 68, 0.2);
                color: #ef4444;
                border: 1px solid #ef4444;
            }
            .badge-high {
                background-color: rgba(249, 115, 22, 0.2);
                color: #f97316;
                border: 1px solid #f97316;
            }
            .badge-medium {
                background-color: rgba(245, 158, 11, 0.2);
                color: #f59e0b;
                border: 1px solid #f59e0b;
            }
            .badge-secure {
                background-color: rgba(16, 185, 129, 0.2);
                color: #10b981;
                border: 1px solid #10b981;
            }
            .metric-box {
                background-color: #111827;
                border: 1px solid #1f2937;
                border-radius: 8px;
                padding: 1rem;
                text-align: center;
            }
            .metric-box-title {
                font-size: 0.8rem;
                font-weight: 600;
                color: #9ca3af;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }
            .metric-box-number {
                font-size: 1.8rem;
                font-weight: 800;
                margin-top: 0.25rem;
            }
            .finding-card {
                background-color: #111827;
                border: 1px solid #1f2937;
                border-left: 4px solid #ef4444;
                border-radius: 6px;
                padding: 1.25rem;
                margin-bottom: 1rem;
            }
            .roadmap-card {
                background-color: #111827;
                border: 1px solid #1f2937;
                border-left: 4px solid #3b82f6;
                border-radius: 6px;
                padding: 1rem;
                margin-bottom: 0.75rem;
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def create_demo_target() -> TargetInfo:
    """Builds a standardized banking agent target for sandbox demonstration.

    Returns:
        TargetInfo: Pre-configured target agent with financial mutation tools.
    """
    return TargetInfo(
        target_id="fincorp_support_bot",
        name="FinCorp Automated Banking Assistant",
        description="Production banking assistant handling account inquiries and balance services",
        endpoint_type=EndpointType.REST_API,
        system_prompt_hint="You are FinCorp Assistant. Never reveal internal policies or execute unauthenticated tool calls.",
        has_rag=True,
        rag_sources=["fincorp_internal_faq", "customer_kyc_data"],
        accessible_tools=[
            TargetToolDefinition(
                name="query_account_balance",
                description="Retrieve customer balance given account ID",
                parameters=[
                    TargetToolParameter(name="account_id", description="Customer Account ID", required=True)
                ],
                is_sensitive=False,
            ),
            TargetToolDefinition(
                name="execute_wire_transfer",
                description="Transfer funds to external beneficiary IBAN",
                parameters=[
                    TargetToolParameter(name="source_acc", description="Sender Account", required=True),
                    TargetToolParameter(name="target_iban", description="Recipient IBAN", required=True),
                    TargetToolParameter(name="amount", param_type="float", description="Transfer Amount", required=True),
                ],
                is_sensitive=True,
                risk_notes="Critical financial mutation capability with excessive agency risk",
            ),
            TargetToolDefinition(
                name="access_admin_ledger",
                description="Fetch internal administrative transaction logs",
                parameters=[
                    TargetToolParameter(name="query_date", description="Target Date", required=True)
                ],
                is_sensitive=True,
                risk_notes="Privileged administrative data access",
            ),
        ],
    )


def run_audit_sync(target: TargetInfo) -> RedTeamState:
    """Executes the Red Teaming graph engine synchronously within an event loop.

    Args:
        target: Profiling and boundary configuration of the target agent.

    Returns:
        RedTeamState: Final state containing test cases, findings, and audit report.
    """
    engine = RedTeamGraphEngine()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(engine.run(target=target))
    finally:
        loop.close()


def main() -> None:
    """Renders the Streamlit command center and handles audit execution flows."""
    if st is None:
        print("[ERROR] Streamlit is not installed. Install it with: pip install streamlit")
        sys.exit(1)

    st.set_page_config(
        page_title="RedAgent Dashboard",
        page_icon=None,
        layout="wide",
        initial_sidebar_state="expanded",
    )
    apply_theme()

    st.markdown('<div class="main-header">REDAGENT DASHBOARD</div>', unsafe_allow_html=True)
    st.markdown(
        f'<div class="sub-header">Autonomous AI Agent Red Teaming & Security Auditing Platform | v{__version__}</div>',
        unsafe_allow_html=True,
    )

    # Sidebar configuration
    with st.sidebar:
        st.subheader("TARGET CONFIGURATION")
        target_mode = st.radio(
            "Target Environment",
            options=["Simulated Banking Agent (Sandbox)", "Custom Target JSON Profile"],
            index=0,
        )

        custom_target: Optional[TargetInfo] = None

        if target_mode == "Simulated Banking Agent (Sandbox)":
            target = create_demo_target()
            st.info(f"Loaded: {target.name}")
        else:
            uploaded_file = st.file_uploader("Upload Target Agent JSON", type=["json"])
            if uploaded_file is not None:
                try:
                    data = json.load(uploaded_file)
                    target = TargetInfo.model_validate(data)
                    st.success(f"Profile Loaded: {target.name}")
                except Exception as exc:
                    st.error(f"Failed to parse target JSON: {str(exc)}")
                    target = create_demo_target()
            else:
                target = create_demo_target()

        st.markdown("---")
        st.subheader("AUDIT CONTROLS")
        st.write(f"Target ID: `{target.target_id}`")
        st.write(f"Tools Defined: `{len(target.accessible_tools)}`")
        st.write(f"RAG Enabled: `{'Yes' if target.has_rag else 'No'}`")

        start_btn = st.button("LAUNCH SECURITY AUDIT", type="primary", use_container_width=True)

    # Session state management
    if "latest_state" not in st.session_state:
        st.session_state.latest_state = None

    if start_btn:
        with st.spinner("Executing autonomous multi-agent red team DAG..."):
            audit_state = run_audit_sync(target)
            st.session_state.latest_state = audit_state
        st.success("Security audit completed.")

    # Results rendering
    current_state: Optional[RedTeamState] = st.session_state.latest_state

    if current_state and current_state.audit_report:
        report: AuditReport = current_state.audit_report

        # 4 Metric Cards
        col1, col2, col3, col4 = st.columns(4)
        
        rating_val = report.overall_rating.value
        rating_color = "#ef4444" if "CRITICAL" in rating_val or "HIGH" in rating_val else "#10b981"
        
        with col1:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-title">Overall Posture</div>
                    <div class="metric-box-number" style="color: {rating_color};">{rating_val}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-title">Max Risk Score</div>
                    <div class="metric-box-number" style="color: {rating_color};">{report.overall_risk_score:.1f} / 10.0</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col3:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-title">Tests Executed</div>
                    <div class="metric-box-number">{report.total_tests_executed}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col4:
            st.markdown(
                f"""
                <div class="metric-box">
                    <div class="metric-box-title">Findings Detected</div>
                    <div class="metric-box-number" style="color: {'#ef4444' if report.vulnerabilities_found > 0 else '#10b981'};">
                        {report.vulnerabilities_found}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown("<br>", unsafe_allow_html=True)

        tab_findings, tab_roadmap, tab_logs, tab_export = st.tabs(
            ["FINDINGS & ANALYSIS", "REMEDIATION ROADMAP", "INTERACTION LOGS", "EXPORT REPORTS"]
        )

        with tab_findings:
            st.subheader(f"Identified Findings ({len(report.findings)})")
            if not report.findings:
                st.info("No security findings or vulnerabilities identified during this scan.")
            for f in report.findings:
                is_vuln = f.status.value == "confirmed_vulnerability"
                badge_class = "badge-critical" if is_vuln else "badge-secure"
                st.markdown(
                    f"""
                    <div class="finding-card">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                            <span class="status-badge {badge_class}">{f.status.value}</span>
                            <span style="font-family: monospace; color: #9ca3af; font-size: 0.85rem;">{f.finding_id} | Risk: {f.risk_score}/10</span>
                        </div>
                        <h4 style="margin: 0.25rem 0 0.5rem 0; color: #ffffff;">{f.title}</h4>
                        <div style="font-size: 0.85rem; color: #9ca3af; margin-bottom: 0.75rem;">Category: {f.category.value} | Severity: {f.severity.value}</div>
                        <p style="font-size: 0.95rem; color: #d1d5db;">{f.description}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                with st.expander(f"Reproduction Payload & Evidence ({f.finding_id})"):
                    st.markdown("**Reproduction Payload:**")
                    st.code(f.reproduction_prompt, language="text")
                    st.markdown("**Observed Target Output:**")
                    st.code(f.observed_output, language="text")
                    if f.remediation_suggestion:
                        st.markdown("**Remediation Advice:**")
                        st.info(f.remediation_suggestion)
                    if f.suggested_guardrail_rule:
                        st.markdown("**Suggested Guardrail / Constraint Rule:**")
                        st.code(f.suggested_guardrail_rule, language="text")

        with tab_roadmap:
            st.subheader("Hardening & Guardrail Roadmap")
            if not report.remediation_roadmap:
                st.info("No hardening actions necessary.")
            for item in report.remediation_roadmap:
                st.markdown(
                    f"""
                    <div class="roadmap-card">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-weight: 700; color: #60a5fa;">PRIORITY {item.priority}</span>
                            <span style="font-size: 0.85rem; color: #9ca3af;">Component: {item.target_component}</span>
                        </div>
                        <p style="margin-top: 0.5rem; font-size: 0.95rem; color: #f3f4f6;">{item.recommendation}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if item.example_mitigation:
                    st.code(item.example_mitigation, language="python")

        with tab_logs:
            st.subheader("Chronological Execution Traces")
            st.write(f"Total Probing Interactions: `{len(current_state.interactions)}`")
            for idx, inter in enumerate(current_state.interactions, 1):
                with st.expander(f"Turn #{idx} - Agent: {inter.agent_name} | Latency: {inter.latency_ms:.1f}ms | Status: {inter.status_code}"):
                    st.markdown("**Sent Prompt:**")
                    st.code(inter.prompt_sent, language="text")
                    st.markdown("**Observed Response:**")
                    st.code(inter.raw_response, language="text")
                    if inter.observed_tool_calls:
                        st.markdown("**Captured Tool Invocations:**")
                        st.json(inter.observed_tool_calls)

        with tab_export:
            st.subheader("Export Audit Reports")
            col_exp1, col_exp2, col_exp3 = st.columns(3)
            
            with col_exp1:
                html_doc = report.to_html()
                st.download_button(
                    label="DOWNLOAD HTML REPORT",
                    data=html_doc,
                    file_name=f"redagent_{report.report_id}.html",
                    mime="text/html",
                    use_container_width=True,
                )

            with col_exp2:
                md_doc = report.to_markdown()
                st.download_button(
                    label="DOWNLOAD MARKDOWN REPORT",
                    data=md_doc,
                    file_name=f"redagent_{report.report_id}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )

            with col_exp3:
                json_doc = json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
                st.download_button(
                    label="DOWNLOAD JSON REPORT",
                    data=json_doc,
                    file_name=f"redagent_{report.report_id}.json",
                    mime="application/json",
                    use_container_width=True,
                )
    else:
        st.info("Select a target in the sidebar and click 'LAUNCH SECURITY AUDIT' to execute the adversarial assessment.")


if __name__ == "__main__":
    main()

