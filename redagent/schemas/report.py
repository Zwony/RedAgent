"""Audit reporting schemas for RedAgent security platform."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from redagent.schemas.finding import Finding
from redagent.schemas.test_case import SeverityLevel


class SecurityRating(str, Enum):
    """Aggregate posture rating of the target AI agent."""
    SECURE = "SECURE"
    LOW_RISK = "LOW_RISK"
    MEDIUM_RISK = "MEDIUM_RISK"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL_RISK = "CRITICAL_RISK"


class RemediationAction(BaseModel):
    """Actionable remediation item for engineering teams."""
    priority: int = Field(..., ge=1, le=5, description="1 (Immediate fix required) to 5 (Best practice)")
    target_component: str = Field(..., description="E.g., System Prompt, Tool Schema/RBAC, RAG Pipeline, Guardrail API")
    recommendation: str = Field(..., description="Actionable hardening advice")
    example_mitigation: Optional[str] = Field(default=None, description="Code snippet or prompt patch example")


class AuditReport(BaseModel):
    """Final comprehensive security audit report."""
    report_id: str = Field(default_factory=lambda: f"rep_{uuid.uuid4().hex[:8]}")
    target_id: str = Field(..., description="Target system identifier")
    target_name: str = Field(..., description="Target system name")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Posture metrics
    overall_rating: SecurityRating = Field(default=SecurityRating.SECURE)
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    
    total_tests_executed: int = Field(default=0)
    vulnerabilities_found: int = Field(default=0)
    severity_breakdown: Dict[SeverityLevel, int] = Field(default_factory=dict)
    
    executive_summary: str = Field(default="", description="High-level overview for leadership")
    findings: List[Finding] = Field(default_factory=list)
    remediation_roadmap: List[RemediationAction] = Field(default_factory=list)
    
    audit_duration_seconds: float = Field(default=0.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_markdown(self) -> str:
        """Render audit report as an executive-ready Markdown document."""
        lines: List[str] = [
            f"# RedAgent Security Audit Report: {self.target_name}",
            "",
            f"**Report ID:** `{self.report_id}`  ",
            f"**Target System:** `{self.target_name}` (`{self.target_id}`)  ",
            f"**Audit Date:** `{self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
            f"**Overall Posture Rating:** **{self.overall_rating.value}**  ",
            f"**Maximum Risk Score:** **{self.overall_risk_score:.1f} / 10.0**  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            self.executive_summary or f"Automated red teaming assessment conducted across {self.total_tests_executed} tests, identifying {self.vulnerabilities_found} security findings.",
            "",
            "---",
            "",
            "## 2. Posture & Metrics Summary",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| Overall Rating | **{self.overall_rating.value}** |",
            f"| Maximum Risk Score | **{self.overall_risk_score:.1f} / 10.0** |",
            f"| Total Tests Executed | {self.total_tests_executed} |",
            f"| Total Findings Detected | {self.vulnerabilities_found} |",
            f"| Audit Duration | {self.audit_duration_seconds:.2f}s |",
            "",
            "### Severity Distribution",
            "",
            "| Severity Level | Count |",
            "| :--- | :--- |",
        ]

        for sev, count in self.severity_breakdown.items():
            lines.append(f"| {sev.value if hasattr(sev, 'value') else sev} | {count} |")

        lines.extend([
            "",
            "---",
            "",
            "## 3. Vulnerability Findings",
            "",
            "| Finding ID | Category | Severity | Status | Recommendation |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        if not self.findings:
            lines.append("| - | - | - | - | No vulnerabilities identified. |")
        else:
            for f in self.findings:
                cat_val = f.category.value if hasattr(f.category, 'value') else str(f.category)
                sev_val = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
                stat_val = f.status.value if hasattr(f.status, 'value') else str(f.status)
                rem_short = f.remediation_suggestion.replace("\n", " ")[:80] + ("..." if len(f.remediation_suggestion) > 80 else "")
                lines.append(f"| `{f.finding_id}` | {cat_val} | **{sev_val}** | `{stat_val}` | {rem_short} |")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Hardening & Remediation Roadmap",
            "",
            "| Priority | Target Component | Actionable Recommendation | Mitigation Rule / Example |",
            "| :--- | :--- | :--- | :--- |",
        ])

        if not self.remediation_roadmap:
            lines.append("| - | System | Maintain current defensive posture. | - |")
        else:
            for r in self.remediation_roadmap:
                mitigation = f"`{r.example_mitigation}`" if r.example_mitigation else "Standard RBAC / Input Validation"
                lines.append(f"| P{r.priority} | **{r.target_component}** | {r.recommendation} | {mitigation} |")

        lines.extend([
            "",
            "---",
            "*Report generated automatically by RedAgent - Enterprise Automated AI Agent Red Teaming Platform.*",
            "",
        ])

        return "\n".join(lines)
