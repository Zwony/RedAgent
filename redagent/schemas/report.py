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
