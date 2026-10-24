"""Security findings, vulnerability assessments, and remediation guidance."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field
from redagent.schemas.test_case import OWASPCategory, SeverityLevel


class VulnerabilityStatus(str, Enum):
    """Outcome of the vulnerability evaluation."""
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"
    SUSPECTED_WEAKNESS = "suspected_weakness"
    ROBUST_DEFENSE = "robust_defense"
    INCONCLUSIVE = "inconclusive"


class Finding(BaseModel):
    """Detailed security finding identified during testing."""
    finding_id: str = Field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:8]}")
    test_id: str = Field(..., description="ID of the triggering test case")
    category: OWASPCategory = Field(..., description="OWASP LLM category")
    severity: SeverityLevel = Field(..., description="Risk severity rating")
    status: VulnerabilityStatus = Field(..., description="Assessment status")
    
    title: str = Field(..., description="Title of the vulnerability finding")
    description: str = Field(..., description="In-depth analysis of what occurred")
    
    # Evidence & Reproduction
    reproduction_prompt: str = Field(..., description="Minimal prompt payload that triggers the issue")
    observed_output: str = Field(..., description="Target response or tool invocation acting as proof")
    proof_of_weakness: str = Field(..., description="Semantic evaluation proof demonstrating bypass or leak")
    
    # Quantitative scoring (e.g. CVSS for LLM / OWASP Risk Rating)
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=10.0,
        description="Calculated risk score from 0.0 (benign) to 10.0 (critical)"
    )
    
    # Remediation & Hardening recommendations
    remediation_suggestion: str = Field(
        ...,
        description="Concrete steps for developers to harden system prompt or guardrail"
    )
    suggested_guardrail_rule: Optional[str] = Field(
        default=None,
        description="Suggested regex, semantic filter, or system prompt defensive constraint"
    )
    
    detected_by: str = Field(..., description="Agent or evaluator that validated the finding")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)
