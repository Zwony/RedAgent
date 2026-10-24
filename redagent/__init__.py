"""RedAgent: AI Agent Security & Automated Red Teaming Platform."""

from redagent.core.graph import RedTeamGraphEngine
from redagent.schemas.finding import Finding, VulnerabilityStatus
from redagent.schemas.report import AuditReport, RemediationAction, SecurityRating
from redagent.schemas.state import RedTeamGraphState, RedTeamState
from redagent.schemas.target import (
    EndpointType,
    TargetInfo,
    TargetToolDefinition,
    TargetToolParameter,
)
from redagent.schemas.test_case import (
    AttackTechnique,
    OWASPCategory,
    SeverityLevel,
    TestCase,
    TestStatus,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "RedTeamGraphEngine",
    "TargetInfo",
    "TargetToolDefinition",
    "TargetToolParameter",
    "EndpointType",
    "TestCase",
    "TestStatus",
    "OWASPCategory",
    "AttackTechnique",
    "SeverityLevel",
    "Finding",
    "VulnerabilityStatus",
    "AuditReport",
    "SecurityRating",
    "RemediationAction",
    "RedTeamState",
    "RedTeamGraphState",
]
