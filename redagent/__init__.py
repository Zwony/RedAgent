"""RedAgent: AI Agent Security & Automated Red Teaming Platform."""
import os
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_TELEMETRY", "False")

from redagent.connectors.callable import CallableTargetConnector
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

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "RedTeamGraphEngine",
    "CallableTargetConnector",
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
