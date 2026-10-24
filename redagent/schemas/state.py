"""State schemas for LangGraph execution and Pydantic validation."""
from datetime import datetime, timezone
import operator
from typing import Annotated, Any, Dict, List, Optional
from pydantic import BaseModel, Field

from redagent.schemas.execution import ExecutionLog, InteractionRecord
from redagent.schemas.finding import Finding
from redagent.schemas.report import AuditReport
from redagent.schemas.target import TargetInfo
from redagent.schemas.test_case import TestCase


class RedTeamState(BaseModel):
    """Pydantic model representing the full snapshot of Red Teaming State.
    Used for Redis persistence, API payloads, and strict schema validation.
    """
    target: TargetInfo
    test_cases: List[TestCase] = Field(default_factory=list)
    interactions: List[InteractionRecord] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    execution_logs: List[ExecutionLog] = Field(default_factory=list)
    
    current_stage: str = Field(default="initialization", description="Current workflow stage in DAG")
    is_completed: bool = Field(default=False)
    
    audit_report: Optional[AuditReport] = Field(default=None)
    errors: List[str] = Field(default_factory=list)
    context_data: Dict[str, Any] = Field(default_factory=dict)
    
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def get_test_case_by_id(self, test_id: str) -> Optional[TestCase]:
        """Lookup a test case by its ID."""
        for tc in self.test_cases:
            if tc.test_id == test_id:
                return tc
        return None

    def get_interactions_for_test(self, test_id: str) -> List[InteractionRecord]:
        """Fetch all raw request/response interactions for a specific test case."""
        return [ix for ix in self.interactions if ix.test_id == test_id]


def update_target_reducer(old: TargetInfo, new: Optional[TargetInfo]) -> TargetInfo:
    """Reducer for target info updates."""
    return new if new is not None else old


def replace_or_keep(old: Any, new: Any) -> Any:
    """Reducer that replaces state if new value provided, else keeps old."""
    return new if new is not None else old


from typing_extensions import TypedDict


class RedTeamGraphState(TypedDict):
    """LangGraph compatible state with reducer annotations.
    Prevents race conditions when multi-agent nodes execute in parallel.
    """
    target: Annotated[TargetInfo, update_target_reducer]
    test_cases: Annotated[List[TestCase], operator.add]
    interactions: Annotated[List[InteractionRecord], operator.add]
    findings: Annotated[List[Finding], operator.add]
    execution_logs: Annotated[List[ExecutionLog], operator.add]
    current_stage: Annotated[str, replace_or_keep]
    is_completed: Annotated[bool, replace_or_keep]
    audit_report: Annotated[Optional[AuditReport], replace_or_keep]
    errors: Annotated[List[str], operator.add]
    context_data: Annotated[Dict[str, Any], replace_or_keep]
