"""Execution logs and target interaction traces."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class LogLevel(str, Enum):
    """Log level taxonomy."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SECURITY_EVENT = "SECURITY_EVENT"


class InteractionRecord(BaseModel):
    """Granular trace of an HTTP/Prompt roundtrip with the target system."""
    interaction_id: str = Field(default_factory=lambda: f"ix_{uuid.uuid4().hex[:8]}")
    test_id: str = Field(..., description="Correlating TestCase ID")
    agent_name: str = Field(..., description="Agent that executed the interaction")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Payload sent and observed response
    prompt_sent: str = Field(..., description="Exact prompt or message sent to target")
    raw_response: str = Field(default="", description="Target agent's exact text response")
    
    # Tool calls executed or attempted by the target agent
    observed_tool_calls: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of tool calls initiated by target LLM (name, arguments)"
    )
    
    # Diagnostic metrics
    latency_ms: float = Field(default=0.0, description="Response time in milliseconds")
    status_code: Optional[int] = Field(default=200, description="HTTP status if via REST")
    error: Optional[str] = Field(default=None, description="Error message if target call failed")
    raw_target_metadata: Dict[str, Any] = Field(default_factory=dict)


class ExecutionLog(BaseModel):
    """Audit log entry generated during red teaming workflow."""
    log_id: str = Field(default_factory=lambda: f"log_{uuid.uuid4().hex[:8]}")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_name: str = Field(..., description="Source agent name")
    level: LogLevel = Field(default=LogLevel.INFO)
    message: str = Field(..., description="Descriptive log entry")
    test_id: Optional[str] = Field(default=None, description="Related test case if applicable")
    details: Dict[str, Any] = Field(default_factory=dict)
