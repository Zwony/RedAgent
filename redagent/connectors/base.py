"""Base connector interfaces for communicating with diverse target AI agents."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from redagent.schemas.target import TargetInfo


class TargetResponse(BaseModel):
    """Standardized response received from any target connector."""
    content: str = Field(default="", description="Text response from target agent")
    tool_calls: List[Dict[str, Any]] = Field(default_factory=list, description="Observed tool/function invocations")
    status_code: int = Field(default=200, description="HTTP or execution status code")
    latency_ms: float = Field(default=0.0, description="Response time in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Raw provider metadata")
    error: Optional[str] = Field(default=None, description="Error message if interaction failed")


class BaseTargetConnector(ABC):
    """Abstract Base Class for target AI agent communication adapters."""

    def __init__(self, name: str):
        self.name = name

    @abstractmethod
    async def send(self, prompt: str, target_info: TargetInfo, **kwargs: Any) -> TargetResponse:
        """Send a test prompt/probe to the target agent and return structured response."""
        pass

    @abstractmethod
    async def health_check(self, target_info: TargetInfo) -> bool:
        """Verify target connectivity and responsiveness."""
        pass
