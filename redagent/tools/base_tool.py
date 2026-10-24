"""Base tool interfaces for Red Teaming agents."""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class BaseRedTeamTool(ABC, BaseModel):
    """Abstract Base Class for all security testing tools and target probe clients."""
    name: str = Field(..., description="Unique tool name")
    description: str = Field(..., description="Tool description for orchestration")

    @abstractmethod
    async def execute(self, **kwargs: Any) -> Any:
        """Execute tool action asynchronously."""
        pass
