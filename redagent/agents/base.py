"""Abstract Base Agent class defining interfaces for all Red Teaming roles."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel
from redagent.core.llm import LLMGateway
from redagent.core.logger import get_logger
from redagent.schemas.execution import ExecutionLog, InteractionRecord, LogLevel
from redagent.schemas.state import RedTeamGraphState
from redagent.schemas.target import TargetInfo
from redagent.tools.base_tool import BaseRedTeamTool
from redagent.tools.target_client import TargetClientTool

logger = get_logger(__name__)


class BaseAgent(ABC):
    """Abstract Base Class for all specialized agents in the Red Teaming multi-agent graph.
    
    Provides standardized utilities for:
    - LLM invocation with strict schemas
    - Structured audit logging
    - Target system probing
    - State updates complying with LangGraph TypedDict reducers
    """

    def __init__(
        self,
        agent_id: str,
        name: str,
        role: str,
        system_prompt: str,
        model_name: Optional[str] = None,
        tools: Optional[List[BaseRedTeamTool]] = None,
    ):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.system_prompt = system_prompt
        self.llm = LLMGateway(model_name=model_name)
        self.tools: Dict[str, BaseRedTeamTool] = {t.name: t for t in (tools or [])}
        
        # Ensure default target client and iteration engine are available
        if "target_client_tool" not in self.tools:
            self.tools["target_client_tool"] = TargetClientTool()
        
        from redagent.core.iteration_engine import DynamicTestIterationEngine
        self.iteration_engine = DynamicTestIterationEngine()

    def log(
        self,
        message: str,
        level: LogLevel = LogLevel.INFO,
        test_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> ExecutionLog:
        """Create a standardized execution log entry."""
        logger.info(
            f"[{self.name}] {message}",
            agent=self.name,
            level=level.value,
            test_id=test_id,
            details=details or {},
        )
        return ExecutionLog(
            agent_name=self.name,
            level=level,
            message=message,
            test_id=test_id,
            details=details or {},
        )

    async def call_llm(
        self,
        user_message: str,
        system_override: Optional[str] = None,
        response_format: Optional[Type[BaseModel]] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """Helper to invoke the agent's backing LLM."""
        messages = [
            {"role": "system", "content": system_override or self.system_prompt},
            {"role": "user", "content": user_message},
        ]
        return await self.llm.acomplete(
            messages=messages,
            temperature=temperature,
            response_format=response_format,
        )

    async def send_probe(
        self,
        target: TargetInfo,
        test_id: str,
        probe_prompt: str,
    ) -> InteractionRecord:
        """Transmit a single probe to the target system via TargetClientTool."""
        client_tool: TargetClientTool = self.tools["target_client_tool"]  # type: ignore
        return await client_tool.execute(
            target=target,
            test_id=test_id,
            agent_name=self.name,
            prompt=probe_prompt,
        )

    async def run_iterative_test(
        self,
        test_case: Any,
        target: TargetInfo,
    ) -> List[InteractionRecord]:
        """Execute persistent multi-turn testing with adaptive mutation and backtracking."""
        client_tool: TargetClientTool = self.tools["target_client_tool"]  # type: ignore
        connector = client_tool.get_connector(target)
        return await self.iteration_engine.execute_iterative_test(
            base_test=test_case,
            target_info=target,
            connector=connector,
            agent_name=self.name,
        )

    @abstractmethod
    async def run(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Execute the agent's core task within the LangGraph DAG.
        
        Args:
            state: The current shared RedTeamGraphState.
            
        Returns:
            Dict containing state updates to be merged by LangGraph reducers.
        """
        pass
