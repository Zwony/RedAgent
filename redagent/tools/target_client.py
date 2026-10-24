"""Target interaction client delegating to modular Target Connectors."""
from typing import Any, Dict, Optional
from redagent.connectors.base import BaseTargetConnector, TargetResponse
from redagent.connectors.mock import MockTargetConnector
from redagent.connectors.rest import RestTargetConnector
from redagent.core.logger import get_logger
from redagent.schemas.execution import InteractionRecord
from redagent.schemas.target import EndpointType, TargetInfo
from redagent.tools.base_tool import BaseRedTeamTool

logger = get_logger(__name__)


class TargetClientTool(BaseRedTeamTool):
    """Tool to send security test payloads to target AI agents via pluggable connectors."""
    name: str = "target_client_tool"
    description: str = "Dispatches a probe prompt to the target AI agent and captures output, latency, and tool calls."

    def __init__(self, default_connector: Optional[BaseTargetConnector] = None, **kwargs: Any):
        super().__init__(**kwargs)
        self._connector: Optional[BaseTargetConnector] = default_connector
        self._mock_connector = MockTargetConnector()
        self._rest_connector = RestTargetConnector()

    def get_connector(self, target: TargetInfo) -> BaseTargetConnector:
        """Select appropriate connector based on target configuration."""
        if self._connector:
            return self._connector
        if target.endpoint_type == EndpointType.REST_API and target.endpoint_url:
            return self._rest_connector
        return self._mock_connector

    async def execute(
        self,
        target: TargetInfo,
        test_id: str,
        agent_name: str,
        prompt: str,
        custom_headers: Optional[Dict[str, str]] = None,
        timeout: float = 30.0,
    ) -> InteractionRecord:
        """Send probe to target agent and return structured interaction trace."""
        connector = self.get_connector(target)
        resp: TargetResponse = await connector.send(
            prompt=prompt,
            target_info=target,
            custom_headers=custom_headers,
            timeout=timeout,
        )

        return InteractionRecord(
            test_id=test_id,
            agent_name=agent_name,
            prompt_sent=prompt,
            raw_response=resp.content,
            observed_tool_calls=resp.tool_calls,
            latency_ms=resp.latency_ms,
            status_code=resp.status_code,
            error=resp.error,
            raw_target_metadata=resp.metadata,
        )
