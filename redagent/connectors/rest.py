"""REST API Target Connector for hosted AI agent endpoints."""
import time
from typing import Any, Dict, Optional
import httpx
import logging
from redagent.connectors.base import BaseTargetConnector, TargetResponse
from redagent.schemas.target import TargetInfo

logger = logging.getLogger(__name__)


class RestTargetConnector(BaseTargetConnector):
    """Connector for targets exposing HTTP REST / JSON endpoints."""

    def __init__(self, timeout: float = 30.0):
        super().__init__(name="rest_target_connector")
        self.timeout = timeout

    async def send(self, prompt: str, target_info: TargetInfo, **kwargs: Any) -> TargetResponse:
        """Send prompt via HTTP POST and extract text and observed function calls."""
        if not target_info.endpoint_url:
            return TargetResponse(
                error="Target endpoint_url is not configured.",
                status_code=400,
            )

        start_time = time.perf_counter()
        headers = dict(target_info.auth_headers)
        if "custom_headers" in kwargs:
            headers.update(kwargs["custom_headers"])

        payload = dict(target_info.request_template or {"prompt": prompt, "message": prompt})
        if "prompt" in payload:
            payload["prompt"] = prompt
        elif "message" in payload:
            payload["message"] = prompt

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(target_info.endpoint_url, json=payload, headers=headers)
                latency = (time.perf_counter() - start_time) * 1000

                raw_text = resp.text
                observed_tools = []
                resp_json: Dict[str, Any] = {}

                try:
                    resp_json = resp.json()
                    if isinstance(resp_json, dict):
                        if "tool_calls" in resp_json:
                            observed_tools = resp_json["tool_calls"]
                        elif "output" in resp_json:
                            raw_text = str(resp_json["output"])
                        elif "response" in resp_json:
                            raw_text = str(resp_json["response"])
                        elif "message" in resp_json:
                            raw_text = str(resp_json["message"])
                except Exception:
                    pass

                return TargetResponse(
                    content=raw_text,
                    tool_calls=observed_tools,
                    status_code=resp.status_code,
                    latency_ms=latency,
                    metadata=resp_json if isinstance(resp_json, dict) else {},
                )

        except Exception as exc:
            latency = (time.perf_counter() - start_time) * 1000
            logger.error(f"REST connection error for endpoint {target_info.endpoint_url}: {exc}")
            return TargetResponse(
                error=str(exc),
                status_code=500,
                latency_ms=latency,
            )

    async def health_check(self, target_info: TargetInfo) -> bool:
        """Ping target endpoint to verify availability."""
        if not target_info.endpoint_url:
            return False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(target_info.endpoint_url, headers=target_info.auth_headers)
                return resp.status_code < 500
        except Exception:
            return False
