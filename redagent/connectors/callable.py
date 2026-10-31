"""In-memory and local callable target connector.

This module provides an adapter to execute adversarial security audits
against Python callables, coroutines, and LangChain Runnable chains.
"""
import asyncio
import inspect
import time
from typing import Any, Callable, Dict, List, Optional, Union

from redagent.connectors.base import BaseTargetConnector, TargetResponse
from redagent.core.logger import get_logger
from redagent.schemas.target import TargetInfo

logger = get_logger(__name__)


class CallableTargetConnector(BaseTargetConnector):
    """Adapter executing security evaluations against in-memory Python callables.

    Attributes:
        callable_fn: Target function, coroutine, or LangChain Runnable.
        timeout: Maximum duration in seconds allowed for a single probe.
    """

    def __init__(
        self,
        callable_fn: Union[Callable[..., Any], Any],
        name: str = "callable_target_connector",
        timeout: float = 30.0,
    ):
        """Initializes the callable target connector.

        Args:
            callable_fn: The target callable, coroutine, or LangChain Runnable.
            name: Human-readable connector identifier.
            timeout: Maximum interaction timeout in seconds.
        """
        super().__init__(name=name)
        self.callable_fn = callable_fn
        self.timeout = timeout

    async def send(self, prompt: str, target_info: TargetInfo, **kwargs: Any) -> TargetResponse:
        """Dispatches an adversarial probe to the target callable.

        Args:
            prompt: The attack or reconnaissance payload string.
            target_info: Profiling and boundary specification of the target system.
            **kwargs: Additional runtime arguments passed to the underlying callable.

        Returns:
            TargetResponse: Standardized response object containing response text,
                captured tool calls, latency, and execution status code.
        """
        start_time = time.perf_counter()

        try:
            raw_result = await self._invoke_callable(prompt, target_info, **kwargs)
            latency = (time.perf_counter() - start_time) * 1000
            return self._parse_output(raw_result, latency)
        except asyncio.TimeoutError:
            latency = (time.perf_counter() - start_time) * 1000
            logger.error("Callable target timed out", timeout=self.timeout)
            return TargetResponse(
                content="",
                status_code=504,
                latency_ms=latency,
                error=f"Execution timed out after {self.timeout}s",
            )
        except Exception as exc:
            latency = (time.perf_counter() - start_time) * 1000
            logger.error("Callable target execution failed", error=str(exc))
            return TargetResponse(
                content="",
                status_code=500,
                latency_ms=latency,
                error=f"Target execution exception: {str(exc)}",
            )

    async def _invoke_callable(self, prompt: str, target_info: TargetInfo, **kwargs: Any) -> Any:
        """Invokes the underlying callable across synchronous, asynchronous, or Runnable interfaces.

        Args:
            prompt: Test probe string.
            target_info: Target metadata.
            **kwargs: Extra parameters.

        Returns:
            Any: Unprocessed execution return value.

        Raises:
            TypeError: If callable_fn does not adhere to supported calling conventions.
        """
        fn = self.callable_fn

        if asyncio.iscoroutinefunction(fn):
            sig = inspect.signature(fn)
            args = [prompt, target_info] if len(sig.parameters) >= 2 else [prompt]
            return await asyncio.wait_for(fn(*args), timeout=self.timeout)

        if callable(fn):
            sig = inspect.signature(fn)
            args = [prompt, target_info] if len(sig.parameters) >= 2 else [prompt]
            return fn(*args)

        if hasattr(fn, "ainvoke") and callable(getattr(fn, "ainvoke")):
            return await asyncio.wait_for(fn.ainvoke(prompt), timeout=self.timeout)
        elif hasattr(fn, "invoke") and callable(getattr(fn, "invoke")):
            return fn.invoke(prompt)

        raise TypeError(f"Target object of type {type(fn)} does not implement a callable interface.")

    def _parse_output(self, raw_result: Any, latency: float) -> TargetResponse:
        """Normalizes heterogeneous return types into a structured TargetResponse.

        Args:
            raw_result: Value returned by the target invocation.
            latency: Execution elapsed time in milliseconds.

        Returns:
            TargetResponse: Uniform target response model.
        """
        if isinstance(raw_result, TargetResponse):
            raw_result.latency_ms = latency
            return raw_result

        content = ""
        tool_calls: List[Dict[str, Any]] = []
        metadata: Dict[str, Any] = {}

        if isinstance(raw_result, str):
            content = raw_result
        elif isinstance(raw_result, dict):
            content = (
                raw_result.get("output")
                or raw_result.get("content")
                or raw_result.get("response")
                or raw_result.get("text")
                or str(raw_result)
            )
            tool_calls = raw_result.get("tool_calls") or raw_result.get("intermediate_steps") or []
            metadata = {
                k: v for k, v in raw_result.items()
                if k not in ("output", "content", "response", "tool_calls")
            }
        elif hasattr(raw_result, "content"):
            content = str(raw_result.content)
            if hasattr(raw_result, "tool_calls"):
                tool_calls = getattr(raw_result, "tool_calls", [])
            if hasattr(raw_result, "response_metadata"):
                metadata = getattr(raw_result, "response_metadata", {})
        else:
            content = str(raw_result)

        normalized_tools: List[Dict[str, Any]] = []
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if isinstance(tc, dict):
                    normalized_tools.append(tc)
                elif hasattr(tc, "name"):
                    normalized_tools.append({
                        "name": getattr(tc, "name"),
                        "args": getattr(tc, "args", {}),
                    })

        return TargetResponse(
            content=content,
            tool_calls=normalized_tools,
            status_code=200,
            latency_ms=latency,
            metadata=metadata,
        )

    async def health_check(self, target_info: TargetInfo) -> bool:
        """Verifies responsiveness of the target callable.

        Args:
            target_info: Profile of the target system.

        Returns:
            bool: True if target returns a valid response without errors, False otherwise.
        """
        try:
            resp = await self.send("PING_HEALTH_CHECK", target_info)
            return resp.status_code == 200 and resp.error is None
        except Exception:
            return False
