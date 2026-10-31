"""LLM gateway abstraction supporting LiteLLM multi-provider dispatch."""
import os
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
os.environ.setdefault("LITELLM_TELEMETRY", "False")

import json
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel

from config.settings import settings
from redagent.core.logger import get_logger

logger = get_logger(__name__)

_LITELLM_MODULE = None


def _get_litellm():
    """Lazily loads and configures the LiteLLM module on demand.

    Returns:
        Optional[module]: Configured litellm module or None if not installed.
    """
    global _LITELLM_MODULE
    if _LITELLM_MODULE is not None:
        return _LITELLM_MODULE
    try:
        import os
        os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
        os.environ.setdefault("LITELLM_TELEMETRY", "False")
        import litellm
        litellm.suppress_debug_info = True
        litellm.telemetry = False
        _LITELLM_MODULE = litellm
        return _LITELLM_MODULE
    except ImportError:
        return None


class LLMGateway:
    """Unified LLM execution gateway for red team adversarial and evaluation agents.

    Attributes:
        model_name: Active LLM model identifier (e.g., 'gpt-4o', 'claude-3-5-sonnet').
        temperature: Default sampling temperature.
    """

    def __init__(self, model_name: Optional[str] = None, temperature: float = 0.2):
        """Initializes the LLM gateway.

        Args:
            model_name: Name of the language model to invoke. Defaults to config settings.
            temperature: Sampling temperature for generations.
        """
        self.model_name = model_name or settings.DEFAULT_ATTACKER_MODEL
        self.temperature = temperature

    async def acomplete(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 2000,
        response_format: Optional[Type[BaseModel]] = None,
    ) -> str:
        """Asynchronously dispatches a completion request through LiteLLM.

        Args:
            messages: OpenAI-format chat history dictionary list.
            temperature: Optional per-request temperature override.
            max_tokens: Maximum completion token budget.
            response_format: Optional Pydantic model class for structured schema outputs.

        Returns:
            str: Generated textual response or JSON-serialized schema string.
        """
        temp = temperature if temperature is not None else self.temperature
        llm_mod = _get_litellm()

        if llm_mod is None:
            logger.warning("litellm is not installed or unavailable; using fallback mock LLM response.")
            if response_format:
                return response_format.model_validate({}).model_dump_json()
            return "Simulated LLM response"

        try:
            kwargs: Dict[str, Any] = {
                "model": self.model_name,
                "messages": messages,
                "temperature": temp,
                "max_tokens": max_tokens,
            }

            if response_format is not None:
                kwargs["response_format"] = response_format

            response = await llm_mod.acompletion(**kwargs)
            content = response.choices[0].message.content
            return content or ""
        except Exception as exc:
            logger.error("LLM completion request failed", model=self.model_name, error=str(exc))
            if response_format:
                return response_format.model_validate({}).model_dump_json()
            return f"Error executing LLM completion: {str(exc)}"
