"""LLM Gateway abstraction supporting LiteLLM and LangChain."""
from typing import Any, Dict, List, Optional, Type
import json
from pydantic import BaseModel
from config.settings import settings
from redagent.core.logger import get_logger

logger = get_logger(__name__)

try:
    import litellm
    litellm.suppress_debug_info = True
except ImportError:
    litellm = None  # type: ignore


class LLMGateway:
    """Unified LLM execution gateway for red team agents."""

    def __init__(self, model_name: Optional[str] = None, temperature: float = 0.2):
        self.model_name = model_name or settings.DEFAULT_ATTACKER_MODEL
        self.temperature = temperature

    async def acomplete(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 2000,
        response_format: Optional[Type[BaseModel]] = None,
    ) -> str:
        """Asynchronously call the underlying LLM provider via LiteLLM."""
        temp = temperature if temperature is not None else self.temperature

        if litellm is None:
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

            response = await litellm.acompletion(**kwargs)
            content = response.choices[0].message.content
            return content or ""
        except Exception as exc:
            logger.error("LLM call failed", model=self.model_name, error=str(exc))
            raise RuntimeError(f"LLM execution error ({self.model_name}): {exc}") from exc
