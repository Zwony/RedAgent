"""Target information and specification schemas."""
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class EndpointType(str, Enum):
    """Supported communication channels for the target AI agent."""
    REST_API = "rest_api"
    WEBSOCKET = "websocket"
    DIRECT_PROMPT = "direct_prompt"
    LANGCHAIN_AGENT = "langchain_agent"
    CREWAI_AGENT = "crewai_agent"
    CUSTOM_SDK = "custom_sdk"
    CALLABLE = "callable"


class TargetToolParameter(BaseModel):
    """Parameter definition for tools exposed to the target agent."""
    name: str
    param_type: str = "string"
    description: str = ""
    required: bool = True
    default: Optional[Any] = None


class TargetToolDefinition(BaseModel):
    """Specification of tools/functions available to the target agent."""
    name: str = Field(..., description="Function/Tool name, e.g., 'query_sql_database'")
    description: str = Field(..., description="Description provided to the target LLM")
    parameters: List[TargetToolParameter] = Field(default_factory=list)
    is_sensitive: bool = Field(default=False, description="Whether tool performs state mutation, DB writes, or exfil-risk operations")
    risk_notes: Optional[str] = Field(default=None, description="Known privileges or risks regarding this tool")


class TargetInfo(BaseModel):
    """Comprehensive profiling data of the AI Agent under audit."""
    target_id: str = Field(..., description="Unique identifier for the target system")
    name: str = Field(..., description="Human-readable name of the target agent")
    description: str = Field(default="", description="Role and context of the target agent")
    endpoint_url: Optional[str] = Field(default=None, description="API endpoint URL if target is hosted")
    endpoint_type: EndpointType = Field(default=EndpointType.REST_API)
    
    # Context & Architecture details (obtained through reconnaissance or configuration)
    system_prompt_hint: Optional[str] = Field(
        default=None,
        description="Known or presumed system prompt/instructions of the target"
    )
    accessible_tools: List[TargetToolDefinition] = Field(
        default_factory=list,
        description="Tools, plugins, or function calls the target has authorization to invoke"
    )
    has_rag: bool = Field(default=False, description="Whether target queries vector stores or external knowledge bases")
    rag_sources: List[str] = Field(default_factory=list, description="Presumed or known indices/documents in the RAG pipeline")
    
    # Request configuration & headers
    auth_headers: Dict[str, str] = Field(default_factory=dict, description="Headers needed for authentication (bearer token, api key)")
    request_template: Optional[Dict[str, Any]] = Field(
        default=None,
        description="JSON payload schema template for communicating with the target"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary custom properties")
