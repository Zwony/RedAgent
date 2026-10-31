"""LangGraph StateGraph workflow assembly for the RedAgent platform."""
from typing import Any, Dict, Optional

from redagent.agents.data_exfil import DataExfiltrationAgent
from redagent.agents.evaluator import EvaluatorAgent
from redagent.agents.orchestrator import OrchestratorAgent
from redagent.agents.prompt_injection import PromptInjectionSpecialistAgent
from redagent.agents.tool_abuse import ToolAbuseAgent
from redagent.connectors.base import BaseTargetConnector
from redagent.core.logger import get_logger
from redagent.schemas.state import RedTeamGraphState, RedTeamState
from redagent.schemas.target import TargetInfo

logger = get_logger(__name__)

try:
    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False
    logger.warning("langgraph is not installed; enabling native DAG state reducer fallback engine.")


class RedTeamGraphEngine:
    """Orchestrates multi-agent execution pipelines using LangGraph StateGraph.

    Falls back to a native DAG execution reducer when LangGraph is not installed.

    Attributes:
        orchestrator: Threat modeling and test matrix planning agent.
        prompt_specialist: Prompt injection and boundary testing agent.
        tool_specialist: Excessive agency and tool authorization testing agent.
        data_specialist: System prompt extraction and sensitive data leakage agent.
        evaluator: Semantic vulnerability analyzer and report synthesis agent.
        graph: Compiled LangGraph executable graph or None if running on fallback.
    """

    def __init__(
        self,
        orchestrator: Optional[OrchestratorAgent] = None,
        prompt_specialist: Optional[PromptInjectionSpecialistAgent] = None,
        tool_specialist: Optional[ToolAbuseAgent] = None,
        data_specialist: Optional[DataExfiltrationAgent] = None,
        evaluator: Optional[EvaluatorAgent] = None,
        target_connector: Optional[BaseTargetConnector] = None,
    ):
        """Initializes the multi-agent graph engine.

        Args:
            orchestrator: Optional custom threat modeling agent.
            prompt_specialist: Optional custom prompt injection agent.
            tool_specialist: Optional custom tool abuse agent.
            data_specialist: Optional custom data exfiltration agent.
            evaluator: Optional custom evaluation and reporting agent.
            target_connector: Optional communication connector override for all agents.
        """
        self.orchestrator = orchestrator or OrchestratorAgent()
        self.prompt_specialist = prompt_specialist or PromptInjectionSpecialistAgent()
        self.tool_specialist = tool_specialist or ToolAbuseAgent()
        self.data_specialist = data_specialist or DataExfiltrationAgent()
        self.evaluator = evaluator or EvaluatorAgent()

        if target_connector:
            self.set_target_connector(target_connector)

        self.graph = self._build_graph() if HAS_LANGGRAPH else None

    def set_target_connector(self, connector: Optional[BaseTargetConnector]) -> None:
        """Propagates an explicit target connector across all specialist agents.

        Args:
            connector: Target connector instance or None to restore default resolution.
        """
        for agent in (self.prompt_specialist, self.tool_specialist, self.data_specialist):
            if hasattr(agent, "tools") and "target_client_tool" in agent.tools:
                agent.tools["target_client_tool"].set_connector(connector)

    def _build_graph(self) -> Any:
        """Constructs and compiles the StateGraph execution DAG.

        Returns:
            CompiledStateGraph: Compiled LangGraph workflow ready for invocation.
        """
        workflow = StateGraph(RedTeamGraphState)

        workflow.add_node("orchestrator_node", self._orchestrator_step)
        workflow.add_node("prompt_injection_node", self._prompt_injection_step)
        workflow.add_node("tool_abuse_node", self._tool_abuse_step)
        workflow.add_node("data_exfil_node", self._data_exfil_step)
        workflow.add_node("evaluator_node", self._evaluator_step)

        workflow.add_edge(START, "orchestrator_node")
        workflow.add_edge("orchestrator_node", "prompt_injection_node")
        workflow.add_edge("prompt_injection_node", "tool_abuse_node")
        workflow.add_edge("tool_abuse_node", "data_exfil_node")
        workflow.add_edge("data_exfil_node", "evaluator_node")
        workflow.add_edge("evaluator_node", END)

        return workflow.compile()

    async def _orchestrator_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Executes the orchestrator planning node."""
        logger.info("Executing Graph Node: orchestrator_node")
        return await self.orchestrator.run(state)

    async def _prompt_injection_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Executes the prompt injection testing node."""
        logger.info("Executing Graph Node: prompt_injection_node")
        return await self.prompt_specialist.run(state)

    async def _tool_abuse_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Executes the tool authorization and excessive agency testing node."""
        logger.info("Executing Graph Node: tool_abuse_node")
        return await self.tool_specialist.run(state)

    async def _data_exfil_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Executes the data exfiltration and prompt extraction testing node."""
        logger.info("Executing Graph Node: data_exfil_node")
        return await self.data_specialist.run(state)

    async def _evaluator_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        """Executes the final vulnerability scoring and remediation synthesis node."""
        logger.info("Executing Graph Node: evaluator_node")
        return await self.evaluator.run(state)

    def _apply_updates(self, current: RedTeamGraphState, updates: Dict[str, Any]) -> None:
        """Applies node updates conforming to LangGraph TypedDict reducers.

        Args:
            current: Active state dictionary being modified in-place.
            updates: Partial dictionary produced by an executed node.
        """
        for key, val in updates.items():
            if key in ("test_cases", "interactions", "findings", "execution_logs", "errors"):
                current[key] = current.get(key, []) + val  # type: ignore
            else:
                current[key] = val  # type: ignore

    async def run(
        self,
        target: TargetInfo,
        target_connector: Optional[BaseTargetConnector] = None,
    ) -> RedTeamState:
        """Executes a complete adversarial assessment against the target system.

        Args:
            target: Target AI agent specification, tools, and endpoints.
            target_connector: Optional explicit connector adapter override.

        Returns:
            RedTeamState: Final assessment state containing audit findings and reports.
        """
        if target_connector:
            self.set_target_connector(target_connector)

        initial_state: RedTeamGraphState = {
            "target": target,
            "test_cases": [],
            "interactions": [],
            "findings": [],
            "execution_logs": [],
            "current_stage": "initialized",
            "is_completed": False,
            "audit_report": None,
            "errors": [],
            "context_data": {},
        }

        if HAS_LANGGRAPH and self.graph is not None:
            final_graph_state = await self.graph.ainvoke(initial_state)
        else:
            state = dict(initial_state)
            self._apply_updates(state, await self._orchestrator_step(state))
            self._apply_updates(state, await self._prompt_injection_step(state))
            self._apply_updates(state, await self._tool_abuse_step(state))
            self._apply_updates(state, await self._data_exfil_step(state))
            self._apply_updates(state, await self._evaluator_step(state))
            final_graph_state = state

        return RedTeamState(
            target=final_graph_state["target"],
            test_cases=final_graph_state["test_cases"],
            interactions=final_graph_state["interactions"],
            findings=final_graph_state["findings"],
            execution_logs=final_graph_state["execution_logs"],
            current_stage=final_graph_state["current_stage"],
            is_completed=final_graph_state["is_completed"],
            audit_report=final_graph_state["audit_report"],
            errors=final_graph_state["errors"],
            context_data=final_graph_state["context_data"],
        )
