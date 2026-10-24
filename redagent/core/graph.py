"""LangGraph StateGraph workflow assembly for RedAgent platform."""
from typing import Any, Dict, Optional
from redagent.agents.data_exfil import DataExfiltrationAgent
from redagent.agents.evaluator import EvaluatorAgent
from redagent.agents.orchestrator import OrchestratorAgent
from redagent.agents.prompt_injection import PromptInjectionSpecialistAgent
from redagent.agents.tool_abuse import ToolAbuseAgent
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
    """Orchestrates multi-agent execution pipeline using LangGraph StateGraph.
    Falls back gracefully to a native DAG runner if langgraph is not yet installed.
    """

    def __init__(
        self,
        orchestrator: Optional[OrchestratorAgent] = None,
        prompt_specialist: Optional[PromptInjectionSpecialistAgent] = None,
        tool_specialist: Optional[ToolAbuseAgent] = None,
        data_specialist: Optional[DataExfiltrationAgent] = None,
        evaluator: Optional[EvaluatorAgent] = None,
    ):
        self.orchestrator = orchestrator or OrchestratorAgent()
        self.prompt_specialist = prompt_specialist or PromptInjectionSpecialistAgent()
        self.tool_specialist = tool_specialist or ToolAbuseAgent()
        self.data_specialist = data_specialist or DataExfiltrationAgent()
        self.evaluator = evaluator or EvaluatorAgent()
        
        self.graph = self._build_graph() if HAS_LANGGRAPH else None

    def _build_graph(self) -> Any:
        """Construct the Directed Acyclic Graph (DAG) for red teaming."""
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
        logger.info("Executing Graph Node: orchestrator_node")
        return await self.orchestrator.run(state)

    async def _prompt_injection_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        logger.info("Executing Graph Node: prompt_injection_node")
        return await self.prompt_specialist.run(state)

    async def _tool_abuse_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        logger.info("Executing Graph Node: tool_abuse_node")
        return await self.tool_specialist.run(state)

    async def _data_exfil_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        logger.info("Executing Graph Node: data_exfil_node")
        return await self.data_specialist.run(state)

    async def _evaluator_step(self, state: RedTeamGraphState) -> Dict[str, Any]:
        logger.info("Executing Graph Node: evaluator_node")
        return await self.evaluator.run(state)

    def _apply_updates(self, current: RedTeamGraphState, updates: Dict[str, Any]) -> None:
        """Apply node state updates mimicking LangGraph TypedDict reducers."""
        for key, val in updates.items():
            if key in ("test_cases", "interactions", "findings", "execution_logs", "errors"):
                current[key] = current.get(key, []) + val  # type: ignore
            else:
                current[key] = val  # type: ignore

    async def run(self, target: TargetInfo) -> RedTeamState:
        """Execute complete Red Teaming audit against target agent."""
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
