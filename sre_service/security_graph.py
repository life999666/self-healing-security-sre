"""LangGraph workflow for security incidents received from Sentinel."""
from typing import Literal

from langgraph.graph import END, StateGraph

from config import settings
from security_agents import (
    security_investigator_node,
    security_mechanic_node,
    security_pr_node,
    security_validator_node,
)
from security_state import SecurityRemediationState


def after_investigation(state: SecurityRemediationState) -> Literal["mechanic", "end"]:
    return "mechanic" if state.get("vulnerability_confirmed") else "end"


def after_validation(state: SecurityRemediationState) -> Literal["pr", "mechanic", "end"]:
    if state.get("fix_validated"):
        return "pr"
    if state.get("iteration_count", 0) >= settings.max_iterations:
        return "end"
    return "mechanic"


def create_security_graph():
    graph = StateGraph(SecurityRemediationState)
    graph.add_node("investigator", security_investigator_node)
    graph.add_node("mechanic", security_mechanic_node)
    graph.add_node("validator", security_validator_node)
    graph.add_node("pr", security_pr_node)
    graph.set_entry_point("investigator")
    graph.add_conditional_edges("investigator", after_investigation, {"mechanic": "mechanic", "end": END})
    graph.add_edge("mechanic", "validator")
    graph.add_conditional_edges("validator", after_validation, {"pr": "pr", "mechanic": "mechanic", "end": END})
    graph.add_edge("pr", END)
    return graph.compile()


security_graph = create_security_graph()
