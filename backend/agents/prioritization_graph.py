import asyncio
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END

class PrioritizationState(TypedDict):
    normalized_data: List[Dict[str, Any]]
    prioritized_data: List[Dict[str, Any]]
    log_message: str

async def prioritize_vectors_node(state: PrioritizationState):
    await asyncio.sleep(1)
    scored_data = []
    for row in state.get("normalized_data", []):
        # Fetch severity with safe fallbacks
        severity = str(row.get("severity") or row.get("severity_raw") or "medium").lower().strip()
        
        # Assign numeric weight for queue prioritization
        if severity == "critical": score = 9.5
        elif severity == "high": score = 7.5
        elif severity == "medium": score = 5.0
        elif severity == "low": score = 2.5
        else: score = 5.0 # Safe default
        
        row["priority_score"] = score
        scored_data.append(row)
        
    # Sort descending so Criticals are processed first by the main.py queue processor
    scored_data.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
    
    return {
        "prioritized_data": scored_data,
        "log_message": "[AGENT-PRIO] Prioritizing threat vectors and calculating CVSS weights."
    }

def build_prioritization_graph():
    workflow = StateGraph(PrioritizationState)
    workflow.add_node("prioritize", prioritize_vectors_node)
    workflow.add_edge(START, "prioritize")
    workflow.add_edge("prioritize", END)
    return workflow.compile()