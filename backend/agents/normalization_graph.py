import asyncio
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END

class NormalizationState(TypedDict):
    raw_data: List[Dict[str, Any]]
    normalized_data: List[Dict[str, Any]]
    log_message: str

async def normalize_schema_node(state: NormalizationState):
    await asyncio.sleep(1)
    normalized = []
    for row in state.get("raw_data", []):
        clean_row = {}
        for key, value in row.items():
            # Standardize key format (lowercase, underscores)
            clean_key = str(key).lower().strip().replace(' ', '_')
            
            # Map various ID names to standard 'vuln_id'
            if clean_key in ['vulnerability_id', 'cve_id', 'id', 'name', 'vulnerability']:
                clean_key = 'vuln_id'
                
            # Map various Severity names to standard 'severity' (FIX FOR CSV DATA)
            if clean_key in ['severity_raw', 'priority_level', 'risk_level', 'priority']:
                clean_key = 'severity'
                
            clean_row[clean_key] = value
        normalized.append(clean_row)
        
    return {
        "normalized_data": normalized,
        "log_message": "[SYSTEM] Normalizing vulnerability schema."
    }

def build_normalization_graph():
    workflow = StateGraph(NormalizationState)
    workflow.add_node("normalize", normalize_schema_node)
    workflow.add_edge(START, "normalize")
    workflow.add_edge("normalize", END)
    return workflow.compile()