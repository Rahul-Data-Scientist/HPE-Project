import io
import pandas as pd
import asyncio
from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END

class ParsingState(TypedDict):
    file_bytes: bytes
    raw_data: List[Dict[str, Any]]
    row_count: int
    col_count: int
    log_message: str

async def parse_csv_node(state: ParsingState):
    await asyncio.sleep(1) # Simulate processing
    df = pd.read_csv(io.BytesIO(state["file_bytes"]))
    df = df.fillna("")
    return {
        "raw_data": df.to_dict(orient="records"),
        "row_count": len(df),
        "col_count": len(df.columns),
        "log_message": f"[SYSTEM] Parsing file. Found {len(df)} rows. & {len(df.columns)} columns."
    }

def build_parsing_graph():
    workflow = StateGraph(ParsingState)
    workflow.add_node("parse_csv", parse_csv_node)
    workflow.add_edge(START, "parse_csv")
    workflow.add_edge("parse_csv", END)
    return workflow.compile()