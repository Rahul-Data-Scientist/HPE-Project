"""
main_workflow.py — Post-Normalisation Remediation Pipeline
===========================================================

HOW TO USE (for the agent coordinator)
---------------------------------------
1. Your normalisation agent produces a normalised DataFrame.
2. Save that DataFrame to a CSV file:

       normalised_df.to_csv(csv_file_path, index=False)

3. Call this single function with the CSV path:

       from main_workflow import run_remediation_pipeline
       final_state = run_remediation_pipeline(csv_file_path)

That's it. The workflow will:
  • Enrich each CVE with static details from NVD API v2.0
    → writes enriched columns back to the same CSV
    → batch upserts into the  vulnerabilities  table on RDS
  • Enrich each CVE with exploit intelligence (EPSS / KEV / Exploit-DB / NVD refs)
    → writes intel columns back to the same CSV
    → batch upserts into the  vulnerability_intel  table on RDS

LANGGRAPH STATE
---------------
The only item flowing through the graph is:
    { "csv_file_path": str }

Both agent nodes read and write the CSV at that path.
The final state dict returned by run_remediation_pipeline() also contains
this key so the coordinator can chain further work downstream.

REQUIREMENTS
------------
  .env must contain:
    DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
    NVD_API_KEY  (optional but strongly recommended to avoid NVD rate limits)
"""

import os
from typing import TypedDict
from langgraph.graph import StateGraph, END

from .vulnerability_agent import run_vulnerability_agent
from .vuln_intel_agent import run_vuln_intel_agent


# =========================
# STATE
# =========================

class WorkflowState(TypedDict):
    csv_file_path: str   # Absolute or relative path to the normalised CSV


# =========================
# NODES
# =========================

async def vulnerability_agent_node(state: WorkflowState) -> WorkflowState:
    """
    Node 1 — Vulnerability Agent
    Reads csv_file_path, queries NVD API v2.0 for any CVE not fully present
    in the DB, enriches the CSV, and batch upserts to the vulnerabilities table.
    """
    print("\n[LangGraph] -- Node 1: vulnerability_agent_node")
    await run_vulnerability_agent(state["csv_file_path"])
    return state


async def vuln_intel_agent_node(state: WorkflowState) -> WorkflowState:
    """
    Node 2 — Vuln Intel Agent
    Reads csv_file_path (now enriched by Node 1), bulk-downloads EPSS / KEV /
    Exploit-DB catalogs, enriches intel columns in the CSV, and batch upserts
    to the vulnerability_intel table.
    """
    print("\n[LangGraph] -- Node 2: vuln_intel_agent_node")
    await run_vuln_intel_agent(state["csv_file_path"])
    return state


# =========================
# GRAPH ASSEMBLY
# =========================

graph_builder = StateGraph(WorkflowState)

graph_builder.add_node("vulnerability_agent", vulnerability_agent_node)
graph_builder.add_node("vuln_intel_agent",    vuln_intel_agent_node)

graph_builder.set_entry_point("vulnerability_agent")
graph_builder.add_edge("vulnerability_agent", "vuln_intel_agent")
graph_builder.add_edge("vuln_intel_agent",    END)

workflow = graph_builder.compile()


# =========================
# PUBLIC ENTRY POINT
# =========================

async def run_remediation_pipeline(csv_file_path: str) -> dict:
    """
    Start the post-normalisation enrichment pipeline.

    Parameters
    ----------
    csv_file_path : str
        Path to the CSV file already saved by the normalisation agent.
        The file MUST exist before calling this function.

    Returns
    -------
    dict
        Final LangGraph state: {"csv_file_path": str}

    Raises
    ------
    FileNotFoundError
        If csv_file_path does not exist on disk.
    """
    if not os.path.exists(csv_file_path):
        raise FileNotFoundError(
            f"[Pipeline] CSV not found: '{csv_file_path}'\n"
            "The normalisation agent must save the DataFrame to this path "
            "before calling run_remediation_pipeline()."
        )

    print(f"\n[Pipeline] Starting from CSV: {csv_file_path}")
    final_state = await workflow.ainvoke({"csv_file_path": csv_file_path})
    print(f"\n[Pipeline] Finished. Final state: {final_state}")
    return final_state
