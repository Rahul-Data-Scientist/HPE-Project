# backend/main.py
import uuid
import json
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

import aiofiles
import aiosqlite
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

# Assuming remediation_agent.py is in the agents/ folder
from agents.remediation_agent import build_graph, initialize_agent_components

# --- STATE CONSTANTS ---
RUNNING = "RUNNING"
WAITING_FOR_HUMAN_APPROVAL = "WAITING_FOR_HUMAN_APPROVAL"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
RESUMING = "RESUMING"

# --- DATABASE UTILS ---
async def update_workflow_state(thread_id: str, status: str):
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO workflow_state (thread_id, status, updated_at)
            VALUES (?, ?, ?)
            """,
            (thread_id, status, datetime.utcnow().isoformat())
        )
        await db.commit()

async def claim_workflow_for_resume(thread_id: str) -> bool:
    async with aiosqlite.connect("state_db.sqlite") as db:
        cursor = await db.execute(
            "UPDATE workflow_state SET status = 'RESUMING' WHERE thread_id = ? AND status = 'WAITING_FOR_HUMAN_APPROVAL'",
            (thread_id,)
        )
        await db.commit()
        return cursor.rowcount == 1

async def get_workflow_state(thread_id: str) -> str | None:
    async with aiosqlite.connect("state_db.sqlite") as db:
        async with db.execute("SELECT status FROM workflow_state WHERE thread_id = ?", (thread_id,)) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def init_database():
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute("CREATE TABLE IF NOT EXISTS pr_mappings (pr_number INTEGER PRIMARY KEY, thread_id TEXT NOT NULL)")
        await db.execute("CREATE TABLE IF NOT EXISTS workflow_state (thread_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL)")
        await db.commit()

# --- BACKGROUND TASKS ---
async def resume_agent_background(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        await update_workflow_state(thread_id, RUNNING)
        async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
            github_workflow_agent = await build_graph(checkpointer=checkpointer)
            async for _ in github_workflow_agent.astream(Command(resume=True), config=config, stream_mode="updates"):
                pass 
        
        current_state = await get_workflow_state(thread_id)
        if current_state == RUNNING:
            await update_workflow_state(thread_id, COMPLETED)
    except Exception as e:
        await update_workflow_state(thread_id, FAILED)
        print(f"[CRITICAL ERROR] Execution failed: {e}")

# --- FASTAPI APP ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database()
    print("[SYSTEM] Booting Security Remediation Core Agent Environment...")
    await initialize_agent_components()
    print("[SYSTEM] System ready. Awaiting inbound vulnerability triggers.\n" + "="*60)
    yield

app = FastAPI(lifespan=lifespan)

# Allow Next.js frontend to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # replace * with http://localhost:3000 or other url
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AgentVulnerabilityInput(BaseModel):
    issue_description: str
    repo_owner: str
    repo_name: str
    target_file: str

# Node-to-Log Mapping for the UI Terminal
NODE_LOG_MAP = {
    "generate_remediation_script": "[AGENT] 🧠 Generating bash remediation script...",
    "create_prompt": "[AGENT] 🛠️ Formulating Git patch payload...",
    "github_workflow": "[GIT] 🚀 Pushing code changes to remote repository...",
    "extract_pr_details": "[SYSTEM] 🔑 Pull Request generated and mapped.",
    "check_ci_status": "[CI/CD] 🧪 Monitoring live pipeline status...",
    "fetch_and_delete_error_logs": "[AWS S3] 📥 Fetching failed CI/CD execution logs...",
    "open_for_resume_request": "[SYSTEM] ✅ Updating PR with wait status...",
    "wait_for_human_approval": "[STANDBY] 💤 Agent entering sleep mode. Awaiting human review...",
    "fetch_pr_feedback": "[AGENT] 🔄 Waking up. Fetching human peer review feedback..."
}

@app.post("/start-agent")
async def start_agent_workflow(payload: AgentVulnerabilityInput):
    thread_id = str(uuid.uuid4())
    config = {"configurable": {"thread_id": thread_id}}
    initial_state = {
        "issue_description": payload.issue_description,
        "repo_owner": payload.repo_owner,
        "repo_name": payload.repo_name,
        "target_file": payload.target_file,
        "messages": []
    }

    async def event_generator():
        try:
            # Emulate pre-agent processing steps for the UI tracker
            yield f"data: {json.dumps({'step': 1, 'log': '[SYSTEM] Parsing vulnerability payload...'})}\n\n"
            await asyncio.sleep(0.5)
            yield f"data: {json.dumps({'step': 2, 'log': '[SYSTEM] Normalizing CVE data and formatting targets...'})}\n\n"
            await asyncio.sleep(0.5)
            yield f"data: {json.dumps({'step': 3, 'log': f'[SYSTEM] Prioritization complete. Target: {payload.repo_owner}/{payload.repo_name}'})}\n\n"
            await asyncio.sleep(0.5)
            
            # Step 4: Actual Agent Execution
            yield f"data: {json.dumps({'step': 4, 'log': '[SYSTEM] Booting Remediation Agent Graph...'})}\n\n"
            await update_workflow_state(thread_id, RUNNING)
            
            async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
                github_workflow_agent = await build_graph(checkpointer=checkpointer)
                
                # Stream the actual LangGraph node execution to the UI
                async for event in github_workflow_agent.astream(initial_state, config=config, stream_mode="updates"):
                    for node_name, state_updates in event.items():
                        # Exclude noisy tool nodes from the UI terminal
                        if node_name == "github_tools":
                            continue
                        
                        log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Executing {node_name}...")
                        yield f"data: {json.dumps({'step': 4, 'log': log_msg})}\n\n"
                        
                        # Add sub-logs if CI failed to provide more UI context
                        if node_name == "check_ci_status" and state_updates.get("ci_status") == "failure":
                            yield f"data: {json.dumps({'step': 4, 'log': '[WARNING] ❌ CI/CD Pipeline failed. Triggering self-healing loop...'})}\n\n"
            
            # If the graph finishes without an interrupt, it's resolved.
            # If it hits the interrupt, the stream closes naturally and UI waits.
            state = await get_workflow_state(thread_id)
            if state != WAITING_FOR_HUMAN_APPROVAL:
                yield f"data: {json.dumps({'step': 5, 'log': '[SYSTEM] 🎉 Workflow Complete. Vulnerability Resolved.'})}\n\n"

        except Exception as e:
            await update_workflow_state(thread_id, FAILED)
            yield f"data: {json.dumps({'step': 'ERROR', 'log': f'[CRITICAL ERROR] Execution failed: {str(e)}'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/github-webhook")
async def github_webhook_listener(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    
    # Save payload for debugging
    async with aiofiles.open("github_webhook_payload2", "a", encoding="utf-8") as f:
        await f.write(json.dumps(payload, indent=4) + "\n\n")

    event_type = request.headers.get("X-GitHub-Event")
    should_continue = False

    if event_type == "pull_request" and payload.get("action") == "closed" and payload["pull_request"].get("merged") is True:
        should_continue = True
    elif event_type == "pull_request_review" and payload.get("action") == "submitted":
        should_continue = True
    elif event_type == "issue_comment" and payload.get("action") == "created" and "pull_request" in payload.get("issue", {}):
        if payload.get("comment", {}).get("body", "").startswith("### 🤖 Automated Remediation Update"):
            return {"status": "ignored"}
        should_continue = True

    if should_continue:
        pr_number = payload.get("pull_request", {}).get("number") or payload.get("issue", {}).get("number")
        if not pr_number:
            return {"status": "ignored"}

        # Fetch thread ID mapped to this PR
        async with aiosqlite.connect("state_db.sqlite") as db:
            async with db.execute("SELECT thread_id FROM pr_mappings WHERE pr_number = ?", (pr_number,)) as cursor:
                row = await cursor.fetchone()
                thread_id = row[0] if row else None
        
        if not thread_id:
            return {"status": "ignored"}

        claimed = await claim_workflow_for_resume(thread_id)
        if not claimed:
            return {"status": "ignored"}

        # Resume agent
        background_tasks.add_task(resume_agent_background, thread_id)
        return {"status": "accepted"}

    return {"status": "ignored"}