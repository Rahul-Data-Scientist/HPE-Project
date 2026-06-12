import uuid
import json
from datetime import datetime
from contextlib import asynccontextmanager

import aiofiles
import aiosqlite

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

from remediation_agent import build_graph, initialize_agent_components

RUNNING = "RUNNING"
WAITING_FOR_HUMAN_APPROVAL = "WAITING_FOR_HUMAN_APPROVAL"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
RESUMING = "RESUMING"

async def update_workflow_state(thread_id: str, status: str):
    # Suppressed verbose stdout state logs for presentation
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO workflow_state
            (thread_id, status, updated_at)
            VALUES (?, ?, ?)
            """,
            (thread_id, status, datetime.utcnow().isoformat())
        )
        await db.commit()

async def claim_workflow_for_resume(thread_id: str) -> bool:
    async with aiosqlite.connect("state_db.sqlite") as db:
        cursor = await db.execute(
            """
            UPDATE workflow_state
            SET status = 'RESUMING'
            WHERE thread_id = ?
              AND status = 'WAITING_FOR_HUMAN_APPROVAL'
            """,
            (thread_id,)
        )
        await db.commit()
        return cursor.rowcount == 1

async def get_workflow_state(thread_id: str) -> str | None:
    async with aiosqlite.connect("state_db.sqlite") as db:
        async with db.execute("SELECT status FROM workflow_state WHERE thread_id = ?", (thread_id,)) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def get_pr_number(payload):
    if "pull_request" in payload:
        return payload["pull_request"]["number"]
    if "issue" in payload and "pull_request" in payload["issue"]:
        return payload["issue"]["number"]
    return None

async def get_thread_id_by_pr(pr_number: int) -> str | None:
    if pr_number is None:
        return None
    async with aiosqlite.connect("state_db.sqlite") as db:
        async with db.execute("SELECT thread_id FROM pr_mappings WHERE pr_number = ?", (pr_number,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]
    return None

async def resume_agent_background(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        await update_workflow_state(thread_id, RUNNING)

        async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
            github_workflow_agent = await build_graph(checkpointer=checkpointer)
            agent_stream = github_workflow_agent.astream(Command(resume=True), config=config, stream_mode="updates")
            
            async for event in agent_stream:
                pass  # Internal graph steps are handled gracefully via node prints now

        current_state = await get_workflow_state(thread_id)
        if current_state == RUNNING:
            await update_workflow_state(thread_id, COMPLETED)
            print("\n[SYSTEM] 🎉 Session Closed. Vulnerability resolved and fully integrated.")

    except Exception as e:
        await update_workflow_state(thread_id, FAILED)
        print(f"[CRITICAL ERROR] Execution failed: {e}")

async def init_database():
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute("CREATE TABLE IF NOT EXISTS pr_mappings (pr_number INTEGER PRIMARY KEY, thread_id TEXT NOT NULL)")
        await db.execute("CREATE TABLE IF NOT EXISTS workflow_state (thread_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL)")
        await db.commit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database()
    print("[SYSTEM] Booting Security Remediation Core Agent Environment...")
    await initialize_agent_components()
    print("[SYSTEM] System ready. Awaiting inbound vulnerability triggers.\n" + "="*60)
    yield

app = FastAPI(lifespan=lifespan)

class AgentVulnerabilityInput(BaseModel):
    issue_description: str
    repo_owner: str
    repo_name: str
    target_file: str

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
            await update_workflow_state(thread_id, RUNNING)
            async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
                github_workflow_agent = await build_graph(checkpointer=checkpointer)
                
                async for event in github_workflow_agent.astream(initial_state, config=config, stream_mode="updates"):
                    pass # Handled inside clean node print logs
                
                yield "data: Agent initialization complete. Live monitoring active.\n\n"
        except Exception as e:
            await update_workflow_state(thread_id, FAILED)
            yield f"data: Error during execution: {str(e)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/github-webhook")
async def github_webhook_listener(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    
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
        pr_number = await get_pr_number(payload)
        thread_id = await get_thread_id_by_pr(pr_number)
        
        if not thread_id:
            return {"status": "ignored"}

        claimed = await claim_workflow_for_resume(thread_id)
        if not claimed:
            return {"status": "ignored"}

        background_tasks.add_task(resume_agent_background, thread_id)
        return {"status": "accepted"}

    return {"status": "ignored"}