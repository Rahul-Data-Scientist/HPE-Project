import uuid
import json
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager

import aiofiles
import aiosqlite
from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

# --- IMPORT AGENT BUILDERS ---
from agents.remediation_agent import build_graph, initialize_agent_components
from agents.parsing_agent import build_parsing_graph
from agents.normalization_graph import build_normalization_graph
from agents.prioritization_graph import build_prioritization_graph

# --- STATE CONSTANTS ---
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
WAITING_FOR_HUMAN_APPROVAL = "WAITING_FOR_HUMAN_APPROVAL"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
RESUMING = "RESUMING"

# --- DATABASE UTILS ---
async def init_database():
    async with aiosqlite.connect("state_db.sqlite") as db:
        # For tracking PRs to thread IDs
        await db.execute("CREATE TABLE IF NOT EXISTS pr_mappings (pr_number INTEGER PRIMARY KEY, thread_id TEXT NOT NULL)")
        # For tracking LangGraph node states
        await db.execute("CREATE TABLE IF NOT EXISTS workflow_state (thread_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL)")
        # For the priority queue system
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY, 
                score REAL, 
                status TEXT NOT NULL, 
                data TEXT NOT NULL
            )
        """)
        await db.commit()

async def update_workflow_state(thread_id: str, status: str):
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute(
            "INSERT OR REPLACE INTO workflow_state (thread_id, status, updated_at) VALUES (?, ?, ?)",
            (thread_id, status, datetime.utcnow().isoformat())
        )
        await db.commit()

async def get_workflow_state(thread_id: str) -> str | None:
    async with aiosqlite.connect("state_db.sqlite") as db:
        async with db.execute("SELECT status FROM workflow_state WHERE thread_id = ?", (thread_id,)) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def claim_workflow_for_resume(thread_id: str) -> bool:
    async with aiosqlite.connect("state_db.sqlite") as db:
        cursor = await db.execute(
            "UPDATE workflow_state SET status = 'RESUMING' WHERE thread_id = ? AND status = 'WAITING_FOR_HUMAN_APPROVAL'",
            (thread_id,)
        )
        await db.commit()
        return cursor.rowcount == 1

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[WS ERROR] Dropping dead connection: {str(e)}")
                dead_connections.append(connection)
                
        # Clean up disconnected clients
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()

# --- BACKGROUND QUEUE PROCESSOR ---
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

async def process_single_task():
    """Processes exactly one PENDING task from the database. Recursively calls itself when finished."""
    async with aiosqlite.connect("state_db.sqlite") as db:
        # ATOMIC CHECK: Only pick up if nothing is currently IN_PROGRESS
        async with db.execute("SELECT count(*) FROM vulnerabilities WHERE status = 'IN_PROGRESS'") as cursor:
            if (await cursor.fetchone())[0] > 0:
                print("[SYSTEM] An agent is already active. Yielding.")
                return 

        # Grab the highest priority PENDING task
        async with db.execute("SELECT vuln_id, data FROM vulnerabilities WHERE status = 'PENDING' ORDER BY score DESC LIMIT 1") as cursor:
            row = await cursor.fetchone()
            
    if not row:
        print("[SYSTEM] Queue empty, returning to idle state.")
        return

    vuln_id, raw_data = row
    task_data = json.loads(raw_data)
    
    # Lock the task so no other worker picks it up
    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute("UPDATE vulnerabilities SET status = 'IN_PROGRESS' WHERE vuln_id = ?", (vuln_id,))
        await db.commit()

    print(f"\n[QUEUE] Processing Vulnerability: {vuln_id}")
    await manager.broadcast({"vuln_id": vuln_id, "status": "IN_PROGRESS"})

    try:
        # Prepare state for the remediation agent
        initial_state = {
            "issue_description": str(task_data),
            "repo_owner": task_data.get("repo_owner", "Rahul-Data-Scientist"), # Fallback
            "repo_name": task_data.get("repo_name", "vulnerability-remediation"), # Fallback
            "messages": []
        }
        
        config = {"configurable": {"thread_id": vuln_id}}
        await update_workflow_state(vuln_id, IN_PROGRESS)
        
        async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
            remediation_graph = await build_graph(checkpointer=checkpointer)
            
            # Stream the LangGraph execution
            async for event in remediation_graph.astream(initial_state, config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools": 
                        continue
                    
                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Executing {node_name}...")
                    await manager.broadcast({"vuln_id": vuln_id, "node": node_name, "log": log_msg})

                    # Handle failure logs visually
                    if node_name == "check_ci_status" and state_updates.get("ci_status") == "failure":
                        await manager.broadcast({"vuln_id": vuln_id, "log": "[WARNING] ❌ CI/CD Pipeline failed. Triggering self-healing loop..."})

                    # Handle the human interrupt
                    if node_name == "wait_for_human_approval":
                        await manager.broadcast({"type": "ACTION_REQUIRED", "vuln_id": vuln_id})
                        return # Stop the chain reaction here; Webhook will resume it later

        # Check if it finished without being interrupted
        current_state = await get_workflow_state(vuln_id)
        if current_state != WAITING_FOR_HUMAN_APPROVAL:
            # Mark as resolved in DB
            async with aiosqlite.connect("state_db.sqlite") as db:
                await db.execute("UPDATE vulnerabilities SET status = 'RESOLVED' WHERE vuln_id = ?", (vuln_id,))
                await db.commit()
            
            await update_workflow_state(vuln_id, COMPLETED)
            await manager.broadcast({"vuln_id": vuln_id, "status": "COMPLETED", "log": f"[SYSTEM] 🎉 {vuln_id} Resolved."})
            
            # RECURSIVE TRIGGER: Start the next task in the queue immediately
            await process_single_task()
            
    except Exception as e:
        print(f"[QUEUE ERROR] {str(e)}")
        await manager.broadcast({"vuln_id": vuln_id, "log": f"[CRITICAL ERROR] {str(e)}"})


# --- BACKGROUND RESUME TASK ---
async def resume_agent_background(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        # 1. Update state in DB
        await update_workflow_state(thread_id, RESUMING)
        
        # 2. IMMEDIATELY tell the UI we are waking up
        await manager.broadcast({
            "vuln_id": thread_id, 
            "status": "IN_PROGRESS", 
            "log": "[WEBHOOK] 🔄 GitHub interaction detected. Resuming remediation pipeline..."
        })
        
        async with AsyncSqliteSaver.from_conn_string("state_db.sqlite") as checkpointer:
            github_workflow_agent = await build_graph(checkpointer=checkpointer)
            
            # 3. Stream the resumed execution
            async for event in github_workflow_agent.astream(Command(resume=True), config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools": continue
                    
                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Resuming {node_name}...")
                    await manager.broadcast({"vuln_id": thread_id, "node": node_name, "log": log_msg})
        
        # 4. Final resolve
        async with aiosqlite.connect("state_db.sqlite") as db:
            await db.execute("UPDATE vulnerabilities SET status = 'RESOLVED' WHERE vuln_id = ?", (thread_id,))
            await db.commit()
            
        await update_workflow_state(thread_id, COMPLETED)
        await manager.broadcast({"vuln_id": thread_id, "status": "COMPLETED", "log": "[SYSTEM] ✅ Human approval processed. Workflow complete."})

        # RECURSIVE TRIGGER: After human approval loop finishes, process next item in queue
        await process_single_task()

    except Exception as e:
        await update_workflow_state(thread_id, FAILED)
        print(f"[CRITICAL ERROR] Resume failed: {e}")
        await manager.broadcast({"vuln_id": thread_id, "log": f"[ERROR] Failed to resume agent: {str(e)}"})


# --- FASTAPI APP & LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database()
    print("[SYSTEM] Booting Security Remediation Core Agent Environment...")
    await initialize_agent_components()
    print("[SYSTEM] System ready. Awaiting inbound vulnerability triggers.\n" + "="*60)
    yield
    # No more background polling loop to cancel!

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ROUTES ---

@app.websocket("/api/v1/ws/updates")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        manager.disconnect(websocket)

@app.post("/api/v1/upload")
async def handle_csv_upload(file: UploadFile = File(...), background_tasks: BackgroundTasks = BackgroundTasks()):
    """Handles the sequential pre-processing pipeline."""
    try:
        # 1. PARSING
        print("-----Started CSV Upload Pipeline-----")
        await manager.broadcast({"step": "Parsing", "log": f"[SYSTEM] Upload received: {file.filename}. Starting Parsing Agent..."})
        file_bytes = await file.read()
        
        parsing_graph = build_parsing_graph()
        parsed_state = await parsing_graph.ainvoke({"file_bytes": file_bytes})
        await manager.broadcast({"log": parsed_state["log_message"]})
        print("-----Parsing Complete-----")
        
        # 2. NORMALIZATION
        await manager.broadcast({"step": "Normalization", "log": "[SYSTEM] Initializing Normalization Agent..."})
        norm_graph = build_normalization_graph()
        norm_state = await norm_graph.ainvoke({"raw_data": parsed_state["raw_data"]})
        await manager.broadcast({"log": norm_state["log_message"]})
        print("-----Normalization Complete-----")
        
        # 3. PRIORITIZATION
        await manager.broadcast({"step": "Prioritization", "log": "[SYSTEM] Calculating threat vectors and CVSS scores..."})
        prio_graph = build_prioritization_graph()
        prio_state = await prio_graph.ainvoke({"normalized_data": norm_state["normalized_data"]})
        await manager.broadcast({"log": prio_state["log_message"]})
        print("-----Prioritization Complete-----")
        
        # 4. QUEUEING (Save to SQLite DB)
        tasks = prio_state["prioritized_data"]
        async with aiosqlite.connect("state_db.sqlite") as db:
            for task in tasks:
                if "vuln_id" not in task or not task["vuln_id"]:
                    task["vuln_id"] = f"VULN-{uuid.uuid4().hex[:6]}"
                
                score = task.get("priority_score", 5.0)
                
                await db.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (vuln_id, score, status, data) VALUES (?, ?, ?, ?)",
                    (task["vuln_id"], score, PENDING, json.dumps(task))
                )
            await db.commit()
        
        print("-----Queueing Complete-----")
        
        # 5. UI SYNCHRONIZATION
        await manager.broadcast({
            "type": "NEW_BATCH",
            "step": "Remediation",
            "log": "[SYSTEM] Pre-processing complete. Handing off to Remediation Queue...",
            "tasks": tasks[:10] # Send top 10 to UI
        })

        # 6. KICKSTART THE BACKGROUND QUEUE
        background_tasks.add_task(process_single_task)

        return {"status": "success", "queued_items": len(tasks)}

    except Exception as e:
        await manager.broadcast({"log": f"[CRITICAL ERROR] Pipeline failed: {str(e)}"})
        return {"status": "error", "message": str(e)}


@app.post("/github-webhook")
async def github_webhook_listener(request: Request, background_tasks: BackgroundTasks):
    """Listens for GitHub PR actions to resume waiting agents."""
    payload = await request.json()
    
    async with aiofiles.open("github_webhook_payload2.json", "a", encoding="utf-8") as f:
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
            return {"status": "ignored", "reason": "already_resuming"}

        # Force UI update IMMEDIATELY so the user knows the merge was detected
        await manager.broadcast({
            "vuln_id": thread_id, 
            "status": "IN_PROGRESS", 
            "log": "[WEBHOOK] 🚀 GitHub Merge detected. Agent waking up..."
        })

        background_tasks.add_task(resume_agent_background, thread_id)
        return {"status": "accepted"}

    return {"status": "ignored"}


@app.get("/api/v1/status/{vuln_id}")
async def get_vuln_status(vuln_id: str):
    async with aiosqlite.connect("state_db.sqlite") as db:
        async with db.execute("SELECT status FROM vulnerabilities WHERE vuln_id = ?", (vuln_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return {"vuln_id": vuln_id, "status": row[0]}
    return {"status": "NOT_FOUND"}