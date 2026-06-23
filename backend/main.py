import uuid
import json
import asyncio
from datetime import datetime, timedelta, timezone
import os
import asyncpg
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiofiles
import aiosqlite
from fastapi import FastAPI, Request, BackgroundTasks, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.types import Command

# --- IMPORT AGENT BUILDERS ---
from agents.parsing_agent import build_parsing_graph
from agents.normalization_graph import build_normalization_graph
from agents.main_workflow import run_remediation_pipeline
from agents.asset_lookup_agent import asset_lookup_graph
from agents.prioritization_graph import run_prioritization_agent
from agents.remediation_agent import build_graph, initialize_agent_components
import pandas as pd

from utils.migrate import migrate_sqlite_to_psql

# --- PATH CONFIGURATION ---
PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = str(PROJECT_ROOT / "state_db.sqlite")
clean_path = str(DB_PATH).replace("\\", "/")

# --- STATE CONSTANTS ---
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
WAITING_FOR_HUMAN_APPROVAL = "WAITING_FOR_HUMAN_APPROVAL"
COMPLETED = "COMPLETED"
FAILED = "FAILED"
RESUMING = "RESUMING"

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:vaibhav@localhost:5432/postgres")

# Global lock to prevent race conditions when multiple uploads happen simultaneously
queue_lock = asyncio.Lock()

async def printS(data):
    print(data)

# --- DATABASE UTILS ---
async def init_database():
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        
        await db.execute("CREATE TABLE IF NOT EXISTS pr_mappings (pr_number INTEGER PRIMARY KEY, thread_id TEXT NOT NULL)")
        await db.execute("CREATE TABLE IF NOT EXISTS workflow_state (thread_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL)")
        
        await db.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                thread_id TEXT PRIMARY KEY,
                asset_id TEXT , 
                cve_id TEXT,
                score REAL, 
                resolved BOOLEAN DEFAULT 0,
                cost REAL DEFAULT 0.00,
                token INTEGER DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                time_taken REAL,
                status TEXT NOT NULL, 
                data TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0,
                error_reason TEXT
            )
        """)  
        await db.commit()

async def update_workflow_state(thread_id: str, status: str):
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        await db.execute(
            "INSERT OR REPLACE INTO workflow_state (thread_id, status, updated_at) VALUES (?, ?, ?)",
            (thread_id, status, datetime.now(timezone.utc).isoformat())
        )
        await db.commit()

async def get_workflow_state(thread_id: str) -> str | None:
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        async with db.execute("SELECT status FROM workflow_state WHERE thread_id = ?", (thread_id,)) as cursor:
            row = await cursor.fetchone()
    return row[0] if row else None

async def claim_workflow_for_resume(thread_id: str) -> bool:
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        cursor = await db.execute(
            "UPDATE workflow_state SET status = 'RESUMING' WHERE thread_id = ? AND status = 'WAITING_FOR_HUMAN_APPROVAL'",
            (thread_id,)
        )
        await db.commit()
        return cursor.rowcount == 1

# --- WEBHOOK HELPER UTILS ---
async def get_pr_number(payload):
    if "pull_request" in payload:
        return payload["pull_request"]["number"]
    if "issue" in payload and "pull_request" in payload["issue"]:
        return payload["issue"]["number"]
    return None

async def get_thread_id_by_pr(pr_number: int) -> str | None:
    if pr_number is None:
        return None
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        async with db.execute("SELECT thread_id FROM pr_mappings WHERE pr_number = ?", (pr_number,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]
    return None

# --- WEBSOCKET MANAGER ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self.last_log_cache: dict = None  

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
        if self.last_log_cache:
            try:
                await websocket.send_json(self.last_log_cache)
            except Exception:
                pass

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        if "log" in message or "status" in message or "node" in message:
            self.last_log_cache = message
            
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"[WS ERROR] Dropping dead connection: {str(e)}")
                dead_connections.append(connection)
                
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
    "fetch_pr_feedback": "[AGENT] 🔄 Waking up. Fetching human peer review feedback...",
    "calculate_tokens_and_cost_consumption": "[SYSTEM] 💸 Calculating token usage and cost..."
}

async def check_and_run_final_migration():
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        async with db.execute("SELECT count(*) FROM vulnerabilities WHERE status IN ('PENDING', 'IN_PROGRESS', 'WAITING_FOR_APPROVAL', 'RESUMING')") as cursor:
            active_count = (await cursor.fetchone())[0]

        if active_count > 0:
            return  

        await printS("\n[SYSTEM] 🏁 All vulnerabilities processed! Calculating totals...")

        async with db.execute("SELECT SUM(cost), SUM(token) FROM vulnerabilities") as cursor:
            row = await cursor.fetchone()
            total_cost = row[0] or 0.0
            total_tokens = row[1] or 0

        await printS(f"[SYSTEM] 💰 Final Batch Cost: ${total_cost:.4f} ({total_tokens} tokens)")
        await printS("[SYSTEM] Executing final PSQL migration...")

    result = await migrate_sqlite_to_psql(sqlite_path=clean_path, psql_dsn=DATABASE_URL)

    if result["status"] == "success":
        await printS(f"[SYSTEM] ✅ Auto-Migration Complete: {result['message']}")
        
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            await db.execute("DELETE FROM vulnerabilities")
            await db.execute("DELETE FROM pr_mappings")
            await db.execute("DELETE FROM workflow_state")
            await db.commit() 
            await db.execute("VACUUM")
            
        await printS("[SYSTEM] 🧹 Local queue cleared. Ready for next upload.\n" + "="*60)
    else:
        await printS(f"[CRITICAL ERROR] ❌ Auto-Migration Failed: {result['message']}")

async def process_single_task():
    await asyncio.sleep(0.2) 
    row = []
    async with queue_lock:
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            async with db.execute("SELECT count(*) FROM vulnerabilities WHERE status = 'IN_PROGRESS'") as cursor:
                if (await cursor.fetchone())[0] > 0:
                    print("[SYSTEM] An agent is already active. Yielding.")
                    return 

            async with db.execute("SELECT thread_id, data, retry_count, cve_id, score FROM vulnerabilities WHERE status = 'PENDING' ORDER BY score DESC LIMIT 1") as cursor:
                row = await cursor.fetchone()
                
        if not row:
            print("[SYSTEM] Queue empty, returning to idle state.")
            await check_and_run_final_migration()
            return

        thread_id = row[0]
        raw_data = row[1]
        retry_count = row[2] or 0
        cve_id = row[3]
        score = row[4]
         
        task_data = json.loads(raw_data)
        refc = task_data.get("references", [])[:3]
        
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            await db.execute("UPDATE vulnerabilities SET status = 'IN_PROGRESS', error_reason = NULL WHERE thread_id = ?", (thread_id,))
            await db.commit()

    print(f"\n[QUEUE] Processing Vulnerability: {thread_id} (Attempt {retry_count + 1}/3)")
    await manager.broadcast({
        "thread_id": thread_id, 
        "vuln_id": cve_id,   
        "score": score,      
        "status": "IN_PROGRESS"
    })

    try:
        initial_state = {
            "issue_description": str(task_data),
            "repo_owner": task_data.get("repo_owner", "Rahul-Data-Scientist"),
            "repo_name": task_data.get("repo_name", "vulnerability-remediation"),
            "start_time": datetime.now(timezone.utc).isoformat(),
            "messages": [],
            "reference_links": refc
        }
        
        config = {"configurable": {"thread_id": thread_id}}
        await update_workflow_state(thread_id, IN_PROGRESS)
        
        async with AsyncSqliteSaver.from_conn_string(clean_path) as checkpointer:
            remediation_graph = await build_graph(checkpointer=checkpointer)
            logged_nodes = set()
            
            async for event in remediation_graph.astream(initial_state, config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools": 
                        continue
                    
                    if node_name == "__interrupt__":
                        await manager.broadcast({
                            "type": "ACTION_REQUIRED", 
                            "thread_id": thread_id,
                            "node": "wait_for_human_approval",
                            "status": "WAITING_FOR_APPROVAL",
                            "log": "[STANDBY] 💤 Agent entering sleep mode. Awaiting human review..."
                        })
                        
                        await update_workflow_state(thread_id, WAITING_FOR_HUMAN_APPROVAL)
                        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
                            await db.execute("UPDATE vulnerabilities SET status = 'WAITING_FOR_APPROVAL' WHERE thread_id = ?", (thread_id,))
                            await db.commit()
                        return 

                    if node_name == "github_workflow":
                        if "github_workflow" in logged_nodes:
                            continue
                        logged_nodes.add("github_workflow")

                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Executing {node_name}...")
                    await manager.broadcast({"thread_id": thread_id, "node": node_name, "log": log_msg})

                    if node_name == "check_ci_status" and state_updates.get("ci_status") == "failure":
                        await manager.broadcast({"thread_id": thread_id, "log": "[WARNING] ❌ CI/CD Pipeline failed. Triggering self-healing loop..."})

            current_state = await get_workflow_state(thread_id)
            if current_state != WAITING_FOR_HUMAN_APPROVAL:
                final_state = await remediation_graph.aget_state(config)
                values = final_state.values
                
                cost = values.get("total_cost", 0.0)
                token = values.get("input_tokens", 0) + values.get("output_tokens", 0)
                start_time = values.get("start_time")
                end_time = values.get("end_time")
                time_taken = values.get("active_execution_time", 0.0)
                
                async with aiosqlite.connect(clean_path, timeout=5.0) as db:
                    await db.execute("UPDATE vulnerabilities SET status = 'RESOLVED', resolved = TRUE, cost = ?, token = ?, start_time = ?, end_time = ?, time_taken = ? WHERE thread_id = ?", (cost, token, start_time, end_time, time_taken, thread_id))
                    await db.commit()
                
                await update_workflow_state(thread_id, COMPLETED)
                await manager.broadcast({"thread_id": thread_id, "status": "COMPLETED", "log": f"[SYSTEM] 🎉 {thread_id} Resolved."})
                
                asyncio.create_task(process_single_task())
            
    except Exception as e:
        error_msg = str(e)
        print(f"[QUEUE ERROR] {error_msg}")
        
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            if retry_count < 2:
                new_count = retry_count + 1
                await db.execute("UPDATE vulnerabilities SET status = 'PENDING', retry_count = ?, error_reason = ? WHERE thread_id = ?", 
                                 (new_count, f"Attempt {retry_count + 1} Failed: {error_msg}", thread_id))
                await db.commit()
                await manager.broadcast({
                    "thread_id": thread_id, 
                    "status": "PENDING", 
                    "log": f"[WARNING] Network/Execution Error. Auto-retrying {thread_id} (Attempt {new_count + 1}/3)..."
                })
                await asyncio.sleep(10)
            else:
                await db.execute("UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = ? WHERE thread_id = ?", 
                                 (f"Permanent Failure: {error_msg}", thread_id))
                await db.commit()
                await update_workflow_state(thread_id, FAILED)
                await manager.broadcast({
                    "thread_id": thread_id, 
                    "status": "FAILED", 
                    "log": f"[CRITICAL ERROR] Failed permanently after 3 attempts. Skipping. Error: {error_msg}"
                })
        
        asyncio.create_task(process_single_task())

async def resume_agent_background(thread_id: str):
    config = {"configurable": {"thread_id": thread_id}}
    try:
        await update_workflow_state(thread_id, RESUMING)
        
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            await db.execute("UPDATE vulnerabilities SET status = 'IN_PROGRESS', error_reason = NULL WHERE thread_id = ?", (thread_id,))
            await db.commit()
        
        await manager.broadcast({
            "thread_id": thread_id, 
            "status": "IN_PROGRESS", 
            "log": "[WEBHOOK] 🚀 GitHub Webhook triggered. Agent waking up..."
        })
        
        async with AsyncSqliteSaver.from_conn_string(clean_path) as checkpointer:
            github_workflow_agent = await build_graph(checkpointer=checkpointer)
            logged_nodes = set()
            
            async for event in github_workflow_agent.astream(Command(resume=True), config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools": 
                        continue
                        
                    if node_name == "__interrupt__":
                        await manager.broadcast({
                            "type": "ACTION_REQUIRED", 
                            "thread_id": thread_id,
                            "node": "wait_for_human_approval",
                            "status": "WAITING_FOR_APPROVAL",
                            "log": "[STANDBY] 💤 Agent entering sleep mode. Awaiting human review..."
                        })
                        
                        await update_workflow_state(thread_id, WAITING_FOR_HUMAN_APPROVAL)
                        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
                            await db.execute("UPDATE vulnerabilities SET status = 'WAITING_FOR_APPROVAL' WHERE thread_id = ?", (thread_id,))
                            await db.commit()
                        return 
                    
                    if node_name == "github_workflow":
                        if "github_workflow" in logged_nodes:
                            continue
                        logged_nodes.add("github_workflow")
                        
                    if node_name == "wait_for_human_approval":
                        continue
                    
                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Resuming {node_name}...")
                    await manager.broadcast({"thread_id": thread_id, "node": node_name, "log": log_msg})

                    if node_name == "check_ci_status" and state_updates.get("ci_status") == "failure":
                        await manager.broadcast({"thread_id": thread_id, "log": "[WARNING] ❌ CI/CD Pipeline failed. Triggering self-healing loop..."})

            final_state = await github_workflow_agent.aget_state(config)
            values = final_state.values
            
            cost = values.get("total_cost", 0.0)
            token = values.get("input_tokens", 0) + values.get("output_tokens", 0)
            start_time = values.get("start_time")
            end_time = values.get("end_time")
            time_taken = values.get("active_execution_time", 0.0)
            
            async with aiosqlite.connect(clean_path, timeout=5.0) as db:
                await db.execute(
                    "UPDATE vulnerabilities SET status = 'RESOLVED', resolved = TRUE, cost = ?, token = ?, start_time = ?, end_time = ?, time_taken = ? WHERE thread_id = ?", 
                    (cost, token, start_time, end_time, time_taken, thread_id)
                )
                await db.commit()
                
            await update_workflow_state(thread_id, COMPLETED)
            await manager.broadcast({"thread_id": thread_id, "status": "COMPLETED", "log": "[SYSTEM] ✅ Human approval processed. Workflow complete."})

            asyncio.create_task(process_single_task())

    except Exception as e:
        error_msg = str(e)
        print(f"[CRITICAL ERROR] Resume failed: {error_msg}")
        
        async with aiosqlite.connect(clean_path, timeout=5.0) as db:
            async with db.execute("SELECT retry_count FROM vulnerabilities WHERE thread_id = ?", (thread_id,)) as cursor:
                row = await cursor.fetchone()
                retry_count = row[0] if (row and len(row) > 0) else 0

            if retry_count < 2:
                new_count = retry_count + 1
                await db.execute("UPDATE vulnerabilities SET status = 'WAITING_FOR_APPROVAL', retry_count = ?, error_reason = ? WHERE thread_id = ?", 
                                 (new_count, f"Resume Attempt {retry_count + 1} Failed: {error_msg}", thread_id))
                await db.commit()
                await update_workflow_state(thread_id, WAITING_FOR_HUMAN_APPROVAL)
                await manager.broadcast({
                    "thread_id": thread_id, 
                    "status": "WAITING_FOR_APPROVAL", 
                    "log": f"[WARNING] Resume crashed. Webhook can be re-triggered (Attempt {new_count + 1}/3)..."
                })
            else:
                await db.execute("UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = ? WHERE thread_id = ?", 
                                 (f"Resume Permanent Failure: {error_msg}", thread_id))
                await db.commit()
                await update_workflow_state(thread_id, FAILED)
                await manager.broadcast({
                    "thread_id": thread_id, 
                    "status": "FAILED", 
                    "log": f"[ERROR] Failed to resume permanently after 3 attempts: {error_msg}"
                })

        asyncio.create_task(process_single_task())

# --- FASTAPI APP & LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[SYSTEM] Connecting to PostgreSQL...")
    app.state.pool = await asyncpg.create_pool(DATABASE_URL)
    
    await init_database()
    
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        await db.execute(
            "UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = 'Server crashed or restarted during active execution' "
            "WHERE status = 'IN_PROGRESS' OR status = 'RESUMING'"
        )
        await db.execute("UPDATE workflow_state SET status = 'FAILED' WHERE status = 'IN_PROGRESS' OR status = 'RESUMING'")
        await db.commit()
    
    print("[SYSTEM] Booting Security Remediation Core Agent Environment...")
    await initialize_agent_components()
    print("[SYSTEM] System ready. Awaiting inbound vulnerability triggers.\n" + "="*60)
    yield
    
    await app.state.pool.close()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
async def handle_csv_upload(files: list[UploadFile] = File(...), background_tasks: BackgroundTasks = BackgroundTasks()):
    try:
        await printS("-----Started CSV Upload Pipeline-----")
        
        # 1. Ensure directory exists and clear previous files
        UPLOAD_DIR = PROJECT_ROOT / "raw_scanner_outputs"
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        for item in UPLOAD_DIR.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                except Exception as e:
                    await printS(f"[WARNING] Could not delete old file {item.name}: {e}")
                    
        await printS("[SYSTEM] Cleared previous scanner outputs.")
        
        # 2. Save the newly uploaded files
        saved_files = []
        for file in files:
            file_path = UPLOAD_DIR / file.filename
            async with aiofiles.open(file_path, 'wb') as out_file:
                while content := await file.read(1024 * 1024):  
                    await out_file.write(content)
            
            saved_files.append(file.filename)
            await manager.broadcast({
                "log": f"[SYSTEM] Successfully saved {file.filename} to {UPLOAD_DIR.name}/"
            })
        
        
        await manager.broadcast({"step": "Parsing", "log": f"[SYSTEM] Upload received: {len(files)} files."})
        
        await manager.broadcast({"log": f"[SYSTEM] Starting Parsing Agent..."})
        
        parsing_graph = build_parsing_graph()
        parser_inputs = {
            "folder_path": "raw_scanner_outputs",
            "parse_code_file_path": "agents/generated_parser_func.py" 
        }
        parsed_state = parsing_graph.invoke(parser_inputs)
        await manager.broadcast({"log": "Parsing Done"})
        await printS("-----Parsing Complete-----")
        
        await manager.broadcast({"step": "Normalization", "log": "[SYSTEM] Initializing Normalization Agent..."})
        normalizer = build_normalization_graph()
        normalizer_inputs = {
            "folder_path": "parsed_csvs" 
        }
        
        normalize_result_state = normalizer.invoke(normalizer_inputs)
        await manager.broadcast({"log": "✅ Normalization Agent completed successfully."})
        await printS("-----Normalization Complete-----")
        
        await manager.broadcast({"step": "Prioritization", "log": "[SYSTEM] Calculating threat vectors and CVSS scores..."})
        CURRENT_DIR = Path(__file__).resolve().parent
        WORKING_CSV_PATH = CURRENT_DIR / "normalized_output" / "working.csv"
        run_remediation_pipeline(WORKING_CSV_PATH)
        initial_state = {
            "working_csv": str(WORKING_CSV_PATH),
            "status": "running",
            "error": None,
            "new_count": 0,
            "existing_count": 0,
        }

        final_state = asset_lookup_graph.invoke(initial_state)
        run_prioritization_agent(str(WORKING_CSV_PATH))
        
        await manager.broadcast({"log": "Prioritization Completed! Starting Remediation..."})
        await printS("-----Prioritization Complete-----")
        
        df = pd.read_csv(str(WORKING_CSV_PATH))
        df = df.where(pd.notnull(df), None)
        tasks = df.to_dict(orient="records")
        
        if not tasks:
            await printS("-----Queueing Complete - No Actions Found-----")
            await manager.broadcast({"log": "[SYSTEM] Pre-processing complete. No actionable vulnerabilities were parsed."})
            return {"status": "success", "queued_items": 0}

        # 1. Sort the tasks by priority score / score (highest to lowest)
        tasks.sort(key=lambda x: float(x.get("priority_score") or x.get("score") or 0.0), reverse=True)
        
        # 2. Slice the top 10 elements BEFORE saving to the DB queue
        BATCH_LIMIT = 10
        top_tasks = tasks[:BATCH_LIMIT]
            
        async with aiosqlite.connect(clean_path, timeout=10.0) as db:
            for task in tasks: # FIX: Iterate over top_tasks only
                if "thread_id" not in task or not task["thread_id"]:
                    task["thread_id"] = f"VULN-{uuid.uuid4().hex[:6]}"
                
                score = float(task.get("priority_score", task.get("score", 5.0)))
                cve_id = task.get("vuln_id", task.get("cve_id", task["asset_id"]))
                asset_id = task.get("asset_id",task["asset_id"]);
                
                # Update map keys back to object for JSON payload consistency
                task["thread_id"] = task["thread_id"]
                task["vuln_id"] = cve_id
                task["score"] = score
                
                await db.execute(
                    "INSERT OR IGNORE INTO vulnerabilities (thread_id, asset_id, cve_id, score, status, data) VALUES (?, ?, ?, ?, ?,?)",
                    (task["thread_id"], asset_id ,cve_id, score, PENDING, json.dumps(task))
                )
            await db.commit()
        
        await printS(f"-----Queueing Complete - Stored Top {len(top_tasks)}-----")
        
        await manager.broadcast({
            "type": "NEW_BATCH",
            "step": "Remediation",
            "log": f"[SYSTEM] Pre-processing complete. Handing off top {len(top_tasks)} items to Remediation Queue...",
            "tasks": top_tasks
        })

        background_tasks.add_task(process_single_task)
        return {"status": "success", "queued_items": len(top_tasks)}

    except Exception as e:
        await manager.broadcast({"log": f"[CRITICAL ERROR] Pipeline failed: {str(e)}"})
        return {"status": "error", "message": str(e)}

@app.post("/github-webhook")
async def github_webhook_listener(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    
    async with aiofiles.open("github_webhook_payload2.json", "a", encoding="utf-8") as f:
        await f.write(json.dumps(payload, indent=4) + "\n\n")

    event_type = request.headers.get("X-GitHub-Event")
    should_continue = False

    if event_type == "pull_request" and payload.get("action") == "closed" and payload["pull_request"].get("merged") is True:
        should_continue = True
    elif event_type == "pull_request" and payload.get("action") == "closed" and not payload["pull_request"].get("merged"):
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
            return {"status": "ignored", "reason": "already_resuming"}

        await manager.broadcast({
            "thread_id": thread_id, 
            "status": "IN_PROGRESS", 
            "log": "[WEBHOOK] 🔄 GitHub interaction detected. Resuming remediation pipeline..."
        })

        background_tasks.add_task(resume_agent_background, thread_id)
        return {"status": "accepted"}

    return {"status": "ignored"}

@app.get("/api/v1/status/{thread_id}")
async def get_vuln_status(thread_id: str):
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        async with db.execute("SELECT status FROM vulnerabilities WHERE thread_id = ?", (thread_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return {"thread_id": thread_id, "status": row[0]}
    return {"status": "NOT_FOUND"}

@app.get("/api/v1/system-state")
async def get_system_state():
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        async with db.execute(
            "SELECT thread_id, status FROM vulnerabilities WHERE status IN ('IN_PROGRESS', 'RESUMING', 'WAITING_FOR_APPROVAL') LIMIT 1"
        ) as cursor:
            active_row = await cursor.fetchone()

        async with db.execute("SELECT count(*) FROM vulnerabilities WHERE status = 'PENDING'") as cursor:
            pending = (await cursor.fetchone())[0]
        async with db.execute("SELECT count(*) FROM vulnerabilities WHERE status IN ('RESOLVED', 'FAILED')") as cursor:
            finished = (await cursor.fetchone())[0]
        async with db.execute("SELECT count(*) FROM vulnerabilities") as cursor:
            total = (await cursor.fetchone())[0]

        async with db.execute("SELECT thread_id, cve_id, score, status, asset_id FROM vulnerabilities") as cursor:
            all_vulns = await cursor.fetchall()

        vulns = [{"thread_id": v[0], "vuln_id": v[1], "score": v[2], "status": v[3], "asset_id" : v[4]} for v in all_vulns]

        return {
            "active_task": {"thread_id": active_row[0], "status": active_row[1]} if active_row else None,
            "metrics": {"pending": pending, "finished": finished, "total": total},
            "vulnerabilities": vulns
        }

# ==========================================
# DASHBOARD REST ENDPOINT (PostgreSQL)
# ==========================================
def format_mttr(td: timedelta) -> str:
    if not td: return "0m 0s"
    total_seconds = int(td.total_seconds())
    minutes, seconds = divmod(total_seconds, 60)
    return f"{minutes}m {seconds}s"

def get_severity_label_and_color(score: float): 
    if score is None: return "Low", "#3B82F6"
    if score >= 9.0: return "Critical", "#EF4444"
    if score >= 7.0: return "High", "#F97316"
    if score >= 4.0: return "Medium", "#EAB308"
    return "Low", "#3B82F6"

@app.get("/api/v1/dashboard")
async def get_dashboard_data(request: Request):
    pool = request.app.state.pool
    try:
        async with pool.acquire() as conn:
            kpi_row = await conn.fetchrow("""
                SELECT 
                    COALESCE(SUM(cost), 0) / NULLIF(COUNT(*), 0) as raw_avg_cost,
                    SUM(time_taken) / NULLIF(COUNT(*), 0) as raw_avg_mttr,
                    COUNT(CASE WHEN resolved = true THEN 1 END) as total_solved,
                    COUNT(CASE WHEN resolved = false OR resolved IS NULL THEN 1 END) as pending_vulns,
                    COUNT(*) as total_vulns,
                    COALESCE(SUM(token), 0) as total_tokens
                FROM vulnerabilities
            """)
            
            total_solved = int(kpi_row['total_solved'] or 0)
            pending_vulns = int(kpi_row['pending_vulns'] or 0)
            total_vulns = int(kpi_row['total_vulns'] or 0)
            success_rate = round((total_solved / total_vulns) * 100, 1) if total_vulns > 0 else 0

            severities_rows = await conn.fetch("SELECT score FROM vulnerabilities")
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for row in severities_rows:
                label, _ = get_severity_label_and_color(float(row['score']))
                severity_counts[label] += 1
                
            severities_data = [
                {"name": "Critical", "value": severity_counts["Critical"], "color": "#EF4444"},
                {"name": "High", "value": severity_counts["High"], "color": "#F97316"},
                {"name": "Medium", "value": severity_counts["Medium"], "color": "#EAB308"},
                {"name": "Low", "value": severity_counts["Low"], "color": "#3B82F6"}
            ]

            tokens_rows = await conn.fetch("""
                SELECT 
                    TO_CHAR(DATE_TRUNC('hour', start_time), 'Mon DD, HH:MI AM') as time, 
                    SUM(token) as tokens
                FROM vulnerabilities 
                WHERE start_time IS NOT NULL
                GROUP BY DATE_TRUNC('hour', start_time) 
                ORDER BY DATE_TRUNC('hour', start_time) ASC
            """)
            tokens_data = [{"time": r['time'], "tokens": r['tokens']} for r in tokens_rows]
            if not tokens_data: tokens_data = [{"time": "No Data", "tokens": 0}]

            recent_rows = await conn.fetch("""
                SELECT thread_id, cve_id, asset_id, score, resolved, end_time, start_time
                FROM vulnerabilities 
                ORDER BY COALESCE(end_time, start_time) DESC 
                LIMIT 10
            """)
            
            recent_activity = []
            for r in recent_rows:
                label, _ = get_severity_label_and_color(float(r['score']))
                timestamp = r['end_time'] if r['resolved'] else r['start_time']
                recent_activity.append({
                    "id": r['cve_id'] or r['thread_id'],
                    "name": f"vulnerabilities on {r['thread_id']}",
                    "severity": label,
                    "status": "Resolved" if r['resolved'] else "Pending",
                    "time": timestamp.strftime('%H:%M %p') if timestamp else "N/A"
                })

            return {
                "kpis": {
                    "avg_cost": float(kpi_row['raw_avg_cost'] or 0),
                    "avg_mttr": format_mttr(kpi_row['raw_avg_mttr']),
                    "total_vulns": total_vulns,
                    "total_solved": total_solved,
                    "total_tokens": int(kpi_row['total_tokens']),
                    "success_rate": success_rate,
                    "pending_vulns": pending_vulns
                },
                "tokens": tokens_data,
                "severities": severities_data,
                "recent_activity": recent_activity
            }
    except Exception as e:
        print(f"[API ERROR] Dashboard Data: {str(e)}")
        return {"error": str(e)}

UPLOAD_DIR = PROJECT_ROOT / "raw_scanner_outputs"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True) 

@app.post("/api/v1/upload-multiple")
async def handle_multiple_uploads(files: list[UploadFile] = File(...)):
    try:
        await printS(f"-----Started Multiple File Upload ({len(files)} files)-----")
        saved_files = []

        for file in files:
            file_path = UPLOAD_DIR / file.filename
            async with aiofiles.open(file_path, 'wb') as out_file:
                while content := await file.read(1024 * 1024):  
                    await out_file.write(content)
            
            saved_files.append(file.filename)
            await manager.broadcast({
                "log": f"[SYSTEM] Successfully saved {file.filename} to {UPLOAD_DIR.name}/"
            })

        await printS("-----Uploads Saved to Disk Complete-----")
        return {"status": "success", "saved_files": saved_files, "folder": str(UPLOAD_DIR)}

    except Exception as e:
        error_msg = str(e)
        await manager.broadcast({"log": f"[CRITICAL ERROR] File save failed: {error_msg}"})
        return {"status": "error", "message": error_msg}
    
    
    
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        reload=True,
        reload_excludes=[
            "normalized_output/*",
            "parsed_csvs/*",
            "raw_scanner_outputs/*",
            "uploaded_files/*",
            "generated_normalization_func.py",
            "state_db.sqlite",
            "agents/*"
        ]
    )