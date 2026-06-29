import uuid
import json
import asyncio
from datetime import datetime, timedelta, timezone
import os
import asyncpg
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
import urllib.parse

import logging

# Quiet down the underlying HTTP client libraries
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("mcp").setLevel(logging.WARNING)

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
from agents.prioritization_agent import run_prioritization_agent
from agents.remediation_agent import build_graph, initialize_agent_components
import pandas as pd
from lib.utils import printS
from lib.migrate import migrate_sqlite_to_psql

from dotenv import load_dotenv

# --- PATH CONFIGURATION ---
PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = str(PROJECT_ROOT / "state_db.sqlite")
clean_path = str(DB_PATH).replace("\\", "/")

# --- STATE CONSTANTS ---
PENDING = "PENDING"
IN_PROGRESS = "IN_PROGRESS"
WAITING_FOR_HUMAN_APPROVAL = "WAITING_FOR_HUMAN_APPROVAL"
APPROVED_READY = "APPROVED_READY"  
COMPLETED = "COMPLETED"
FAILED = "FAILED"
RESUMING = "RESUMING"

# Locate and load the environment variables from .env
load_dotenv(override=True)

# Retrieve database connection variables
db_user = os.getenv("DB_USER", "").strip().strip('"').strip("'")
db_password = os.getenv("DB_PASSWORD", "").strip().strip('"').strip("'")
db_host = os.getenv("DB_HOST", "").strip().strip('"').strip("'")
db_port = os.getenv("DB_PORT", "5432").strip().strip('"').strip("'")
db_name = os.getenv("DB_NAME", "postgres").strip().strip('"').strip("'")

db_password = urllib.parse.quote(db_password)
DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

# --- CONCURRENCY & ORCHESTRATION SHIELDS ---
MAX_CONCURRENT_AGENTS = 5
pool_semaphore = asyncio.Semaphore(MAX_CONCURRENT_AGENTS)
orchestrator_kick_event = asyncio.Event()

# Strong references for background tasks to prevent GC wiping them out
active_workers = set()

# Global persistent SQLite connection
sqlite_conn: aiosqlite.Connection = None

# --- DATABASE UTILS ---
async def init_database():
    await sqlite_conn.execute("PRAGMA journal_mode=WAL;")
    
    await sqlite_conn.execute("CREATE TABLE IF NOT EXISTS pr_mappings (pr_number INTEGER PRIMARY KEY, thread_id TEXT NOT NULL)")
    await sqlite_conn.execute("CREATE TABLE IF NOT EXISTS workflow_state (thread_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL)")
    
    await sqlite_conn.execute("""
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
    await sqlite_conn.commit()

async def update_workflow_state(thread_id: str, status: str):
    await sqlite_conn.execute(
        "INSERT OR REPLACE INTO workflow_state (thread_id, status, updated_at) VALUES (?, ?, ?)",
        (thread_id, status, datetime.now(timezone.utc).isoformat())
    )
    await sqlite_conn.commit()

async def get_workflow_state(thread_id: str) -> str | None:
    async with sqlite_conn.execute("SELECT status FROM workflow_state WHERE thread_id = ?", (thread_id,)) as cursor:
        row = await cursor.fetchone()
    return row[0] if row else None

async def claim_workflow_for_resume(thread_id: str) -> bool:
    cursor = await sqlite_conn.execute(
        "UPDATE vulnerabilities SET status = 'APPROVED_READY' WHERE thread_id = ? AND status = 'WAITING_FOR_APPROVAL'",
        (thread_id,)
    )
    await sqlite_conn.execute(
        "UPDATE workflow_state SET status = 'APPROVED_READY', updated_at = ? WHERE thread_id = ? AND status = 'WAITING_FOR_HUMAN_APPROVAL'",
        (datetime.now(timezone.utc).isoformat(), thread_id)
    )
    await sqlite_conn.commit()
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
    async with sqlite_conn.execute("SELECT thread_id FROM pr_mappings WHERE pr_number = ?", (pr_number,)) as cursor:
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
            
        if "step" in message:
            global_tracker.current_step = message["step"]
        if "log" in message:
            global_tracker.add_log(message["log"])
        if message.get("type") == "QUEUE_CLEARED":
            global_tracker.clear()
            
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

# --- GLOBAL SYSTEM TRACKER ---
class SystemTracker:
    def __init__(self):
        self.current_step = "Idle"
        self.logs = []

    def add_log(self, text: str):
        time_str = datetime.now().strftime("%I:%M:%S %p")
        self.logs.append({"time": time_str, "text": text})
        if len(self.logs) > 100:
            self.logs.pop(0)
            
    def clear(self):
        self.current_step = "Idle"
        self.logs = []

global_tracker = SystemTracker()

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
    async with sqlite_conn.execute("SELECT count(*) FROM vulnerabilities WHERE status IN ('PENDING', 'APPROVED_READY', 'IN_PROGRESS', 'WAITING_FOR_APPROVAL', 'RESUMING')") as cursor:
        active_count = (await cursor.fetchone())[0]

    if active_count > 0:
        return  

    await printS("\n[SYSTEM] 🏁 All vulnerabilities processed! Calculating totals...")

    async with sqlite_conn.execute("SELECT SUM(cost), SUM(token) FROM vulnerabilities") as cursor:
        row = await cursor.fetchone()
        total_cost = row[0] or 0.0
        total_tokens = row[1] or 0

    await printS(f"[SYSTEM] 💰 Final Batch Cost: ${total_cost:.4f} ({total_tokens} tokens)")
    await printS("[SYSTEM] Executing final PSQL migration...")

    result = await migrate_sqlite_to_psql(sqlite_path=clean_path, psql_dsn=DATABASE_URL)

    if result["status"] == "success":
        await printS(f"[SYSTEM] ✅ Auto-Migration Complete: {result['message']}")
        
        await sqlite_conn.execute("DELETE FROM vulnerabilities")
        await sqlite_conn.execute("DELETE FROM pr_mappings")
        await sqlite_conn.execute("DELETE FROM workflow_state")
        await sqlite_conn.commit() 
        await sqlite_conn.execute("VACUUM")
            
        await printS("[SYSTEM] 🧹 Local queue cleared. Ready for next upload.\n" + "="*60)
    else:
        await printS(f"[CRITICAL ERROR] ❌ Auto-Migration Failed: {result['message']}")


# --- CENTRALIZED PRIORITIZED SCHEDULER ENGINE ---
async def global_queue_orchestrator():
    """
    Engine resolving the concurrency flaws using a robust polling + event architecture.
    """
    print("[ORCHESTRATOR] 🚀 Global Prioritized Orchestration Engine Active.")
    while True:
        try:
            await pool_semaphore.acquire()

            query = """
                SELECT thread_id, status, data, retry_count, cve_id, score 
                FROM vulnerabilities 
                WHERE status IN ('PENDING', 'APPROVED_READY') 
                ORDER BY (status = 'APPROVED_READY') DESC, score DESC 
                LIMIT 1
            """
            async with sqlite_conn.execute(query) as cursor:
                row = await cursor.fetchone()

            if not row:
                pool_semaphore.release()
                orchestrator_kick_event.clear()
                # Hybrid wait: sleep max 2s to catch missed event triggers safely
                try:
                    await asyncio.wait_for(orchestrator_kick_event.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    pass
                continue

            thread_id, current_status, raw_data, retry_count, cve_id, score = row
            retry_count = retry_count or 0

            next_state = IN_PROGRESS if current_status == PENDING else RESUMING
            await sqlite_conn.execute("UPDATE vulnerabilities SET status = ?, error_reason = NULL WHERE thread_id = ?", (next_state, thread_id))
            await sqlite_conn.commit()

            # Schedule task with strict retention
            if current_status == APPROVED_READY:
                task = asyncio.create_task(execute_resume_worker(thread_id, raw_data, retry_count, cve_id, score))
            else:
                task = asyncio.create_task(execute_fresh_worker(thread_id, raw_data, retry_count, cve_id, score))
            
            active_workers.add(task)
            task.add_done_callback(active_workers.discard)

        except Exception as e:
            print(f"[CRITICAL ERROR] Core Orchestration Loop encountered exception: {str(e)}")
            await asyncio.sleep(2)


# --- REFACTORED WORKERS ---
async def execute_fresh_worker(thread_id: str, raw_data: str, retry_count: int, cve_id: str, score: float):
    print(f"\n[WORKER] ⚡ Starting fresh remediation for: {thread_id} (Attempt {retry_count + 1}/3)")
    await manager.broadcast({
        "thread_id": thread_id, "vuln_id": cve_id, "score": score, "status": "IN_PROGRESS",
        "log": f"[QUEUE] ⚡ Initializing remediation sequence for {cve_id or thread_id}..."
    })

    try:
        task_data = json.loads(raw_data)
        initial_state = {
            "issue_description": str(task_data),
            "repo_owner": os.getenv("DEFAULT_REPO_OWNER", "Rahul-Data-Scientist"),
            "repo_name": os.getenv("DEFAULT_REPO_NAME", "vulnerability-remediation"),
            "messages": []
        }
        
        config = {"configurable": {"thread_id": thread_id}}
        await update_workflow_state(thread_id, IN_PROGRESS)
        
        async with AsyncSqliteSaver.from_conn_string(clean_path) as checkpointer:
            remediation_graph = await build_graph(checkpointer=checkpointer)
            
            async for event in remediation_graph.astream(initial_state, config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools": continue
                    
                    if node_name == "__interrupt__":
                        await manager.broadcast({
                            "type": "ACTION_REQUIRED", "thread_id": thread_id, "node": "wait_for_human_approval",
                            "status": "WAITING_FOR_APPROVAL", "log": "[STANDBY] 💤 Agent entered sleep mode. Awaiting human review..."
                        })
                        
                        await update_workflow_state(thread_id, WAITING_FOR_HUMAN_APPROVAL)
                        await sqlite_conn.execute("UPDATE vulnerabilities SET status = 'WAITING_FOR_APPROVAL' WHERE thread_id = ?", (thread_id,))
                        await sqlite_conn.commit()
                        
                        pool_semaphore.release()
                        orchestrator_kick_event.set()
                        return 

                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Executing {node_name}...")
                    await manager.broadcast({"thread_id": thread_id, "node": node_name, "log": log_msg})

            final_state = await remediation_graph.aget_state(config)
            values = final_state.values
            
            cost = values.get("total_cost", 0.0)
            token = values.get("input_tokens", 0) + values.get("output_tokens", 0)
            start_time = values.get("start_time")
            end_time = values.get("end_time")
            time_taken = values.get("active_execution_time", 0.0)
            agent_succeeded = values.get("ci_status") == "success" 

            if agent_succeeded:
                await sqlite_conn.execute(
                    "UPDATE vulnerabilities SET status = 'RESOLVED', resolved = TRUE, cost = ?, token = ?, start_time = ?, end_time = ?, time_taken = ? WHERE thread_id = ?", 
                    (cost, token, start_time, end_time, time_taken, thread_id)
                )
                await sqlite_conn.commit()
                await update_workflow_state(thread_id, COMPLETED)
                await manager.broadcast({"thread_id": thread_id, "status": "RESOLVED", "log": f"[SYSTEM] 🎉 {thread_id} Resolved."})
            else:
                await sqlite_conn.execute(
                    "UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, cost = ?, token = ?, start_time = ?, end_time = ?, time_taken = ?, error_reason = 'Agent failed to resolve after self-healing' WHERE thread_id = ?", 
                    (cost, token, start_time, end_time, time_taken, thread_id)
                )
                await sqlite_conn.commit()
                await update_workflow_state(thread_id, FAILED)
                await manager.broadcast({"thread_id": thread_id, "status": "FAILED", "log": f"[CRITICAL ERROR] ❌ {thread_id} failed."})
            
    except Exception as e:
        error_msg = str(e)
        if retry_count < 2:
            new_count = retry_count + 1
            await sqlite_conn.execute("UPDATE vulnerabilities SET status = 'PENDING', retry_count = ?, error_reason = ? WHERE thread_id = ?", 
                                (new_count, f"Attempt {retry_count + 1} Failed: {error_msg}", thread_id))
            await sqlite_conn.commit()
        else:
            await sqlite_conn.execute("UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = ? WHERE thread_id = ?", 
                                (f"Permanent Failure: {error_msg}", thread_id))
            await sqlite_conn.commit()
            await update_workflow_state(thread_id, FAILED)
    finally:
        pool_semaphore.release()
        orchestrator_kick_event.set()
        await check_and_run_final_migration()


async def execute_resume_worker(thread_id: str, raw_data: str, retry_count: int, cve_id: str, score: float):
    print(f"\n[WORKER] 🔄 Resuming human-approved remediation pipeline for: {thread_id}")
    config = {"configurable": {"thread_id": thread_id}}
    try:
        await update_workflow_state(thread_id, RESUMING)
        await manager.broadcast({
            "thread_id": thread_id, "status": "IN_PROGRESS", 
            "log": "[WEBHOOK] 🚀 GitHub Review received. Resuming execution chain with high priority..."
        })
        
        async with AsyncSqliteSaver.from_conn_string(clean_path) as checkpointer:
            github_workflow_agent = await build_graph(checkpointer=checkpointer)
            
            async for event in github_workflow_agent.astream(Command(resume=True), config=config, stream_mode="updates"):
                for node_name, state_updates in event.items():
                    if node_name == "github_tools" or node_name == "wait_for_human_approval": continue
                        
                    if node_name == "__interrupt__":
                        await manager.broadcast({
                            "type": "ACTION_REQUIRED", "thread_id": thread_id, "node": "wait_for_human_approval",
                            "status": "WAITING_FOR_APPROVAL", "log": "[STANDBY] 💤 Re-entering loop interrupt. Awaiting new review..."
                        })
                        await update_workflow_state(thread_id, WAITING_FOR_HUMAN_APPROVAL)
                        await sqlite_conn.execute("UPDATE vulnerabilities SET status = 'WAITING_FOR_APPROVAL' WHERE thread_id = ?", (thread_id,))
                        await sqlite_conn.commit()
                        
                        pool_semaphore.release()
                        orchestrator_kick_event.set()
                        return 

                    log_msg = NODE_LOG_MAP.get(node_name, f"[SYSTEM] Resuming {node_name}...")
                    await manager.broadcast({"thread_id": thread_id, "node": node_name, "log": log_msg})

            final_state = await github_workflow_agent.aget_state(config)
            values = final_state.values
            
            cost = values.get("total_cost", 0.0)
            token = values.get("input_tokens", 0) + values.get("output_tokens", 0)
            start_time = values.get("start_time")
            end_time = values.get("end_time")
            time_taken = values.get("active_execution_time", 0.0)
            
            await sqlite_conn.execute(
                "UPDATE vulnerabilities SET status = 'RESOLVED', resolved = TRUE, cost = ?, token = ?, start_time = ?, end_time = ?, time_taken = ? WHERE thread_id = ?", 
                (cost, token, start_time, end_time, time_taken, thread_id)
            )
            await sqlite_conn.commit()
                
            await update_workflow_state(thread_id, COMPLETED)
            await manager.broadcast({"thread_id": thread_id, "status": "COMPLETED", "log": "[SYSTEM] ✅ Human approval processed. Workflow complete."})

    except Exception as e:
        error_msg = str(e)
        await sqlite_conn.execute("UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = ? WHERE thread_id = ?", 
                            (f"Resume Permanent Failure: {error_msg}", thread_id))
        await sqlite_conn.commit()
        await update_workflow_state(thread_id, FAILED)
    finally:
        pool_semaphore.release()
        orchestrator_kick_event.set()
        await check_and_run_final_migration()


# --- FASTAPI APP & LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global sqlite_conn
    print("[SYSTEM] Booting Application Services...")
    
    app.state.pool = await asyncpg.create_pool(DATABASE_URL)
    sqlite_conn = await aiosqlite.connect(clean_path, timeout=30.0)
    
    await init_database()
    
    # Reset tasks that died unexpectedly during previous app execution
    await sqlite_conn.execute(
        "UPDATE vulnerabilities SET status = 'FAILED', resolved = FALSE, error_reason = 'Server crashed or restarted during active execution' "
        "WHERE status = 'IN_PROGRESS' OR status = 'RESUMING'"
    )
    await sqlite_conn.execute("UPDATE workflow_state SET status = 'FAILED' WHERE status = 'IN_PROGRESS' OR status = 'RESUMING'")
    await sqlite_conn.commit()
    
    print("[SYSTEM] Booting Security Remediation Core Agent Environment...")
    try:
        await initialize_agent_components()
    except Exception as e:
        print(f"[CRITICAL WARNING] Failed to initialize agents on boot. Check dependencies: {e}")
    
    # Initialize Orchestrator loop inside the application's ASGI event ecosystem
    orchestrator_task = asyncio.create_task(global_queue_orchestrator())
    active_workers.add(orchestrator_task)
    
    print("[SYSTEM] Prioritized Worker Pool initialized and watching. Awaiting triggers.\n" + "="*60)
    yield
    
    await sqlite_conn.close()
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
async def handle_csv_upload(files: list[UploadFile] = File(...)):
    try:
        await printS("-----Started CSV Upload Pipeline-----")
        
        # Security: Isolate batches to prevent concurrent user file wiping & use safe filenames
        batch_id = uuid.uuid4().hex
        UPLOAD_DIR = PROJECT_ROOT / "raw_scanner_outputs" / batch_id
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                    
        for file in files:
            safe_filename = os.path.basename(file.filename)
            if not safe_filename: 
                safe_filename = f"upload_{uuid.uuid4().hex[:6]}.csv"
                
            file_path = UPLOAD_DIR / safe_filename
            async with aiofiles.open(file_path, 'wb') as out_file:
                while content := await file.read(1024 * 1024):  
                    await out_file.write(content)
        
        await manager.broadcast({"step": "Parsing", "log": f"[SYSTEM] 📥 Upload received: {len(files)} files. Initiating pipeline..."})
        
        parsing_graph = build_parsing_graph()
        # Assumes parsing graph takes the directory as an input.
        await parsing_graph.ainvoke({"folder_path": str(UPLOAD_DIR), "parse_code_file_path": "agents/generated_parser_func.py"})
        
        await manager.broadcast({"step": "Parsing", "log": f"[SYSTEM] Parsing Done"})
        
        
        await manager.broadcast({"step": "Normalization", "log": f"[SYSTEM] Normalization"})
        
        normalizer = build_normalization_graph()
        await normalizer.ainvoke({"folder_path": "parsed_csvs"})
        
        await manager.broadcast({"step": "Normalization", "log": f"[SYSTEM] Normalization Done"})
        
        
        await manager.broadcast({"step": "Enrichment", "log": f"[SYSTEM] Enrichment Started"})
        
        
        WORKING_CSV_PATH = Path(__file__).resolve().parent / "normalized_output" / "working.csv"
        await run_remediation_pipeline(WORKING_CSV_PATH)
        await asset_lookup_graph.ainvoke({"working_csv": str(WORKING_CSV_PATH), "status": "running", "error": None, "new_count": 0, "existing_count": 0})
        
        await manager.broadcast({"step": "Enrichment", "log": f"[SYSTEM] Enrichment Done"})
        
        
        await manager.broadcast({"step": "Prioritization", "log": f"[SYSTEM] Prioritization Started"})
        
        
        await run_prioritization_agent(str(WORKING_CSV_PATH))
        
        await manager.broadcast({"step": "Prioritization", "log": f"[SYSTEM] Prioritization Done"})
        
        
        df = await asyncio.to_thread(pd.read_csv, str(WORKING_CSV_PATH))
        df = df.where(pd.notnull(df), None)
        df.drop_duplicates(subset=["vuln_id","asset_id"],inplace=True)
        tasks = df.to_dict(orient="records")
        
        if not tasks:
            return {"status": "success", "queued_items": 0}

        tasks.sort(key=lambda x: float(x.get("priority_score") or x.get("score") or 0.0), reverse=True)
        BATCH_LIMIT = 10
        top_tasks = tasks[:BATCH_LIMIT]
            
        for task in tasks:
            if "thread_id" not in task or not task["thread_id"]:
                task["thread_id"] = f"vuln-{uuid.uuid4().hex[:10]}"
            
            score = float(task.get("priority_score", task.get("score", 5.0)))
            asset_id = task.get("asset_id","Unknown")
            cve_id = task.get("vuln_id", task.get("cve_id", asset_id))
            
            task["thread_id"] = task["thread_id"]
            task["vuln_id"] = cve_id
            task["score"] = score
            
            await sqlite_conn.execute(
                "INSERT OR IGNORE INTO vulnerabilities (thread_id, asset_id, cve_id, score, status, data) VALUES (?, ?, ?, ?, ?,?)",
                (task["thread_id"], asset_id ,cve_id, score, PENDING, json.dumps(task))
            )
        await sqlite_conn.commit()
        
        await manager.broadcast({
            "type": "NEW_BATCH", "step": "Remediation", "tasks": top_tasks,
            "log": f"[SYSTEM] 🚀 Loaded top {len(top_tasks)} priority items to the Autonomous Registry..."
        })

        orchestrator_kick_event.set()
        return {"status": "success", "queued_items": len(top_tasks)}

    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/github-webhook")
async def github_webhook_listener(request: Request):
    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event")
    should_continue = False

    if event_type == "pull_request" and payload.get("action") == "closed":
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
            return {"status": "ignored", "reason": "already_resuming_or_processed"}

        await manager.broadcast({
            "thread_id": thread_id, "status": "PENDING", 
            "log": "[WEBHOOK] 🔄 Peer Review detected on GitHub. Adding task back into prioritized queue loop..."
        })

        orchestrator_kick_event.set()
        return {"status": "accepted"}

    return {"status": "ignored"}

@app.get("/api/v1/status/{thread_id}")
async def get_vuln_status(thread_id: str):
    async with sqlite_conn.execute("SELECT status FROM vulnerabilities WHERE thread_id = ?", (thread_id,)) as cursor:
        row = await cursor.fetchone()
        if row: return {"thread_id": thread_id, "status": row[0]}
    return {"status": "NOT_FOUND"}

@app.get("/api/v1/system-state")
async def get_system_state():
    async with sqlite_conn.execute(
        "SELECT thread_id, status FROM vulnerabilities WHERE status IN ('IN_PROGRESS', 'RESUMING', 'WAITING_FOR_APPROVAL') LIMIT 1"
    ) as cursor:
        active_row = await cursor.fetchone()

    async with sqlite_conn.execute("SELECT count(*) FROM vulnerabilities WHERE status = 'PENDING'") as cursor:
        pending = (await cursor.fetchone())[0]
    async with sqlite_conn.execute("SELECT count(*) FROM vulnerabilities WHERE status IN ('RESOLVED', 'FAILED')") as cursor:
        finished = (await cursor.fetchone())[0]
    async with sqlite_conn.execute("SELECT count(*) FROM vulnerabilities") as cursor:
        total = (await cursor.fetchone())[0]

    async with sqlite_conn.execute("SELECT thread_id, cve_id, score, status, asset_id FROM vulnerabilities") as cursor:
        all_vulns = await cursor.fetchall()

    vulns = [{"thread_id": v[0], "vuln_id": v[1], "score": v[2], "status": v[3], "asset_id": v[4]} for v in all_vulns]
    step = global_tracker.current_step
    return {
        "active_task": {"thread_id": active_row[0], "status": active_row[1]} if active_row else None,
        "metrics": {"pending": pending, "finished": finished, "total": total},
        "vulnerabilities": vulns,
        "current_step": step,
        "recent_logs": global_tracker.logs
    }
        
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
                FROM vulnerabilities_history 
            """)
            
            total_solved = int(kpi_row['total_solved'] or 0)
            pending_vulns = int(kpi_row['pending_vulns'] or 0)
            total_vulns = int(kpi_row['total_vulns'] or 0)
            success_rate = round((total_solved / total_vulns) * 100, 1) if total_vulns > 0 else 0

            severities_rows = await conn.fetch("SELECT score FROM vulnerabilities_history ")
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

            tokens_data = [{"time": r['time'], "tokens": r['tokens']} for r in await conn.fetch("""
                SELECT TO_CHAR(DATE_TRUNC('hour', start_time), 'Mon DD, HH:MI AM') as time, SUM(token) as tokens
                FROM vulnerabilities_history WHERE start_time IS NOT NULL
                GROUP BY DATE_TRUNC('hour', start_time) ORDER BY DATE_TRUNC('hour', start_time) ASC
            """)]
            if not tokens_data: tokens_data = [{"time": "No Data", "tokens": 0}]

            recent_activity = [{
                "id": r['cve_id'] or r['thread_id'], "name": f"vulnerabilities on {r['asset_id']}",
                "severity": get_severity_label_and_color(float(r['score']))[0],
                "status": "Resolved" if r['resolved'] else "Unresolved",
                "time": (r['end_time'] if r['resolved'] else r['start_time']).strftime('%H:%M %p') if (r['end_time'] or r['start_time']) else "N/A"
            } for r in await conn.fetch("SELECT thread_id, cve_id, asset_id, score, resolved, end_time, start_time FROM vulnerabilities_history ORDER BY COALESCE(end_time, start_time) DESC LIMIT 10")]

            return {
                "kpis": {
                    "avg_cost": float(kpi_row['raw_avg_cost'] or 0), "avg_mttr": format_mttr(kpi_row['raw_avg_mttr']),
                    "total_vulns": total_vulns, "total_solved": total_solved, "total_tokens": int(kpi_row['total_tokens'])/max(total_solved, 1),
                    "success_rate": success_rate, "pending_vulns": pending_vulns
                },
                "tokens": tokens_data, "severities": severities_data, "recent_activity": recent_activity
            }
    except Exception as e:
        return {"error": str(e)}

def format_mttr(time_taken) -> str:
    if not time_taken: return "0m 0s"
    total_seconds = int(time_taken.total_seconds()) if isinstance(time_taken, timedelta) else int(time_taken)
    minutes, seconds = divmod(total_seconds, 60)
    return f"{minutes}m {seconds}s"

def get_severity_label_and_color(score: float): 
    if score is None: return "Low", "#3B82F6"
    if score >= 9.0: return "Critical", "#EF4444"
    if score >= 7.0: return "High", "#F97316"
    if score >= 4.0: return "Medium", "#EAB308"
    return "Low", "#3B82F6"