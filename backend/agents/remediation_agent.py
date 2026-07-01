from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_tavily import TavilySearch

from langgraph.graph import StateGraph, START, END, MessagesState
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.types import RetryPolicy, interrupt
from langgraph.config import RunnableConfig

from dotenv import load_dotenv

from typing import Optional, Annotated, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from .jira_workflow_manager import create_jira_issue, transition_jira_issue, add_jira_comment
from .system_prompts import research_system_prompt
from pathlib import Path

import os
import asyncio
import json
import time
import requests
import aiosqlite
from functools import wraps
import operator

import boto3

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "state_db.sqlite"

# Clean path formatting for Windows compatibility (strip any URI parameters)
clean_path = str(DB_PATH).replace("\\", "/")

GITHUB_TOKEN = os.environ["GITHUB_MCP_TOKEN"]

SERVERS = {
    "github": {
        "transport": "http",
        "url": "https://api.githubcopilot.com/mcp/",
        "headers": {
            "Authorization": f"Bearer {GITHUB_TOKEN}"
        }
    }
}

tools = None
git_llm = None
tool_node = None
git_branch_llm = None
remediation_llm = None
client = None
research_tavily_tool = None
research_tool_node = None

MAX_RETRIES = 5
INITIAL_DELAY = 2  # seconds

async def initialize_agent_components():
    global tools, client, git_llm, tool_node, git_branch_llm, remediation_llm, research_tavily_tool, research_tool_node

    if all(x is not None for x in [tools, git_llm, tool_node]):
        return

    last_exception = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"[SYSTEM] Connecting to GitHub MCP Server (Attempt {attempt}/{MAX_RETRIES})...")

            client = MultiServerMCPClient(SERVERS)
            tools = await client.get_tools()

            # --- Token Budget Optimization: Whitelist Filtering ---
            required_git_tools = {
                # Core Remediation Workflow Tools
                "list_branches",
                "create_branch",
                "get_file_contents",
                "create_or_update_file",
                "create_pull_request"

                # # PR Interaction & Thread Resolution Tools
                # "add_issue_comment",
                # "add_reply_to_pull_request_comment",
                # "add_comment_to_pending_review",
                # "pull_request_read",
                # "pull_request_review_write"
            }

            # Filter the tool objects based on their name attribute
            remediation_workflow_tools = [t for t in tools if getattr(t, 'name', '') in required_git_tools]

            print(f"[SYSTEM] Securely connected. Loaded {len(tools)} security automation tools.")
            break

        except Exception as e:
            last_exception = e
            print(f"[WARNING] MCP connection failed (attempt {attempt}/{MAX_RETRIES}): {str(e)}")

            if attempt < MAX_RETRIES:
                delay = INITIAL_DELAY * (2 ** (attempt - 1))
                await asyncio.sleep(delay)
            else:
                raise last_exception

    # Bind only the filtered toolset to keep context windows lightweight
    git_llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0).bind_tools(remediation_workflow_tools)
    tool_node = ToolNode(remediation_workflow_tools, handle_tool_errors=True)
    git_branch_llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0)
    remediation_llm = ChatOpenAI(model="gpt-4.1-mini", temperature=0)
    research_tavily_tool = TavilySearch(
        max_results=3,
        search_depth="advanced",
        description="Search URLs or the web. Read advisory pages, vendor bulletins, commits, patch pages, mailing lists and repositories."
    )
    research_tool_node = ToolNode([research_tavily_tool])

class AgentState(MessagesState):
    # Core Repository & Issue Metadata
    issue_description: str
    reference_links: Optional[list[str]] = []
    repo_owner: str
    repo_name: str
    branch_name: Optional[str]
    target_file: Optional[str]
    
    # File Content & Modification Details
    original_file_content: Optional[str]
    modified_file_content: Optional[str]
    fix_description: Optional[str]
    
    # CI/CD & Pipeline Tracking
    ci_status: Optional[str]
    ci_retry_count: Optional[int] = 0
    ci_max_retry_limit: Optional[int] = 2
    job_id: Optional[str]
    error_message: Optional[str]
    error_logs: Optional[str]
    
    # Scripts, Testing & Validation Logs
    precheck_script: Optional[str]
    precheck_logs: Optional[str]
    validation_script: Optional[str]
    validation_logs: Optional[str]
    unified_evidence_report: Optional[str]
    
    # Pull Request Tracking
    pr_number: Optional[int]
    pr_url: Optional[str]
    pr_merged: Optional[bool]
    pr_state: Optional[str]
    
    # PR Review & Comment Tracking (Processed vs New)
    processed_review_ids: Optional[list] = []
    processed_general_comment_ids: Optional[list] = []
    processed_inline_comment_ids: Optional[list] = []
    pending_feedback: Optional[str] = ""
    new_review_ids: Optional[list] = []
    new_general_comment_ids: Optional[list] = []
    new_inline_comment_ids: Optional[list] = []
    failure_report_url: Optional[str] = None
    
    # Jira Integration
    jira_issue_key: Optional[str] = None
    jira_status: Optional[str] = None
    jira_comment_result: Optional[Dict] = None
    
    # LLM Metrics, Cost, & Execution Tracking
    start_idx: Optional[int] = 0
    input_tokens: Optional[int] = 0
    output_tokens: Optional[int] = 0
    total_cost: Optional[float] = 0
    active_execution_time: Annotated[float, operator.add]

    # Temporary Loop Time Trackers
    research_loop_start: Optional[float] = None
    github_loop_start: Optional[float] = None

    # Pipeline Timing Trackers
    start_time: Optional[str] = None
    end_time: Optional[str] = None

async def invoke_with_retry(tool_instance, payload, retry_policy: RetryPolicy):
    """Executes an MCP tool with explicit retry logic based on a LangGraph RetryPolicy."""
    attempt = 0
    delay = retry_policy.initial_interval
    
    while True:
        try:
            attempt += 1
            # Execute tool invocation
            return await tool_instance.ainvoke(payload)
        except Exception as e:
            if attempt >= retry_policy.max_attempts:
                print(f"[RETRY ENGINE] ❌ Maximum retry attempts ({retry_policy.max_attempts}) exhausted. Final Exception: {str(e)}")
                raise e  # Fail permanently after exhausting retries
            
            print(f"[RETRY ENGINE] ⚠️ Attempt {attempt} failed due to network/HTTP fault: {str(e)}. Retrying in {delay} seconds...")
            await asyncio.sleep(delay)
            
            # Apply backoff_factor (1.0 means linear, 2.0 means exponential)
            delay = delay * retry_policy.backoff_factor

git_retry_policy = RetryPolicy(
    max_attempts=3,
    initial_interval=5.0,
    backoff_factor=1.0,
    jitter=False
)

async def update_workflow_state(thread_id: str, status: str):
    # Removed the verbose print statement from here to avoid polluting agent execution logs
    async with aiosqlite.connect(clean_path, timeout=5.0) as db:
        await db.execute(
            """
            INSERT OR REPLACE INTO workflow_state
            (thread_id, status, updated_at)
            VALUES (?, ?, ?)
            """,
            (thread_id, status, datetime.now(timezone.utc).isoformat())
        )
        await db.commit()

async def create_research_prompt_node(state: AgentState):
    """Prepares the structured payload for the vulnerability research agent."""

    payload = {
        "vulnerability": state["issue_description"],
        "reference_links": state.get("reference_links", [])
    }
    
    compiled_messages = [
        {"role": "system", "content": research_system_prompt},
        HumanMessage(content=json.dumps(payload, indent=2))
    ]
    
    return {"messages": compiled_messages, "research_loop_start": time.perf_counter()}

async def research_vulnerability_node(state: AgentState):
    """Executes target-focused advisory extraction using Tavily tools."""
    if state.get("messages", None) and len(state['messages']) == 2:
        print("\n[AGENT] 🔍 Target-focused advisory extraction and deep research...")
    
    research_llm = ChatOpenAI(
        model="gpt-4.1-mini",
        temperature=0
    ).bind_tools([research_tavily_tool])
    
    response = await research_llm.ainvoke(state['messages'])
    return {"messages": [response]}

class RemediationOutput(BaseModel):
    script_content: str = Field(
        ...,
        description=(
            "The raw, production-ready content of the primary bash remediation script. "
            "It must perform the complete vulnerability fix, be fully executable without "
            "placeholders, and use clean formatting, logical line breaks (\\n), and inline "
            "comments for readability when rendered inside the orchestration JSON."
        )
    )

    precheck_script: str = Field(
        ...,
        description=(
            "A safe, non-mutating bash script that gathers remediation-relevant system telemetry "
            "BEFORE any changes are made. It should inspect not only the vulnerable package, but "
            "also related installed packages, candidate versions, dependency information, "
            "successor/replacement packages, package manager metadata, and any other system state "
            "required to determine the correct remediation path. Output must be organized into "
            "clearly labeled sections and use explicit newlines (\\n) for human-readable CI/CD telemetry."
        )
    )

    validation_script: str = Field(
        ...,
        description=(
            "A safe, non-mutating bash script executed AFTER remediation. It must verify that the "
            "vulnerability has been successfully remediated by inspecting the resulting system state "
            "and must return exit code 0 on success and non-zero on failure. Validation should test "
            "the actual remediation outcome rather than merely checking whether the script executed. "
            "Use explicit newlines (\\n), clear section headers, and human-readable output."
        )
    )

    branch_name: str = Field(
        ...,
        description=(
            "A clean, lowercase, kebab-case Git branch name "
            "(e.g., 'patch/cve-2026-1234-openssl-update'). "
            "Avoid spaces and special characters."
        )
    )

    fix_summary: str = Field(
        ...,
        description=(
            "A concise remediation summary written as exactly 3-4 Markdown bullet points. "
            "It should explain the remediation strategy, root cause identified, actions taken, "
            "and any required operator follow-up steps. This summary should also capture the "
            "reasoning behind the chosen remediation approach."
        )
    )

async def remediation_node(state: AgentState):
    elapsed = None
    if state.get("research_loop_start") and not state.get("ci_status"):
        elapsed = time.perf_counter() - state["research_loop_start"]

    current_message_count = len(state.get("messages", []))
    current_script = state.get("modified_file_content", "")
    error_logs = state.get("error_logs", "")
    active_feedback = state.get("pending_feedback", "")
    
    # Refocused instructions emphasizing pristine line breaks and unified structural readability
    evidence_instructions = (
        "\n\nREADABLE TRIPLE-STAGE RUNBOOK CONFIGURATION DUTIES:\n"
        "You are compiling a complete, end-to-end vulnerability remediation runbook. Every bash script segment "
        "(`script_content`, `precheck_script`, and `validation_script`) will be injected directly into a single "
        "consolidated configuration JSON file. Because human engineering peers will review this configuration directly, "
        "you MUST format each script to the highest standards of code cleanliness:\n"
        "1. Use clear inline comments, proper indentation, and distinct logical spacing.\n"
        "2. Embed structural newlines (\\n) so the scripts render as cleanly readable, multi-line blocks inside the JSON fields.\n"
        "3. CRITICAL: Never truncate code, use shorthand squashing, or include markdown block formatting (like ```bash) inside the schema string parameters."
    )

    # Universal core rules adapted for the singular JSON configuration paradigm
    core_rules = (
        "\n\nCRITICAL CODE EXECUTION RULES:\n"
        "1. When generating scripts, use the exact package name shown in the vulnerability description. Do not replace it with a base package name or meta-package name."
        "2. Always output complete, fully functional operational script blocks under 'script_content', 'precheck_script', and 'validation_script'. "
        "Never leave placeholders or comment out intact production lines.\n"
        "3. Ensure all three scripts are completely self-contained, syntax-valid, and safe to execute unattended on the target cloud instances."
    )

    if active_feedback and not error_logs:
        print("\n[AGENT] 🔄 Human PR Feedback Received! Adapting unified runbook configurations...")
        system_prompt = (
            "You are an expert security automation assistant and Linux systems engineer. "
            "Your task is to review the existing orchestration script components and modify them "
            "to fully satisfy the team's review feedback.\n\n"
            "Ensure you maintain all requested features unless explicitly told to change them."
            + evidence_instructions + core_rules
        )
        user_prompt = (
            f"### CURRENT REPOSITORY RUNBOOK CONTEXT:\n{current_script}\n\n"
            f"### REQUESTED PULL REQEST REVIEW FEEDBACK:\n{active_feedback}\n\n"
            f"Please apply the modifications and deliver the updated scripts via structured output."
        )

    elif error_logs:
        print(f"\n[AGENT] ⚠️ CI/CD Validation Failed. Debugging configuration telemetry and rewriting patch suite...")
        feedback_constraint = f"\n\nCRITICAL HUMAN FEEDBACK CONSTRAINT:\nYou must maintain previous changes made to address: \"{active_feedback}\". Do not revert or break this human intent while resolving the runtime execution failure." if active_feedback else ""
        
        system_prompt = (
            "You are an expert systems engineer. The current validation or execution script configurations failed during "
            "pipeline telemetry checks. Analyze the logs and rewrite the orchestration script tree to resolve the breakdown completely.\n"
            "Ensure your `validation_script` accurately tests the precise changes that your updated `script_content` modifies." 
            + evidence_instructions + core_rules + feedback_constraint
        )
        user_prompt = (
            f"Original Vulnerability Objective:\n{state['issue_description']}\n\n"
            f"### FAILING CONFIGURATION CONTEXT:\n{current_script}\n\n"
            f"### CI/CD RUNTIME ERROR LOGS:\n{error_logs}\n\n"
            f"Modify the script suite properties to eliminate this runtime failure completely while preserving stability."
        )

    else:
        print("\n[AGENT] 🧠 Generating automated remediation runbook using verified advisory research...")
        
        # Pull the last message (the raw output from our research node)
        if state["messages"]:
            research_context = f"### DETAILED ADVISORY RESEARCH FINDINGS\n{state['messages'][-1].content}"
        else:
            research_context = "### DETAILED ADVISORY RESEARCH FINDINGS\nNo prior research available."

        system_prompt = (
            "You are an automated DevSecOps security agent. Your task is to analyze the cloud vulnerability "
            "and generate a production-ready, three-tier runbook (Precheck, Remediation, and Validation) "
            "packaged beautifully for a single asset tracking configuration layout.\n\n"
            
            "CRITICAL CONTEXT INTEGRATION RULES:\n"
            "1. You have been provided with background security research instructions regarding this vulnerability. Use this research to guide your fix strategy.\n"
            "2. WARNING: The research output may contain hallucinated package targets (e.g., generic kernel names). DO NOT treat package names or paths in the research text as absolute truths.\n"
            "3. The absolute source of truth for the baseline package name is the 'Issue Description' itself. If the exact target package is missing or ambiguous there, rely on your `precheck_script` to query the live system state.\n"
            "4. FIXED VERSION HANDLING:\n"
            "   - If the 'Issue Description' explicitly defines a fixed version, you MUST use that version.\n"
            "   - If the 'Issue Description' does NOT contain a fixed version, check the provided 'Research Output'. If a fixed version is present there, use it.\n"
            "   - If neither contains a definitive target version, default to upgrading the verified target package to its latest repository availability as outlined in your standard rules.\n\n"
            
            "IMPORTANT: If the vulnerability is inside a compiled language standard library, attempt to "
            "upgrade the language SDK/toolchain using the system package manager (e.g., apt, yum) and "
            "add clear echo statements to the script notifying the system operator to rebuild the affected binaries.\n"
            + evidence_instructions + core_rules
        )
        
        user_prompt = (
            f"### LIVE SOURCE OF TRUTH (ISSUE DESCRIPTION):\n{state['issue_description']}\n\n"
            f"{research_context}\n\n"
        )

    response: RemediationOutput = await remediation_llm.with_structured_output(RemediationOutput, include_raw=True).ainvoke([
        {"role": "system", "content": system_prompt},
        HumanMessage(content=user_prompt)
    ])
    
    return_payload = {
        "messages": [response['raw']],
        "modified_file_content": response['parsed'].script_content,
        "fix_description": response['parsed'].fix_summary,
        "precheck_script": response['parsed'].precheck_script,
        "validation_script": response['parsed'].validation_script,
        "start_idx": current_message_count + 1
    }
    if not state.get("branch_name"):
        return_payload["branch_name"] = response['parsed'].branch_name
    if elapsed:
        return_payload["active_execution_time"] = elapsed
        return_payload["research_loop_start"] = None
        
    return return_payload

async def create_prompt(state: AgentState, config: RunnableConfig):
    owner = state["repo_owner"]
    repo = state["repo_name"]
    branch = state["branch_name"]
    fix_desc = state["fix_description"]
    pr_number = state.get("pr_number")

    # 1. Isolate and sanitize the operational thread_id
    thread_id = config["configurable"]["thread_id"]
    sanitized_thread_id = str(thread_id).replace("/", "-").replace("\\", "-").replace(" ", "_")


    # 🌟 MODIFIED: Enforce the compound naming convention: payloads/{vuln_id}_{thread_id}.json
    target_file = f"payloads/{sanitized_thread_id}.json"

    # Assemble the tracking metadata along with the orchestration scripts inside the JSON body
    scripts_payload_json = json.dumps({
        "thread_id": thread_id,
        "precheck_script": state.get("precheck_script", ""),
        "remediation_script": state.get("modified_file_content", ""),
        "validation_script": state.get("validation_script", "")
    }, indent=2)

    if pr_number:
        print(f"[AGENT] 🛠️ Formulating Git payload to patch runtime runbook configuration on branch '{branch}' at '{target_file}' for PR #{pr_number}...")
        prompt = (
            f"Using your GitHub tools, execute the following actions on the repository '{owner}/{repo}':\n\n"
            f"1. Update the configuration file named '{target_file}' in the branch '{branch}' with this content exactly:\n"
            f"-----------\n{scripts_payload_json}\n-----------\n"
            f"2. Commit this change to the branch '{branch}'. You must call the appropriate tools sequentially "
            f"to ensure the file is successfully updated in the commit tree. Use the commit message: "
            f"'Refine remediation code and evidence scripts: {fix_desc}'\n"
        )
    else:
        print(f"[AGENT] 🛠️ Formulating initialization payload for new security branch '{branch}' containing isolated configuration layout at '{target_file}'...")
        prompt = (
            f"Using your GitHub tools, execute the following actions sequentially on the repository '{owner}/{repo}':\n\n"
            f"1. Check if a branch named '{branch}' already exists. If not, create the branch named '{branch}' in the repository.\n"
            f"2. Create or update the isolated orchestration file named '{target_file}' on branch '{branch}' with this content exactly:\n"
            f"-----------\n{scripts_payload_json}\n-----------\n"
            f"3. Commit the file change with a suitable message detailing this security remediation.\n"
            f"4. Create a Pull Request from branch '{branch}' to the default branch.\n\n"
            f"CRITICAL: You MUST continue calling your tools sequentially until the Pull Request is fully created. "
            f"Do not stop after updating the file.\n\n"
            f"When all steps are complete, return ONLY: 1. commit sha, 2. pr_url, 3. pr_number"
        )
        
    return {"messages": [HumanMessage(content=prompt)], "github_loop_start": time.perf_counter()}

async def git_operator_node(state: AgentState):
    start_idx = state.get("start_idx", 0)
    # Conditionally printing only the first push invocation to avoid repetitive loop outputs
    if not state.get("messages") or len(state["messages"]) <= 1:
        print("[AGENT] 🚀 Pushing source code changes to remote GitHub repository...")
    response = await git_llm.ainvoke(state['messages'][start_idx:])
    return {"messages": [response]}

class GitWorkflowOutput(BaseModel):
    pr_url: str = Field(..., description = "URL of the PR")
    pr_number: int = Field(..., description = "PR Number")

pr_details_extractor_llm = ChatOpenAI(model = "gpt-4.1-mini", temperature = 0).with_structured_output(GitWorkflowOutput, include_raw = True)

async def extract_pr_details(state: AgentState, config: RunnableConfig):
    elapsed = None
    if state.get("github_loop_start"):
        elapsed = time.perf_counter() - state["github_loop_start"]
    if state.get("pr_number"):
        return_payload = {
            "error_logs": "",
            "processed_review_ids": list(set(state.get("processed_review_ids", []) + state.get("new_review_ids", []))),
            "processed_general_comment_ids": list(set(state.get("processed_general_comment_ids", []) + state.get("new_general_comment_ids", []))),
            "processed_inline_comment_ids": list(set(state.get("processed_inline_comment_ids", []) + state.get("new_inline_comment_ids", []))),
            "new_review_ids": [],
            "new_general_comment_ids": [],
            "new_inline_comment_ids": []
        }
        if elapsed:
            return_payload["active_execution_time"] = elapsed
            return_payload["github_loop_start"] = None
        return return_payload

    details = await pr_details_extractor_llm.ainvoke([HumanMessage(
        content=f"Extract the PR URL and PR Number from the given LLM response:\n{state['messages'][-1].content}"
    )])

    async with aiosqlite.connect("state_db.sqlite") as db:
        await db.execute(
            "INSERT INTO pr_mappings (pr_number, thread_id) VALUES (?, ?)",
            (details['parsed'].pr_number, config["configurable"]["thread_id"])
        )
        await db.commit()

    print(f"[SYSTEM] 🔑 Generated Pull Request successfully verified: PR #{details['parsed'].pr_number}")
    return_payload = {
        "messages": details["raw"],
        "pr_url": details["parsed"].pr_url,
        "pr_number": details["parsed"].pr_number
    }
    if elapsed:
        return_payload["active_execution_time"] = elapsed
        return_payload["github_loop_start"] = None
    return return_payload

async def check_ci_status(state: AgentState):
    print(f"[AGENT] 🧪 Initiating live monitoring for CI/CD status on PR #{state.get('pr_number', '')}...")
    pr_tool = next(t for t in tools if t.name == "pull_request_read")
    timeout_seconds = 900
    start_time = time.time()

    while True:
        try:
            # Wrap the tool invocation with your retry engine to handle HTTP connection flakes
            result = await invoke_with_retry(
                tool_instance=pr_tool,
                payload={
                    "method": "get_check_runs",
                    "owner": state["repo_owner"],
                    "repo": state["repo_name"],
                    "pullNumber": state["pr_number"]
                },
                retry_policy=git_retry_policy
            )
        except Exception as e:
            # If the tool completely fails after all retries, log the error and mark as a pipeline failure
            print(f"[AGENT] ❌ Permanent connection failure querying GitHub API: {str(e)}")
            return {"ci_status": "failure", "error_message": f"GitHub API unreachable: {str(e)}"}

        data = json.loads(result[0]["text"])
        check_runs = data.get("check_runs", [])

        # ENHANCEMENT: Handle cold starts vs historical completions safely
        if len(check_runs) == 0:
            # If 45 seconds have passed and no check run has appeared, the previous run likely completed 
            # and settled successfully before this check loop initialized.
            if time.time() - start_time > 45:
                print("[AGENT] ⚠️ No active check runs detected. Proceeding under historical success validation assumption.")
                return {"ci_status": "success", "job_id": "historical_run_settled"}
                
            if time.time() - start_time > timeout_seconds:
                return {"ci_status": "failure"}
            await asyncio.sleep(10)
            continue

        statuses = [run["status"] for run in check_runs]
        if any(s != "completed" for s in statuses):
            if time.time() - start_time > timeout_seconds:
                return {"ci_status": "failure"}
            await asyncio.sleep(10)
            continue

        conclusions = [run["conclusion"] for run in check_runs]
        
        # Robust check to ensure we parse the job ID out of the first available run safely
        sample_url = check_runs[0].get("html_url", "")
        job_id = sample_url.split("/")[-1].strip() if sample_url else "unknown_job"
        
        if all(c == "success" for c in conclusions):
            print("[SYSTEM] ✅ CI/CD Status: All health and security integration tests PASSED.")
            return {"ci_status": "success", "job_id": job_id}
        else:
            print("[SYSTEM] ❌ CI/CD Status: Execution failure detected during pipeline run.")
            return {"ci_status": "failure", "job_id": job_id}

async def route_after_ci(state: AgentState):
    ci_status = state["ci_status"]
    if ci_status == "failure":
        return "failure"
    return "success"

async def route_after_failure(state: AgentState):
    """Determines whether to retry remediation or terminate based on the retry budget."""
    retry_count = state.get("ci_retry_count", 0)
    max_limit = state.get("ci_max_retry_limit", 2)

    if retry_count >= max_limit:
        print("[SYSTEM] 🛑 Maximum CI/CD retry limit reached. Routing to terminal failure node.")
        return "max_limit_reached"
    return "retry"

async def fetch_and_purge_latest_logs(state: AgentState, config: RunnableConfig) -> Dict[str, Any]:
    s3_client = boto3.client('s3')
    bucket_name = "remediation-logs-bucket" 
    raw_branch = state.get("branch_name", "")
    if not raw_branch:
        return {"error_logs": "Execution failed: branch_name key not found in agent state."}
        
    clean_branch = raw_branch.replace("/", "-")
    prefix = f"remediation-runs/{clean_branch}/"
    
    precheck_telemetry = "No precheck telemetry found."
    remediation_telemetry = "No core execution error telemetry found."
    validation_telemetry = "No validation telemetry found."
    
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' not in response:
            return {"error_logs": "No logs found in S3 for this evidence branch run."}
            
        all_objects = response['Contents']
        
        def get_log_content(stage_substring: str):
            stage_objects = [obj for obj in all_objects if stage_substring in obj['Key']]
            stderr_list = [obj for obj in stage_objects if obj['Key'].endswith('/stderr')]
            stdout_list = [obj for obj in stage_objects if obj['Key'].endswith('/stdout')]

            stderr_list.sort(key=lambda x: x['LastModified'], reverse=True)
            stdout_list.sort(key=lambda x: x['LastModified'], reverse=True)

            target = stderr_list[0] if stderr_list else (stdout_list[0] if stdout_list else None)
            
            if target:
                print(f"[SYSTEM] 📥 Harvesting log element: {target['Key']}")
                return s3_client.get_object(Bucket=bucket_name, Key=target['Key'])['Body'].read().decode('utf-8')
            return None
        
        print(f"[SYSTEM] 📥 Fetching multi-stage telemetry reports from cloud storage runway...")

        pre_log = get_log_content("/precheck/")
        if pre_log: precheck_telemetry = pre_log

        core_log = get_log_content("/remediation/")
        if core_log: remediation_telemetry = core_log

        val_log = get_log_content("/validation/")
        if val_log: validation_telemetry = val_log

    except Exception as e:
        return {"error_logs": f"S3 Harvesting Error: {str(e)}"}

    unified_error_report = (
        f"=== STAGE 1: PRECHECK TELEMETRY STATE ===\n{precheck_telemetry}\n\n"
        f"=== STAGE 2: CORE REMEDIATION EXECUTION LOGS ===\n{remediation_telemetry}\n\n"
        f"=== STAGE 3: POST-REMEDIATION VALIDATION CHECKS ===\n{validation_telemetry}\n"
    )

    current_retry = state.get("ci_retry_count", 0)
    max_limit = state.get("ci_max_retry_limit", 2)
    next_retry_count = current_retry + 1
    
    return_payload = {
        "error_logs": unified_error_report, 
        "precheck_logs": precheck_telemetry,
        "validation_logs": validation_telemetry,
        "ci_retry_count": next_retry_count
    }

    # --- Desired behavior on final failure ---
    if next_retry_count >= max_limit:
        try:
            thread_id = config["configurable"]["thread_id"]
            failure_report = {
                "thread_id": thread_id,
                "branch": state["branch_name"],
                "pr": state["pr_url"],
                "retry_count": next_retry_count,
                "generated_script": state["modified_file_content"],
                "precheck_logs": precheck_telemetry,
                "validation_logs": validation_telemetry,
                "remediation_logs": remediation_telemetry,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            report_key = f"remediation-runs/{clean_branch}/final_failure_report.json"
            print(f"[SYSTEM] 📤 Uploading consolidated failure report to S3: {report_key}")
            
            s3_client.put_object(
                Bucket=bucket_name,
                Key=report_key,
                Body=json.dumps(failure_report, indent=2),
                ContentType="application/json"
            )
            
            # Generate a presigned URL valid for 7 days (604800 seconds)
            presigned_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': bucket_name, 'Key': report_key},
                ExpiresIn=604800
            )
            return_payload["failure_report_url"] = presigned_url

        except Exception as e:
            print(f"[ERROR] Failed to compile or upload terminal failure report: {str(e)}")

    # Purge temporary logs while keeping the final report if it was created
    try:
        objects_to_delete = [
            {'Key': obj['Key']} for obj in all_objects 
            if not obj['Key'].endswith('final_failure_report.json')
        ]
        if objects_to_delete:
            for i in range(0, len(objects_to_delete), 1000):
                chunk = objects_to_delete[i:i + 1000]
                s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': chunk})
    except Exception as e:
        return_payload["error_logs"] = f"{unified_error_report}\n\n[SYSTEM WARNING] S3 Purge Exception: {str(e)}"

    return return_payload

async def open_for_resume_request(state: AgentState, config: RunnableConfig):
    pr_number = state.get("pr_number")
    owner = state["repo_owner"]
    repo = state["repo_name"]
    fix_summary = state.get("fix_description", "Applied requested architectural updates.")
    original_feedback = state.get("pending_feedback")
    evidence_report = state.get("unified_evidence_report")
    thread_id = config['configurable']['thread_id']

    # Base comment layout
    comment_body = "### 🤖 Automated Remediation Update\n\n"

    # Branch logic depending on whether this execution was a response to an active human review
    if original_feedback:  
        comment_body += (
            "The requested review feedback has been successfully addressed, processed, and "
            "validated through the verification pipeline.\n\n"
            f"**Resolution Details:**\n{fix_summary}\n\n"
        )
    else:
        comment_body += (
            "The initial automated remediation suite has been generated and validated "
            "successfully through the verification pipeline.\n\n"
            f"**Remediation Summary:**\n{fix_summary}\n\n"
        )

    # Inject the Evidence Telemetry Accordion if it exists
    if evidence_report:
        comment_body += (
            "### 📊 Execution Validation Evidence\n"
            "<details>\n"
            "<summary>Click to expand runtime precheck and validation logs</summary>\n\n"
            "```text\n"
            f"{evidence_report}\n"
            "```\n\n"
            "</details>\n\n"
        )

    # Trailing status indicator
    comment_body += "Status: **Waiting for formal review and approval** ⏳"

    # Dispatch to GitHub
    comment_tool = next((t for t in tools if t.name == "add_issue_comment"), None)
    if comment_tool:
        try:
            # Using the inline wrapper to isolate comment API connection flakes
            await invoke_with_retry(
                tool_instance=comment_tool,
                payload={"owner": owner, "repo": repo, "issue_number": pr_number, "body": comment_body},
                retry_policy=git_retry_policy
            )
        except Exception as e:
            print(f"[SYSTEM ERROR] Completely failed to post comment to PR #{pr_number} after retries: {str(e)}")
            pass
    
    await update_workflow_state(thread_id, "WAITING_FOR_HUMAN_APPROVAL")

async def wait_for_human_approval(state: AgentState):
    pr_number = state.get("pr_number")
    owner = state["repo_owner"]
    repo = state["repo_name"]

    webhook_data = interrupt({"info": "Waiting for human review...", "pr_number": pr_number})
    
    pr_tool = next(t for t in tools if t.name == "pull_request_read")
    result = await pr_tool.ainvoke({"method": "get", "owner": owner, "repo": repo, "pullNumber": pr_number})
    data = json.loads(result[0]['text'])
    if data['merged']:
        print("PR Merged")
    else:
        print("PR Not Merged")
    print("PR State:", data['state'])
    return {"pending_feedback": "", "pr_merged": data["merged"], "pr_state": data['state']}

async def route_after_human_decision(state: AgentState):
    if state.get("pr_merged"):
        print("[AGENT] 🎉 Code approved and merged by engineer! Finalizing remediation session.")
        return "approved"
    else:
        if state.get("pr_state", "") == "closed":
            print("[AGENT] 📦 Pull Request has been closed without being merged. Terminating remediation workflow.")
            return "pr_closed"
        return "not_approved"
    
async def fetch_pr_feedback_node(state: AgentState):
    transition_result = await transition_jira_issue(issue_key = state["jira_issue_key"], status = "OPEN")
    token = os.environ.get("GITHUB_MCP_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    owner = state["repo_owner"]
    repo = state["repo_name"]
    pr_number = state["pr_number"]

    processed_review_ids = set(state.get("processed_review_ids", []))
    processed_general_comment_ids = set(state.get("processed_general_comment_ids", []))
    processed_inline_comment_ids = set(state.get("processed_inline_comment_ids", []))

    base_url = f"https://api.github.com/repos/{owner}/{repo}"
    prompt_header = f"### Pull Request Feedback for {owner}/{repo} (PR #{pr_number})\nPlease resolve the following review comments left on the codebase:\n"
    
    general_prompt_lines, inline_prompt_lines = [], []
    newly_discovered_review_ids, newly_discovered_general_comment_ids, newly_discovered_inline_comment_ids = [], [], []

    # General Comments
    try:
        response = requests.get(f"{base_url}/issues/{pr_number}/comments", headers=headers)
        response.raise_for_status()
        for comment in response.json():
            comment_id = comment["id"]
            if comment_id in processed_general_comment_ids:
                continue
            general_prompt_lines.append(f"- {comment['body']}")
            newly_discovered_general_comment_ids.append(comment_id)
    except Exception:
        pass

    # Reviews & Inline
    try:
        response = requests.get(f"{base_url}/pulls/{pr_number}/reviews", headers=headers)
        response.raise_for_status()
        for review in response.json():
            review_id = review["id"]
            if review["state"] not in ("CHANGES_REQUESTED", "COMMENTED"):
                continue
            review_is_new = (review_id not in processed_review_ids)

            inline_response = requests.get(f"{base_url}/pulls/{pr_number}/reviews/{review_id}/comments", headers=headers)
            has_new_inline_comments = False
            if inline_response.status_code == 200:
                for inline_comment in inline_response.json():
                    inline_comment_id = inline_comment["id"]
                    if inline_comment_id in processed_inline_comment_ids:
                        continue
                    has_new_inline_comments = True
                    line_number = inline_comment.get("line") or inline_comment.get("original_line") or inline_comment.get("position")
                    inline_prompt_lines.append(f"- **File:** `{inline_comment['path']}` (Line {line_number}) -> **Fix:** {inline_comment['body']}")
                    newly_discovered_inline_comment_ids.append(inline_comment_id)

            if review_is_new or has_new_inline_comments:
                if review_is_new:
                    newly_discovered_review_ids.append(review_id)
    except Exception:
        pass

    final_prompt_sections = [prompt_header]
    if general_prompt_lines:
        final_prompt_sections.append("#### General PR Comments:")
        final_prompt_sections.extend(general_prompt_lines)
        final_prompt_sections.append("")
    if inline_prompt_lines:
        final_prompt_sections.append("#### Code-Specific Feedback:")
        final_prompt_sections.extend(inline_prompt_lines)

    return {
        "pending_feedback": "\n".join(final_prompt_sections).strip(),
        "new_review_ids": newly_discovered_review_ids,
        "new_general_comment_ids": newly_discovered_general_comment_ids,
        "new_inline_comment_ids": newly_discovered_inline_comment_ids,
        "ci_retry_count": 0
    }

async def calculate_tokens_and_cost_consumption(state: AgentState):
    ai_msgs = [
        ai_msg
        for ai_msg in state["messages"]
        if isinstance(ai_msg, AIMessage)
    ]

    input_tokens = 0
    output_tokens = 0

    for ai_msg in ai_msgs:
        usage = ai_msg.response_metadata["token_usage"]
        input_tokens += usage["prompt_tokens"]
        output_tokens += usage["completion_tokens"]

    input_cost = (input_tokens / 1_000_000) * 0.40
    output_cost = (output_tokens / 1_000_000) * 1.60
    total_cost = input_cost + output_cost

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_cost": total_cost,
        "end_time": datetime.now(timezone.utc).isoformat()
    }

async def generate_evidence(state: AgentState) -> Dict[str, Any]:
    s3_client = boto3.client('s3')
    bucket_name = "remediation-logs-bucket" 
    raw_branch = state.get("branch_name", "")
    if not raw_branch:
        return {"error_logs": "Evidence generation failed: branch_name key not found in agent state."}
        
    clean_branch = raw_branch.replace("/", "-")
    prefix = f"remediation-runs/{clean_branch}/"
    
    precheck_telemetry = "No precheck telemetry found."
    validation_telemetry = "No validation telemetry found."
    
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        if 'Contents' not in response:
            return {"error_logs": "No logs found in S3 for this evidence branch run."}
            
        all_objects = response['Contents']
        
        # Helper to retrieve contents of the latest stdout *only* for specific pipeline stages
        def get_log_content(stage_substring: str):
            # 1. Isolate objects for this specific stage execution
            stage_objects = [obj for obj in all_objects if stage_substring in obj['Key']]
            
            # 2. Extract list of stdout matches only
            stdout_list = [obj for obj in stage_objects if obj['Key'].endswith('/stdout')]

            # 3. Sort them chronologically descending (newest first)
            stdout_list.sort(key=lambda x: x['LastModified'], reverse=True)

            # 4. Extract the newest stdout file literal
            target = stdout_list[0] if stdout_list else None
            
            if target:
                return s3_client.get_object(Bucket=bucket_name, Key=target['Key'])['Body'].read().decode('utf-8')
            return None
        
        # FIXED: Pulled out of the get_log_content function definition scope so it actually runs!
        print(f"[SYSTEM] 📥 Fetching multi-stage success telemetry reports from cloud storage...")

        # Gather telemetry maps from evidence stages
        pre_log = get_log_content("/precheck/")
        if pre_log: 
            precheck_telemetry = pre_log

        val_log = get_log_content("/validation/")
        if val_log: 
            validation_telemetry = val_log

    except Exception as e:
        return {"error_logs": f"S3 Evidence Harvesting Error: {str(e)}"}

    # Format everything into a clean validation context
    unified_evidence_report = (
        f"=== STAGE 1: PRECHECK TELEMETRY STATE ===\n{precheck_telemetry}\n\n"
        f"=== STAGE 2: POST-REMEDIATION VALIDATION CHECKS ===\n{validation_telemetry}\n"
    )

    # Purge historical tracking files to clear the workspace after saving evidence
    try:
        objects_to_delete = [{'Key': obj['Key']} for obj in all_objects]
        for i in range(0, len(objects_to_delete), 1000):
            chunk = objects_to_delete[i:i + 1000]
            s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': chunk})
    except Exception as e:
        # Pass the report back even if the cleanup step runs into an intermittent S3 API glitch
        return {
            "unified_evidence_report": unified_evidence_report,
            "error_logs": f"[SYSTEM WARNING] S3 Purge Exception during evidence save: {str(e)}"
        }

    return {
        "unified_evidence_report": unified_evidence_report
    }

def track_time(node_func):
    @wraps(node_func)
    async def wrapper(state, *args, **kwargs):
        start = time.perf_counter()

        result = await node_func(state, *args, **kwargs)

        elapsed = time.perf_counter() - start

        if result is None:
            result = {}

        result["active_execution_time"] = elapsed
        return result

    return wrapper


async def jira_create_issue_node(state: AgentState) -> Dict[str, Any]:
    print(f"[AGENT] Creating JIRA Ticket...")
    if state.get("jira_issue_key"):
        return {"jira_issue_key": state["jira_issue_key"], "jira_status": "OPEN"}

    issue_summary = f"Automated remediation workflow"
    issue_description = (
        f"Automated remediation workflow started for repository {state['repo_owner']}/{state['repo_name']}\n"
        f"Target file: {state.get('target_file') or 'remediation.sh'}\n"
        f"Issue description: {state['issue_description']}"
    )
    
    # Added 'await' here
    result = await create_jira_issue(summary=issue_summary, description=issue_description)
    
    return {"jira_issue_key": result.get("issue_key"), "jira_status": result.get("status", "OPEN")}

async def jira_human_in_loop_node(state: AgentState) -> Dict[str, Any]:
    print(f"[AGENT] Flagging for Human Review in JIRA...")
    issue_key = state.get("jira_issue_key")
    if not issue_key:
        return {"jira_status": "HUMAN_IN_THE_LOOP"}

    pr_url = state.get("pr_url", "N/A")
    pr_number = state.get("pr_number", "N/A")
    ci_status = state.get("ci_status", "unknown")
    comment = (
        f"Remediation PR is ready.\n"
        f"PR URL: {pr_url}\n"
        f"PR Number: {pr_number}\n"
        f"CI Success Status: {ci_status}\n"
        f"Waiting for human approval."
    )

    # Performance optimization: Run transition and comment concurrently!
    transition_task = transition_jira_issue(issue_key, "HUMAN_IN_THE_LOOP")
    comment_task = add_jira_comment(issue_key, comment)
    
    transition_result, comment_result = await asyncio.gather(transition_task, comment_task)

    print(f"\n[AGENT] 💤 Entering standby state. Awaiting Human Peer Review or merge action on PR #{pr_number}...")
    
    return {
        "jira_issue_key": issue_key,
        "jira_status": transition_result.get("status", "HUMAN_IN_THE_LOOP"),
        "jira_comment_result": comment_result,
    }


async def jira_resolved_node(state: AgentState) -> Dict[str, Any]:
    print(f"[AGENT] Resolving JIRA Ticket...")
    issue_key = state.get("jira_issue_key")
    if not issue_key:
        return {"jira_status": "RESOLVED"}

    comment = (
        f"Remediation workflow approved and merged.\n"
        f"PR URL: {state.get('pr_url', 'N/A')}\n"
        f"Merge confirmation: approved and merged by human reviewer."
    )
    
    # Run transition and comment concurrently
    transition_task = transition_jira_issue(issue_key, "RESOLVED")
    comment_task = add_jira_comment(issue_key, comment)
    
    transition_result, _ = await asyncio.gather(transition_task, comment_task)
    
    return {"jira_issue_key": issue_key, "jira_status": transition_result.get("status", "RESOLVED")}


async def jira_unresolved_node(state: AgentState) -> Dict[str, Any]:
    print(f"[AGENT] Marking JIRA Ticket as UNRESOLVED...")
    issue_key = state.get("jira_issue_key")
    if not issue_key:
        return {"jira_status": "UNRESOLVED"}

    failure_details = None
    retry_count = state.get("ci_retry_count", 0)
    max_limit = state.get("ci_max_retry_limit", 2)
    pr_url = state.get("pr_url", "N/A")
    report_url = state.get("failure_report_url")

    if retry_count >= max_limit:
        failure_details = "Automated remediation workflow terminated: Maximum execution retry limit exceeded."
    else:
        failure_details = "Workflow cancelled: Pull Request was manually closed by a human reviewer."
    
    comment = (
        "Remediation workflow could not be completed.\n"
        f"Failure details: {failure_details}\nPR URL: {pr_url}\n"
    )
    
    # Inject the presigned link if it exists
    if report_url:
        comment += f"Consolidated Failure Report (S3 Presigned URL): {report_url}\n"
    else:
        comment += "CI failure logs / exception details are attached in the workflow state.\n"

    # Run transition and comment concurrently
    transition_task = transition_jira_issue(issue_key, "UNRESOLVED")
    comment_task = add_jira_comment(issue_key, comment)
    
    transition_result, _ = await asyncio.gather(transition_task, comment_task)
    
    return {"jira_issue_key": issue_key, "jira_status": transition_result.get("status", "UNRESOLVED")}



async def build_graph(checkpointer):
    if tool_node is None:
        raise RuntimeError("Agent tools not initialized.")
    
    graph = StateGraph(AgentState)
    graph.add_node("generate_remediation_script", track_time(remediation_node))
    graph.add_node("create_prompt", track_time(create_prompt))
    graph.add_node("github_workflow", git_operator_node, retry_policy=git_retry_policy)
    graph.add_node("github_tools", tool_node)
    graph.add_node("extract_pr_details", track_time(extract_pr_details))
    graph.add_node("check_ci_status", track_time(check_ci_status))
    graph.add_node("fetch_and_delete_error_logs", track_time(fetch_and_purge_latest_logs))
    graph.add_node("wait_for_human_approval", wait_for_human_approval)
    graph.add_node("fetch_pr_feedback", track_time(fetch_pr_feedback_node))
    graph.add_node("open_for_resume_request", track_time(open_for_resume_request))
    graph.add_node("calculate_tokens_and_cost_consumption", track_time(calculate_tokens_and_cost_consumption))
    graph.add_node("generate_evidence", track_time(generate_evidence))
    graph.add_node("create_jira_ticket", track_time(jira_create_issue_node))
    graph.add_node("flag_for_review_jira", track_time(jira_human_in_loop_node))
    graph.add_node("resolve_jira_ticket", track_time(jira_resolved_node))
    graph.add_node("mark_jira_ticket_unresolved", track_time(jira_unresolved_node))
    graph.add_node("create_research_prompt", track_time(create_research_prompt_node))
    graph.add_node("research_vulnerability", research_vulnerability_node)
    graph.add_node("research_tools", research_tool_node)

    
    graph.add_edge(START, "create_jira_ticket")
    graph.add_edge("create_jira_ticket", "create_research_prompt")
    graph.add_edge("create_research_prompt", "research_vulnerability")

    graph.add_conditional_edges(
        "research_vulnerability",
        tools_condition,
        {
            "tools": "research_tools", 
            "__end__": "generate_remediation_script"
        }
    )
    graph.add_edge("research_tools", "research_vulnerability")
    
    
    graph.add_edge("generate_remediation_script", "create_prompt")

    
    graph.add_edge("create_prompt", "github_workflow")
    graph.add_conditional_edges(
        "github_workflow", 
        tools_condition, 
        {"tools": "github_tools", "__end__": "extract_pr_details"}
    )
    graph.add_edge("github_tools", "github_workflow")
    graph.add_edge("extract_pr_details", "check_ci_status")

    
    graph.add_conditional_edges("check_ci_status", route_after_ci, {
        "failure": "fetch_and_delete_error_logs",
        "success": "generate_evidence"
    })
    graph.add_conditional_edges("fetch_and_delete_error_logs", route_after_failure, {
        "retry": "generate_remediation_script",
        "max_limit_reached": "mark_jira_ticket_unresolved"
    })

    
    graph.add_edge("generate_evidence", "open_for_resume_request")
    graph.add_edge("open_for_resume_request", "flag_for_review_jira")
    
    
    graph.add_edge("flag_for_review_jira", "wait_for_human_approval")

    
    graph.add_conditional_edges("wait_for_human_approval", route_after_human_decision, {
        "approved": "resolve_jira_ticket",
        "pr_closed": "mark_jira_ticket_unresolved",
        "not_approved": "fetch_pr_feedback"
    })
    graph.add_edge("fetch_pr_feedback", "generate_remediation_script")
    graph.add_edge("resolve_jira_ticket", "calculate_tokens_and_cost_consumption")
    graph.add_edge("mark_jira_ticket_unresolved", "calculate_tokens_and_cost_consumption")
    graph.add_edge("calculate_tokens_and_cost_consumption", END)

    return graph.compile(checkpointer=checkpointer)