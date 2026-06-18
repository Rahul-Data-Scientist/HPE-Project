import os
import base64
from typing import Any, Dict, Optional

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type


JIRA_STATUS_MAP = {
    "OPEN": "OPEN",
    "HUMAN_IN_THE_LOOP": "HUMAN_IN_THE_LOOP",
    "RESOLVED": "RESOLVED",
    "UNRESOLVED": "UNRESOLVED",
}

# -------------------------------------------------------------------------
# Retry Decorator Configuration
# -------------------------------------------------------------------------
# This will retry up to 3 times if an HTTP status error or network timeout happens.
# Wait times: 2s -> 4s -> 8s...
jira_retry_decorator = retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.RequestError))
)

# -------------------------------------------------------------------------
# Synchronous Configuration Utilities (No Retries Needed)
# -------------------------------------------------------------------------
def _jira_config() -> Dict[str, Optional[str]]:
    return {
        "base_url": (os.getenv("JIRA_BASE_URL") or "").rstrip("/"),
        "email": os.getenv("JIRA_EMAIL"),
        "token": os.getenv("JIRA_API_TOKEN"),
        "project_key": os.getenv("JIRA_PROJECT_KEY", "KAN"),
        "issue_type": os.getenv("JIRA_ISSUE_TYPE", "Task"),
    }

def _auth_headers() -> Dict[str, str]:
    config = _jira_config()
    if not config["base_url"] or not config["email"] or not config["token"]:
        raise RuntimeError("Jira configuration is incomplete. Set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN.")
    
    auth_str = f"{config['email']}:{config['token']}"
    b64_auth = base64.b64encode(auth_str.encode()).decode()
    
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Basic {b64_auth}",
    }

# -------------------------------------------------------------------------
# Asynchronous Main Client Functions (With Retries Attached)
# -------------------------------------------------------------------------

@jira_retry_decorator
async def create_jira_issue(summary: str, description: str, project_key: Optional[str] = None) -> Dict[str, Any]:
    config = _jira_config()
    if not config["base_url"]:
        return {"issue_key": None, "status": "OPEN", "created": False, "message": "Jira not configured"}

    project = project_key or config["project_key"]
    payload = {
        "fields": {
            "project": {"key": project or "AUTO"},
            "summary": summary[:255],
            "description": description,
            "issuetype": {"name": config["issue_type"]},
        }
    }

    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{config['base_url']}/rest/api/2/issue",
            headers=_auth_headers(),
            json=payload,
            timeout=15.0,  # Dropped to 15s since tenacity handles retry loops now
        )
        response.raise_for_status()
        
    data = response.json()
    issue_key = data.get("key")
    return {"issue_key": issue_key, "status": "OPEN", "created": True, "raw": data}


@jira_retry_decorator
async def get_jira_issue(issue_key: str) -> Dict[str, Any]:
    config = _jira_config()
    if not issue_key or not config["base_url"]:
        return {"issue_key": issue_key, "exists": False, "status": None}

    
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{config['base_url']}/rest/api/2/issue/{issue_key}",
            headers=_auth_headers(),
            timeout=15.0,
        )
        response.raise_for_status()
        
    data = response.json()
    status_name = data.get("fields", {}).get("status", {}).get("name")
    return {"issue_key": issue_key, "exists": True, "status": status_name, "raw": data}


@jira_retry_decorator
async def transition_jira_issue(issue_key: str, status: str) -> Dict[str, Any]:
    config = _jira_config()
    if not issue_key or not config["base_url"]:
        return {"issue_key": issue_key, "status": status, "transitioned": False, "message": "Jira not configured"}

    target_status = JIRA_STATUS_MAP.get(str(status).upper(), str(status).upper())
    
    async with httpx.AsyncClient() as client:
        # Step 1: Fetch valid available transitions
        response = await client.get(
            f"{config['base_url']}/rest/api/2/issue/{issue_key}/transitions",
            headers=_auth_headers(),
            timeout=15.0,
        )
        response.raise_for_status()
        transitions = response.json().get("transitions", [])

        transition = next((item for item in transitions if item.get("to", {}).get("name", "").upper() == target_status), None)
        if transition is None:
            return {"issue_key": issue_key, "status": target_status, "transitioned": False, "message": "Transition not found"}

        # Step 2: Post the selected transition ID
        post_response = await client.post(
            f"{config['base_url']}/rest/api/2/issue/{issue_key}/transitions",
            headers=_auth_headers(),
            json={"transition": {"id": transition["id"]}},
            timeout=15.0,
        )
        post_response.raise_for_status()

    return {"issue_key": issue_key, "status": target_status, "transitioned": True}


@jira_retry_decorator
async def add_jira_comment(issue_key: str, body: str) -> Dict[str, Any]:
    config = _jira_config()
    if not issue_key or not config["base_url"]:
        return {"issue_key": os.get("base_url"), "comment_added": False, "message": "Jira not configured"}
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{config['base_url']}/rest/api/2/issue/{issue_key}/comment",
            headers=_auth_headers(),
            json={"body": body},
            timeout=15.0,
        )
        response.raise_for_status()
        
    return {"issue_key": issue_key, "comment_added": True, "raw": response.json()}