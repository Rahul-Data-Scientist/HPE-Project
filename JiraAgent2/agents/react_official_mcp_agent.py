from langchain_groq import (
    ChatGroq
)

from langgraph.graph import (
    StateGraph,
    END
)

from typing import TypedDict

from langchain_core.messages import (
    ToolMessage,
    SystemMessage
)

from agents.atlassian_mcp import (
    get_atlassian_tools
)

from dotenv import load_dotenv

import os
import asyncio

load_dotenv()


# =========================
# LLM
# =========================

llm = ChatGroq(

    model="llama-3.3-70b-versatile",

    api_key=os.getenv(
        "GROQ_API_KEY"
    ),

    temperature=0
)


# =========================
# STATE
# =========================

class AgentState(TypedDict):

    messages: list


# =========================
# LOAD MCP TOOLS
# =========================

tools = asyncio.run(
    get_atlassian_tools()
)

print("\nMCP TOOLS LOADED:\n")

for tool in tools:

    print(tool.name)


# =========================
# TOOL MAP
# =========================

tool_map = {

    tool.name: tool

    for tool in tools
}


# =========================
# BIND TOOLS
# =========================

llm_with_tools = llm.bind_tools(
    tools
)


# =========================
# ASSISTANT NODE
# =========================

def assistant_node(state):

    messages = state["messages"]

    system_message = SystemMessage(

        content=f"""
You are an enterprise Atlassian Jira AI Agent.

IMPORTANT TOOL RULES:

1. To get cloud ID:
ALWAYS use:
getAccessibleAtlassianResources

2. To create Jira issues:
ALWAYS use:
createJiraIssue

3. To search Jira tickets:
ALWAYS use:
searchJiraIssuesUsingJql

4. To add comments:
ALWAYS use:
addCommentToJiraIssue

5. To close or transition tickets:
ALWAYS use:
transitionJiraIssue

6. NEVER hallucinate:
- cloudId
- projectKey
- URLs

7. Use these REAL Jira details:

Cloud ID:
{os.getenv("ATLASSIAN_CLOUD_ID")}

Project Key:
{os.getenv("ATLASSIAN_PROJECT_KEY")}

8. NEVER invent fake values like:
- your_cloud_id
- your_project_key

9. ONLY perform the exact task requested.

10. NEVER:
- auto close tickets
- auto add comments
- auto search tickets

11. After task completion:
STOP immediately.

12. Use concise tool arguments only.

13. When creating Jira tickets:
always use:

projectKey:
{os.getenv("ATLASSIAN_PROJECT_KEY")}

cloudId:
{os.getenv("ATLASSIAN_CLOUD_ID")}
"""
    )

    response = llm_with_tools.invoke(

        [system_message] + messages
    )

    return {

        "messages":
        messages + [response]
    }


# =========================
# TOOL NODE
# =========================

async def tool_node(state):

    messages = state["messages"]

    last_message = messages[-1]

    tool_calls = last_message.tool_calls

    tool_messages = []

    for tool_call in tool_calls:

        tool_name = tool_call["name"]

        tool_args = tool_call["args"]

        print("\nTOOL CALLED:\n")
        print(tool_name)

        print("\nARGS:\n")
        print(tool_args)

        selected_tool = tool_map.get(
            tool_name
        )

        if not selected_tool:

            result = {

                "error": True,

                "message":
                f"Tool {tool_name} not found"
            }

        else:

            try:

                result = await selected_tool.ainvoke(
                    tool_args
                )

            except Exception as e:

                result = {

                    "error": True,

                    "message": str(e)
                }

        print("\nTOOL RESULT:\n")
        print(result)

        tool_message = ToolMessage(

            content=str(result),

            tool_call_id=
            tool_call["id"]
        )

        tool_messages.append(
            tool_message
        )

    return {

        "messages":
        messages + tool_messages
    }


# =========================
# ROUTER
# =========================

def router(state):

    last_message = state["messages"][-1]

    # =========================
    # PREVENT INFINITE LOOPS
    # =========================

    if len(state["messages"]) > 6:

        return END

    # =========================
    # TOOL CALL DETECTION
    # =========================

    if (

        hasattr(
            last_message,
            "tool_calls"
        )

        and

        last_message.tool_calls
    ):

        return "tools"

    return END


# =========================
# GRAPH
# =========================

graph_builder = StateGraph(
    AgentState
)

graph_builder.add_node(
    "assistant",
    assistant_node
)

graph_builder.add_node(
    "tools",
    tool_node
)

graph_builder.set_entry_point(
    "assistant"
)

graph_builder.add_conditional_edges(

    "assistant",

    router,

    {
        "tools": "tools",
        END: END
    }
)

graph_builder.add_edge(
    "tools",
    "assistant"
)

graph = graph_builder.compile()