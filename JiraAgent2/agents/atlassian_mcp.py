from langchain_mcp_adapters.client import (
    MultiServerMCPClient
)

from dotenv import load_dotenv

import os

load_dotenv()


async def get_atlassian_tools():

    client = MultiServerMCPClient(

        {
            "atlassian": {

                "transport":
                "sse",

                "url":
                "https://mcp.atlassian.com/v1/sse",

                "headers": {

                    "Authorization":
                    f"Bearer {os.getenv('ATLASSIAN_ACCESS_TOKEN')}"
                }
            }
        }
    )

    all_tools = await client.get_tools()

    # =========================
    # FILTER ONLY REQUIRED TOOLS
    # =========================

    allowed_tools = [

        "getAccessibleAtlassianResources",

        "getVisibleJiraProjects",

        "createJiraIssue",

        "getJiraIssue",

        "editJiraIssue",

        "addCommentToJiraIssue",

        "transitionJiraIssue",

        "searchJiraIssuesUsingJql",

        "getTransitionsForJiraIssue"
    ]

    tools = []

    for tool in all_tools:

        if tool.name in allowed_tools:

            tools.append(tool)

    print("\nFILTERED TOOLS:\n")

    for tool in tools:

        print(tool.name)

    return tools