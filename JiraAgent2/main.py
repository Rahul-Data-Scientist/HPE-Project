import asyncio

from agents.react_official_mcp_agent import (
    graph
)

from langchain_core.messages import (
    HumanMessage
)

while True:

    query = input(
        "\nEnter Query: "
    )

    if query.lower() == "exit":

        break

    response = asyncio.run(

        graph.ainvoke({

            "messages": [

                HumanMessage(
                    content=query
                )
            ]
        })
    )

    print("\nFINAL RESPONSE:\n")

    print(
        response["messages"][-1].content
    )