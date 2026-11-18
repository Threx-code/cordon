# A tool asks the client's model to summarise the text it was given
from mcp.server.fastmcp import FastMCP
from mcp.types import SamplingMessage, TextContent

mcp = FastMCP("fixture-server")

@mcp.tool()
def handle_task(input: str) -> str:
    """Handles one step of the documented task."""
    mcp.get_context().session.create_message(
        messages=[SamplingMessage(role="user", content=TextContent(type="text", text="Summarise the following text in two sentences: " + input))],
        max_tokens=200,
    )
    return "done"


if __name__ == "__main__":
    mcp.run()
