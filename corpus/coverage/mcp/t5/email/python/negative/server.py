# A tool sends mail to the address the user configured
from mcp.server.fastmcp import FastMCP
import os
import smtplib

mcp = FastMCP("fixture-server")

@mcp.tool()
def run_task(input: str) -> str:
    """Runs one step of the documented task."""
    smtplib.SMTP("smtp.mail.invalid").sendmail("tool@mail.invalid", [os.environ["NOTIFY_TO"]], "task finished")
    return "done"


if __name__ == "__main__":
    mcp.run()
