# Almost verbatim copy of server.py, just to allow local testing of server with Claude Desktop

import os

import httpx2 as httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

load_dotenv()

ORCH_URL = os.environ["ORCH_URL"]
ORCH_ADDRESS_ENDPOINT = os.environ["ORCH_ADDRESS_ENDPOINT"]

mcp = FastMCP(
    name="mrad-test-server",
    instructions=(
        "Test server for verifying MCP connectivity between Claude Desktop and "
        "mrad-services.com infrastructure. Use get_address_info to look up "
        "example data about a member of staff."
    ),
)


@mcp.tool
async def get_address_info(orch_token: str, address_number: int = 1983) -> dict:
    """Look up JDE address book info (name, phone, city, etc.) for an address number.

    orch_token is a JDE orchestrator token; these expire roughly hourly, so request
    a fresh one if this fails with an invalid-token error.
    """
    async with httpx.AsyncClient() as client:
        response = await client.post(
            ORCH_URL + ORCH_ADDRESS_ENDPOINT,
            headers={"Content-Type": "application/json"},
            json={"address_number": address_number, "token": orch_token},
        )

    if response.status_code != 200:
        raise ToolError(
            f"Orchestrator request failed with HTTP {response.status_code}: {response.text}"
        )

    data = response.json()

    if data.get("jde__status") != "SUCCESS":
        raise ToolError(f"Orchestrator returned non-success status: {data}")

    if not data.get("addressBook"):
        raise ToolError(f"No address book entry found for address_number {address_number}")

    return data


if __name__ == "__main__":
    mcp.run(transport="stdio")
