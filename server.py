import os

import httpx2 as httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token

from auth import JdeOAuthProvider

load_dotenv()

ORCH_URL = os.environ["ORCH_URL"]
ORCH_ADDRESS_ENDPOINT = os.environ["ORCH_ADDRESS_ENDPOINT"]
ORCH_TOKEN_URL = os.environ["ORCH_TOKEN_URL"]
PUBLIC_BASE_URL = os.environ["PUBLIC_BASE_URL"]

mcp = FastMCP(
    name="mrad-test-server",
    instructions=(
        "Test server for verifying MCP connectivity between Claude Desktop and "
        "mrad-services.com infrastructure. Use get_address_info to look up "
        "example data about a member of staff. Connecting requires signing in "
        "with your JDE username and password via a browser login prompt."
    ),
    auth=JdeOAuthProvider(base_url=PUBLIC_BASE_URL, orch_token_url=ORCH_TOKEN_URL),
)


@mcp.tool
async def get_address_info(address_number: int = 1983) -> dict:
    """Look up JDE address book info (name, phone, city, etc.) for an address number.

    Requires signing in with your JDE credentials once per MCP session (handled
    by a browser login prompt).
    """
    access_token = get_access_token()
    orch_token = access_token.claims.get("jde_token") if access_token else None
    if not orch_token:
        raise ToolError("No active JDE session; reconnect to the server to sign in again.")

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
    mcp.run(transport="http", host="127.0.0.1", port=8000)