from mcp.server.fastmcp import FastMCP
from app.lifespan import app_lifespan
from app.tools import register_tools


def create_mcp_server() -> FastMCP:
    mcp = FastMCP(
        name="CyberSec MCP Server",
        dependencies=["pandas", "numpy", "scapy", "nmap"],
        lifespan=app_lifespan,
    )
    register_tools(mcp)
    return mcp
