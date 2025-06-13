from app.context import AppContext
from mcp.server.fastmcp import FastMCP


def register_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    def query_db() -> str:
        ctx = mcp.get_context()
        app_ctx: AppContext = ctx.request_context.lifespan_context
        return app_ctx.db.query()

    @mcp.tool()
    def scan_network(target_ip: str) -> str:
        # Placeholder
        return f"Scanned network at {target_ip}, no vulnerabilities found."

    @mcp.tool()
    def run_exploit(exploit_name: str, target_ip: str) -> str:
        # Placeholder
        return f"Executed exploit {exploit_name} on target {target_ip}. Success!"
