from typing import AsyncIterator
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP

from app.context import AppContext
from fake_database import Database  # Replace with actual DB type


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    db = await Database.connect()
    try:
        yield AppContext(db=db)
    finally:
        await db.disconnect()
