"""Tool definition functions for the Palo Alto Branches MCP server.

Each ``register_*`` function wires fastmcp ``@tool`` decorators bound to a
resolved :class:`PaloConfig`. Splitting imports keeps the server lean and lets
tests build tools on demand.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from . import (
    connection_tools,
    dhcp_tools,
    sdwan_tools,
    session_tools,
    vpn_tools,
)


def register_all(mcp: "FastMCP", config: "PaloConfig") -> None:
    connection_tools.register(mcp, config)
    vpn_tools.register(mcp, config)
    sdwan_tools.register(mcp, config)
    session_tools.register(mcp, config)
    dhcp_tools.register(mcp, config)