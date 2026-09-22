"""VPN tunnel tools.

``show vpn flow`` lists every IPSec tunnel and whether it monitors as up. If
one or two tunnels are down, the branch is likely having an internet
connectivity issue.
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from ..client import get_client
from ._common import run_and_report

#: Command from the notes.
VPN_FLOW_COMMAND = "show vpn flow"

#: Tunnels in these states are considered healthy.
_UP_STATES = {"up", "active"}
_DOWN_STATES = {"down", "inactive"}


def _tunnel_state(row: dict) -> str:
    """The meaningful up/down indicator for a tunnel row.

    ``show vpn flow`` has both a ``state`` (active/inactive) and a ``monitor``
    column (up/down); the monitor column is what the notes mean by "up or
    not", so it is preferred when present.
    """
    return (row.get("monitor") or row.get("state") or "").strip().lower()


def summarize_tunnels(rows: list) -> dict:
    """Summarise tunnel rows into up/down counts and lists."""
    up, down, other = [], [], []
    for row in rows or []:
        state = _tunnel_state(row)
        name = row.get("name") or row.get("id") or "?"
        if state in _UP_STATES:
            up.append(name)
        elif state in _DOWN_STATES:
            down.append(name)
        else:
            other.append({"name": name, "state": state})
    return {"total": len(rows or []), "up": len(up), "down": len(down),
            "up_tunnels": up, "down_tunnels": down, "other_states": other}


def register(mcp: "FastMCP", config: "PaloConfig") -> None:

    @mcp.tool()
    def show_vpn_flow(store: int, timeout: Optional[int] = None) -> dict:
        """Show all IPSec VPN tunnels and whether they are up. If one or two
        tunnels are down the branch is likely experiencing an internet
        connectivity issue. Returns the raw output plus an up/down summary."""
        client = get_client(config)
        result = run_and_report(client, store, VPN_FLOW_COMMAND, timeout=timeout)
        result["summary"] = summarize_tunnels(result.get("rows") or [])
        return result