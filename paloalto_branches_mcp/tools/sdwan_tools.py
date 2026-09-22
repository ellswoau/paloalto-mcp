"""SD-WAN tools.

``show sdwan connection all`` reports the SD-WAN links: ``ethernet1/1`` is
always the primary (fiber DIA) internet connection and ``ethernet1/2`` is the
secondary. The ``sdwan.9xx`` VIFs route traffic either straight to the
internet or to a datacenter (identified by peer-IP): the Grand Rapids primary
DC is ``74.204.122.83/28`` and the Indianapolis secondary DC is
``184.175.154.179/28``.
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from ..client import get_client
from ._common import run_and_report, validate_policy_name, validate_session_id

CONNECTION_ALL_COMMAND = "show sdwan connection all"

#: Known datacenter underlay subnet -> friendly name (from the notes).
DATACENTERS = {
    "74.204.122.83": "Grand Rapids (primary DC)",
    "184.175.154.179": "Indianapolis (secondary DC)",
}

#: The primary and secondary internet hand-offs.
PRIMARY_INTERFACE = "ethernet1/1"
SECONDARY_INTERFACE = "ethernet1/2"


def distribution_command(policy_name: str) -> str:
    """Build the session-distribution command for a policy name."""
    return f'show sdwan session distribution policy-name "{policy_name}"'


def path_select_command(session_id) -> str:
    return f"show sdwan session path-select session-id {session_id}"


def register(mcp: "FastMCP", config: "PaloConfig") -> None:

    @mcp.tool()
    def show_sdwan_connection(store: int, timeout: Optional[int] = None) -> dict:
        """Show the SD-WAN connection state for a branch. ``ethernet1/1`` is
        the primary internet connection and ``ethernet1/2`` the secondary;
        the ``sdwan.9xx`` VIFs route to the internet or to a datacenter (by
        peer-IP: 74.204.122.83 = Grand Rapids, 184.175.154.179 = Indianapolis).
        Returns the raw output plus parsed link rows."""
        client = get_client(config)
        result = run_and_report(client, store, CONNECTION_ALL_COMMAND, timeout=timeout)
        rows = []
        for table in (result.get("tables") or []):
            for row in table["rows"]:
                peer = (row.get("peer-ip") or "").strip()
                if peer in DATACENTERS:
                    row = {**row, "datacenter": DATACENTERS[peer]}
                rows.append(row)
        if rows:
            result["rows"] = rows
        return result

    @mcp.tool()
    def list_sdwan_policies(store: int, timeout: Optional[int] = None) -> dict:
        """List the SD-WAN traffic-steering policies configured on a branch
        (e.g. 'Voice to Internet', 'Guest to Internet'). Use a returned policy
        name with sdwan_session_distribution."""
        client = get_client(config)
        return run_and_report(client, store, "show sdwan policy", timeout=timeout)

    @mcp.tool()
    def sdwan_session_distribution(store: int, policy_name: str,
                                   timeout: Optional[int] = None) -> dict:
        """Show the session distribution for one SD-WAN policy, i.e. which
        internet connection the policed traffic uses. Voice traffic should
        normally go out ethernet1/1 (primary/fiber); a significant share on
        ethernet1/2 indicates a problem. Pass the exact policy name, e.g.
        'Voice to Internet'."""
        name = validate_policy_name(policy_name)
        client = get_client(config)
        result = run_and_report(client, store, distribution_command(name),
                                timeout=timeout)
        result["policy_name"] = name

        # Tag each row with which internet hand-off the link belongs to.
        tagged = []
        for row in (result.get("rows") or []):
            link = (row.get("Link") or "").strip().lower()
            if "ethernet1/1" in link:
                row = {**row, "internet_connection": "primary (ethernet1/1)"}
            elif "ethernet1/2" in link:
                row = {**row, "internet_connection": "secondary (ethernet1/2)"}
            tagged.append(row)
        if tagged:
            result["rows"] = tagged
        return result

    @mcp.tool()
    def sdwan_session_path_select(store: int, session_id: str,
                                  timeout: Optional[int] = None) -> dict:
        """Show recent SD-WAN path-quality/path-selection changes for a session
        id. Recent path changes can indicate an internet quality issue or
        outage. Get the session id from find_session_by_source."""
        sid = validate_session_id(session_id)
        client = get_client(config)
        result = run_and_report(client, store, path_select_command(sid),
                                timeout=timeout)
        result["session_id"] = sid
        output = result.get("output") or ""
        result["recent_path_changes"] = not ("not available" in output.lower()
                                             or "no recent" in output.lower())
        return result