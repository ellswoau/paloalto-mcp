"""Session tools -- find, inspect, and clear PAN-OS network sessions.

Typical voice troubleshooting flow:
  1. ``show dhcp server lease interface <iface>`` -> find the phone's IP
     (match MAC/hostname to the device serial).
  2. ``find_session_by_source`` -> get the session id and see which internet
     connection the phone is NAT'd out of.
  3. ``sdwan_session_path_select`` -> check for recent path changes.
  4. If the phone misbehaves (one-way voice, red buttons, not registered),
     ``clear_session_by_id`` / ``clear_session_by_source``.
"""
from __future__ import annotations

import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from ..client import get_client
from ._common import (
    run_and_report,
    validate_ip,
    validate_session_id,
    validate_store,
    validate_subnet,
)


def show_session_command(source_ip: str) -> str:
    return f"show session all filter source {source_ip}"


def clear_session_id_command(session_id) -> str:
    return f"clear session id {validate_session_id(session_id)}"


def clear_session_source_command(source) -> str:
    return f"clear session all filter source {source}"


#: A PAN-OS session row starts with the numeric session id, then the
#: application name, separated by two or more spaces.
_SESSION_ROW_RE = re.compile(r"^(\d+)\s{2,}([A-Za-z0-9_\-]+)")


def extract_session_id(output: str, source_ip: Optional[str] = None) -> Optional[str]:
    """Extract the first session id from ``show session`` output.

    PAN-OS prints session rows as ``<id>  <Application>  <State> ...``; the
    header line starts with ``ID`` and rule lines are dashes, both skipped.
    When ``source_ip`` is given, a row must also mention it.
    """
    for line in (output or "").splitlines():
        s = line.strip()
        if not s or s.startswith(("ID", "-", "Vsys")):
            continue
        if source_ip and source_ip not in s:
            continue
        m = _SESSION_ROW_RE.match(s)
        if m:
            return m.group(1)
    return None


def register(mcp: "FastMCP", config: "PaloConfig") -> None:

    @mcp.tool()
    def find_session_by_source(store: int, source_ip: str,
                              timeout: Optional[int] = None) -> dict:
        """Show the PAN-OS session(s) for a source IP on a branch firewall.
        Reveals the NAT translation (which internet connection the device is
        going out of) and the session id to use with
        sdwan_session_path_select / clear_session_by_id."""
        ip = validate_ip(source_ip)
        client = get_client(config)
        result = run_and_report(client, store, show_session_command(ip),
                                timeout=timeout)
        result["source_ip"] = ip
        return result

    @mcp.tool()
    def show_sessions(store: int, source_ip: str,
                      timeout: Optional[int] = None) -> dict:
        """Alias of find_session_by_source: 'show session all filter source
        <ip>' -- the raw session information for one source IP."""
        ip = validate_ip(source_ip)
        client = get_client(config)
        result = run_and_report(client, store, show_session_command(ip),
                                timeout=timeout)
        result["source_ip"] = ip
        return result

    @mcp.tool()
    def clear_session_by_id(store: int, session_id: str,
                            timeout: Optional[int] = None) -> dict:
        """Clear (drop) a single network session by session id, forcing it to
        be re-established. Use when a device misbehaves, e.g. a phone with
        one-way voice. Get the id from find_session_by_source."""
        command = clear_session_id_command(session_id)
        client = get_client(config)
        return run_and_report(client, store, command, timeout=timeout, parse=False)

    @mcp.tool()
    def clear_session_by_source(store: int, source_ip: str,
                                timeout: Optional[int] = None) -> dict:
        """Clear (drop) all network sessions for one source IP, forcing them to
        be re-established. Use for a single misbehaving device."""
        ip = validate_ip(source_ip)
        client = get_client(config)
        return run_and_report(client, store, clear_session_source_command(ip),
                              timeout=timeout, parse=False)

    @mcp.tool()
    def clear_sessions_by_subnet(store: int, subnet: str,
                                 timeout: Optional[int] = None) -> dict:
        """Clear all sessions for a source subnet (CIDR, e.g. 172.16.90.0/24).
        Use when ALL phones at a branch report voice issues, to clear the SIP
        sessions for every device at once."""
        cidr = validate_subnet(subnet)
        client = get_client(config)
        return run_and_report(client, store, clear_session_source_command(cidr),
                              timeout=timeout, parse=False)

    @mcp.tool()
    def clear_dhcp_sessions(store: int, timeout: Optional[int] = None) -> dict:
        """Clear all DHCP-application sessions on a branch firewall. Use when a
        device on the data network (computer, printer, mobile) will not obtain
        an IP address. Does not disrupt other traffic."""
        client = get_client(config)
        return run_and_report(client, store, "clear session all filter application dhcp",
                              timeout=timeout, parse=False)

    @mcp.tool()
    def diagnose_phone_session(store: int, source_ip: str,
                               timeout: Optional[int] = None) -> dict:
        """Convenience composite for voice/phone issues: runs
        ``show session all filter source <ip>`` and then
        ``show sdwan session path-select session-id <id>`` on the *same*
        persistent SSH session. Returns the session view (NAT/internet
        connection) plus any recent SD-WAN path changes."""
        n = validate_store(store)
        ip = validate_ip(source_ip)
        client = get_client(config)

        sessions = run_and_report(client, n, show_session_command(ip),
                                  timeout=timeout)
        result = {
            "store": n,
            "source_ip": ip,
            "session": sessions,
            "path_select": None,
            "path_select_skipped": None,
        }

        # Best-effort session id extraction from the raw CLI output (the
        # session table's "ID" column is not always cleanly parseable).
        session_id = extract_session_id(sessions.get("output") or "", ip)
        if not session_id:
            for row in (sessions.get("rows") or []):
                sid = (row.get("ID") or row.get("id") or "").strip()
                if sid.isdigit():
                    session_id = sid
                    break

        if not session_id:
            result["path_select_skipped"] = (
                "No session id found for this source IP (device may have no "
                "active session, or the output could not be parsed)."
            )
            return result

        path = run_and_report(client, n, f"show sdwan session path-select session-id {session_id}",
                              timeout=timeout)
        path["session_id"] = session_id
        output = path.get("output") or ""
        path["recent_path_changes"] = not ("not available" in output.lower()
                                           or "no recent" in output.lower())
        result["path_select"] = path
        return result