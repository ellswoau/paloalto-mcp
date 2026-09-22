"""Connectivity, configuration and persistent-SSH-session management."""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from ..client import get_client
from ._common import run_and_report, validate_show_command, validate_store


def register(mcp: "FastMCP", config: "PaloConfig") -> None:

    @mcp.tool()
    def palo_config() -> dict:
        """Return a redacted description of the Palo Alto branch environment
        this server is configured for (SSH username, IP template, port,
        timeouts). Never includes the password."""
        return config.redacted()

    @mcp.tool()
    def palo_ping(store: int = 1) -> dict:
        """Verify connectivity and credentials by opening (or reusing) an SSH
        session to the firewall for ``store``. Returns the firewall host,
        device hostname and session details. Useful as a first sanity check."""
        client = get_client(config)
        n = validate_store(store)
        try:
            info = client.test_connection(n)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the agent
            return {"store": n, "host": client.host_for_store(n), "ok": False,
                    "error": str(exc)}
        return {"store": n, "ok": True, **info}

    @mcp.tool()
    def palo_ssh_sessions() -> list:
        """List the persistent SSH sessions this server currently holds, one
        per firewall. Shows host, PAN-OS device hostname, connected/idle time.
        Sessions persist across tool calls and are reused automatically."""
        client = get_client(config)
        return client.sessions()

    @mcp.tool()
    def close_ssh_session(store: int) -> dict:
        """Close the persistent SSH session to one firewall (``store``). The
        next tool call for that store will log in again."""
        client = get_client(config)
        n = validate_store(store)
        return {"store": n, **client.close(n)}

    @mcp.tool()
    def close_all_ssh_sessions() -> dict:
        """Close every persistent SSH session held by this server."""
        client = get_client(config)
        return {"closed_sessions": client.close_all()}

    @mcp.tool()
    def run_show_command(store: int, command: str, timeout: Optional[int] = None) -> dict:
        """Run a read-only PAN-OS ``show`` command on a branch firewall and
        return its output. Escape hatch for commands without a dedicated tool --
        the command must start with ``show``; ``clear``/config commands are
        rejected. Example: 'show interface ethernet1/1'."""
        cmd = validate_show_command(command)
        client = get_client(config)
        return run_and_report(client, store, cmd, timeout=timeout)