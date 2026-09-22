"""DHCP tools.

``show dhcp server lease interface <iface>`` lists the leases handed out on a
branch voice/data VLAN. Match the MAC/hostname to a device serial to find a
phone's IP address.
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from fastmcp import FastMCP
    from ..config import PaloConfig

from ..client import get_client
from ._common import run_and_report, validate_interface


def dhcp_lease_command(interface: str) -> str:
    return f"show dhcp server lease interface {interface}"


def register(mcp: "FastMCP", config: "PaloConfig") -> None:

    @mcp.tool()
    def show_dhcp_leases(store: int, interface: str,
                         timeout: Optional[int] = None) -> dict:
        """Show DHCP server leases on a branch interface (e.g.
        'ethernet1/3.2090'). Returns the leased IP, MAC and hostname; match
        the MAC/hostname to the device serial to identify a phone's IP."""
        iface = validate_interface(interface)
        client = get_client(config)
        result = run_and_report(client, store, dhcp_lease_command(iface),
                                timeout=timeout)
        result["interface"] = iface
        return result