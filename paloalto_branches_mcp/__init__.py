"""Palo Alto Branches MCP server.

Exposes NOC / helpdesk tools for Palo Alto Networks branch firewalls
("PaloAltoBranches") over the Model Context Protocol using FastMCP.

Each tool maps to one PAN-OS operational CLI command and is executed over a
*persistent* interactive SSH session to the branch firewall, so repeated tool
calls reuse the same login instead of re-authenticating per command.
"""

__version__ = "0.1.0"