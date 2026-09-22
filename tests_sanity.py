"""Offline sanity tests for the Palo Alto Branches MCP server.

No real firewall or SSH server is required. The tests cover:
  * store-number -> management IP mapping and config validation
  * the keyboard-interactive login handler (acknowledgement + password)
  * prompt detection, command-echo stripping and pager handling
  * PAN-OS table parsing (dash-ruled and whitespace-aligned)
  * tool registration, argument validation and the exact CLI command each
    tool issues (the commands from the notes)
"""
import json
import unittest
from unittest import mock

from paloalto_branches_mcp.config import ConfigError, PaloConfig, load_config
from paloalto_branches_mcp.client import SSHShell, PaloClient
import paloalto_branches_mcp.client as clientmod


# --------------------------------------------------------------------- fakes
class FakeTransport:
    def __init__(self):
        self.handler = None
        self.used = None
        self._auth = False

    def auth_interactive(self, username, handler):
        self.used = ("interactive", username)
        self.handler = handler
        self._auth = True

    def auth_password(self, username, password):
        self.used = ("password", username, password)
        self._auth = True

    def is_authenticated(self):
        return self._auth


class FakeChannel:
    """Delivers scripted output only after the matching command is sent."""

    def __init__(self, script):
        self.script = script  # list of (substring, output_bytes)
        self.sent = []
        self.queue = []
        self.closed = False

    def send(self, data):
        self.sent.append(data)
        for needle, out in self.script:
            if needle in data:
                self.queue.append(out.encode())
                break

    def recv_ready(self):
        return bool(self.queue)

    def recv(self, n):
        return self.queue.pop(0)

    def settimeout(self, t):
        pass

    def get_pty(self, **kw):
        pass

    def invoke_shell(self):
        pass

    def close(self):
        self.closed = True


class FakeMCP:
    """Minimal stand-in for FastMCP that captures registered tool functions."""

    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco

    def custom_route(self, *args, **kwargs):
        def deco(fn):
            return fn
        return deco


def make_config(**kw):
    base = dict(username="aeadmin", password="pw",
                ip_template="10.102.{store}.250")
    base.update(kw)
    return PaloConfig(**base)


# ------------------------------------------------------------------ config
class ConfigTest(unittest.TestCase):
    def test_store_maps_to_third_octet(self):
        cfg = make_config()
        self.assertEqual(cfg.host_for_store(6), "10.102.6.250")
        self.assertEqual(cfg.host_for_store(22), "10.102.22.250")
        self.assertEqual(cfg.host_for_store("5"), "10.102.5.250")

    def test_store_validation(self):
        cfg = make_config()
        for bad in (0, 255, -1, "abc", None, ""):
            with self.assertRaises(ConfigError):
                cfg.host_for_store(bad)

    def test_bad_template_raises(self):
        cfg = make_config(ip_template="10.102.250")
        with self.assertRaises(ConfigError):
            cfg.host_for_store(6)

    def test_redacted_hides_password(self):
        cfg = make_config(password="secret")
        red = cfg.redacted()
        self.assertEqual(red["password"], "***REDACTED***")
        self.assertNotIn("secret", json.dumps(red))

    def test_load_config_requires_credentials(self):
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ConfigError):
                load_config()

    def test_load_config_from_env(self):
        env = {"PALO_USERNAME": "aeadmin", "PALO_PASSWORD": "pw",
               "PALO_IP_TEMPLATE": "10.102.{store}.250"}
        with mock.patch.dict("os.environ", env, clear=True):
            cfg = load_config()
        self.assertEqual(cfg.host_for_store(7), "10.102.7.250")


# ---------------------------------------------------------------- login flow
class LoginHandlerTest(unittest.TestCase):
    def test_handler_answers_statement_then_password(self):
        cfg = make_config(username="aeadmin", password="hunter2",
                          statement_response="yes")
        shell = SSHShell("10.102.5.250", cfg)
        transport = FakeTransport()
        shell._authenticate(transport, "interactive")

        self.assertEqual(transport.used[0], "interactive")
        responses = transport.handler(
            "Login", "",
            [("(aeadmin@10.102.5.250) Do you accept and acknowledge the "
              "statement above ? (yes/no) : ", False),
             ("(aeadmin@10.102.5.250) Password: ", False)],
        )
        self.assertEqual(responses, ["yes", "hunter2"])

    def test_handler_password_only_prompt(self):
        cfg = make_config(password="pw")
        shell = SSHShell("h", cfg)
        transport = FakeTransport()
        shell._authenticate(transport, "interactive")
        responses = transport.handler("", "", [("Password: ", False)])
        self.assertEqual(responses, ["pw"])

    def test_password_fallback(self):
        cfg = make_config(username="aeadmin", password="pw")
        shell = SSHShell("h", cfg)
        transport = FakeTransport()
        shell._authenticate(transport, "password")
        self.assertEqual(transport.used, ("password", "aeadmin", "pw"))


# ------------------------------------------------------------- ssh mechanics
class ShellRunTest(unittest.TestCase):
    def _shell(self, script):
        cfg = make_config(timeout=2, connect_timeout=2, pager_off=False)
        shell = SSHShell("10.102.8.250", cfg)
        shell._transport = mock.MagicMock()
        shell._transport.is_active.return_value = True
        shell._chan = FakeChannel(script)
        shell._chan.closed = False
        return shell

    def test_strips_echo_and_prompt(self):
        out = ("show vpn flow\r\n"
               "\r\n"
               "total tunnels configured: 1\r\n"
               "\r\n"
               "aeadmin@PA-08-Atlanta>")
        shell = self._shell([("show vpn flow", out)])
        result = shell.run("show vpn flow")
        self.assertEqual(result, "total tunnels configured: 1")

    def test_answers_pager_prompt(self):
        out = ("show x\r\n"
               "line1\r\n"
               "--- More ---"
               "line2\r\n"
               "aeadmin@PA-08-Atlanta>")
        shell = self._shell([("show x", out)])
        result = shell.run("show x")
        self.assertIn("line1", result)
        self.assertIn("line2", result)
        self.assertNotIn("More", result)
        self.assertIn(" ", shell._chan.sent)  # space sent to advance the pager

    def test_timeout_raises(self):
        from paloalto_branches_mcp.client import PaloAltoError
        shell = self._shell([])  # no output ever
        with self.assertRaises(PaloAltoError):
            shell.run("show nothing", timeout=1)


# ------------------------------------------------------------------- parsing
class ParsingTest(unittest.TestCase):
    VPN_SAMPLE = (
        "id    name                                                            state   monitor local-ip                                        peer-ip                                         tunnel-i/f  mode\n"
        "--    --------------                                                  -----   ------- --------                                        -------                                         ----------  ----\n"
        "2     tl_0101_023001001109_0101                                       active  up      50.168.130.178                                  74.204.122.83                                   tunnel.902  tunnel\n"
        "7     tl_0101_023001011216_A02                                        active  up      50.168.130.178                                  184.175.154.179                                 tunnel.900  tunnel\n"
        "8     tl_0102_023001011216_A02                                        active  down    50.176.10.233                                   184.175.154.179                                 tunnel.901  tunnel\n"
    )

    DHCP_SAMPLE = (
        'interface: "ethernet1/3.2090" id: 257\n'
        "Allocated IPs: 6, Total number of IPs in pool: 256. 2.3% used\n"
        "ip              mac                hostname                         state      duration    lease_time\n"
        "172.16.90.6     64:16:7f:e9:cb:97  Polycom64167fe9cb97              committed  0           Tue Sep 22 08:42:26 2026\n"
        "172.16.90.1     64:16:7f:e9:c9:93  Polycom64167fe9c993              committed  0           Tue Sep 22 08:42:23 2026\n"
    )

    def test_dash_ruled_table(self):
        from paloalto_branches_mcp.tools._common import parse_table, parse_tables
        rows = parse_table(self.VPN_SAMPLE)
        self.assertEqual(len(rows), 3)
        first = rows[0]
        self.assertEqual(first["id"], "2")
        self.assertEqual(first["name"], "tl_0101_023001001109_0101")
        self.assertEqual(first["state"], "active")
        self.assertEqual(first["monitor"], "up")
        self.assertEqual(first["local-ip"], "50.168.130.178")
        self.assertEqual(first["peer-ip"], "74.204.122.83")
        self.assertEqual(first["tunnel-i/f"], "tunnel.902")
        self.assertEqual(first["mode"], "tunnel")
        self.assertEqual(rows[2]["monitor"], "down")
        self.assertEqual(len(parse_tables(self.VPN_SAMPLE)), 1)

    def test_whitespace_table_fallback(self):
        from paloalto_branches_mcp.tools._common import parse_table
        rows = parse_table(self.DHCP_SAMPLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["ip"], "172.16.90.6")
        self.assertEqual(rows[0]["mac"], "64:16:7f:e9:cb:97")
        self.assertEqual(rows[0]["hostname"], "Polycom64167fe9cb97")
        self.assertEqual(rows[0]["lease_time"], "Tue Sep 22 08:42:26 2026")

    def test_no_table_returns_empty(self):
        from paloalto_branches_mcp.tools._common import parse_table
        self.assertEqual(parse_table("no table here\njust text"), [])

    def test_vpn_summary(self):
        from paloalto_branches_mcp.tools.vpn_tools import summarize_tunnels
        from paloalto_branches_mcp.tools._common import parse_table
        summary = summarize_tunnels(parse_table(self.VPN_SAMPLE))
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["up"], 2)
        self.assertEqual(summary["down"], 1)
        self.assertIn("tl_0102_023001011216_A02", summary["down_tunnels"])


# ------------------------------------------------------------ input validation
class ValidationTest(unittest.TestCase):
    def test_validators(self):
        from paloalto_branches_mcp.tools import _common as c
        self.assertEqual(c.validate_ip("172.16.90.1"), "172.16.90.1")
        self.assertEqual(c.validate_subnet("172.16.90.0/24"), "172.16.90.0/24")
        self.assertEqual(c.validate_session_id("261"), "261")
        self.assertEqual(c.validate_interface("ethernet1/3.2090"), "ethernet1/3.2090")
        self.assertEqual(c.validate_policy_name("Voice to Internet"), "Voice to Internet")

    def test_rejects_bad_values(self):
        from paloalto_branches_mcp.tools import _common as c
        for fn, bad in ((c.validate_ip, "999.1.1.1"),
                        (c.validate_subnet, "not-a-subnet"),
                        (c.validate_session_id, "0"),
                        (c.validate_interface, "rm -rf"),
                        (c.validate_policy_name, 'bad"; drop')):
            with self.assertRaises(ValueError):
                fn(bad)

    def test_run_show_command_only_allows_show(self):
        from paloalto_branches_mcp.tools import _common as c
        self.assertEqual(c.validate_show_command("show interface ethernet1/1"),
                         "show interface ethernet1/1")
        for bad in ("clear session all", "configure", "show x; rm", "show x\nclear y"):
            with self.assertRaises(ValueError):
                c.validate_show_command(bad)


# --------------------------------------------------------------- tool wiring
EXPECTED_COMMANDS = {
    "show_vpn_flow": "show vpn flow",
    "show_sdwan_connection": "show sdwan connection all",
    "list_sdwan_policies": "show sdwan policy",
    "sdwan_session_distribution": 'show sdwan session distribution policy-name "Voice to Internet"',
    "sdwan_session_path_select": "show sdwan session path-select session-id 261",
    "show_dhcp_leases": "show dhcp server lease interface ethernet1/3.2090",
    "find_session_by_source": "show session all filter source 172.16.90.1",
    "show_sessions": "show session all filter source 172.16.90.1",
    "clear_session_by_id": "clear session id 261",
    "clear_session_by_source": "clear session all filter source 172.16.90.1",
    "clear_sessions_by_subnet": "clear session all filter source 172.16.90.0/24",
    "clear_dhcp_sessions": "clear session all filter application dhcp",
    "run_show_command": "show interface ethernet1/1",
}

# Tool name -> kwargs for the invocation used to capture its command.
TOOL_CALLS = {
    "show_vpn_flow": {"store": 8},
    "show_sdwan_connection": {"store": 8},
    "list_sdwan_policies": {"store": 8},
    "sdwan_session_distribution": {"store": 8, "policy_name": "Voice to Internet"},
    "sdwan_session_path_select": {"store": 8, "session_id": "261"},
    "show_dhcp_leases": {"store": 8, "interface": "ethernet1/3.2090"},
    "find_session_by_source": {"store": 8, "source_ip": "172.16.90.1"},
    "show_sessions": {"store": 8, "source_ip": "172.16.90.1"},
    "clear_session_by_id": {"store": 8, "session_id": "261"},
    "clear_session_by_source": {"store": 8, "source_ip": "172.16.90.1"},
    "clear_sessions_by_subnet": {"store": 8, "subnet": "172.16.90.0/24"},
    "clear_dhcp_sessions": {"store": 8},
    "run_show_command": {"store": 8, "command": "show interface ethernet1/1"},
}

FAKE_OUTPUT = ("some header\n"
               "id    name    state\n"
               "--    ----    -----\n"
               "1     x       up\n"
               "\n"
               "aeadmin@PA-08-Atlanta>")


def registered_tools(config):
    from paloalto_branches_mcp.tools import register_all
    mcp = FakeMCP()
    register_all(mcp, config)
    return mcp.tools


class ToolWiringTest(unittest.TestCase):
    def test_all_notes_commands_map_to_tools(self):
        config = make_config()
        tools = registered_tools(config)
        captured = []

        def fake_run(self, store, command, timeout=None):
            captured.append((store, command))
            return FAKE_OUTPUT

        with mock.patch.object(clientmod.PaloClient, "run", fake_run):
            for tool_name, kwargs in TOOL_CALLS.items():
                self.assertIn(tool_name, tools, f"missing tool {tool_name}")
                tools[tool_name](**kwargs)

        issued = [c for (_s, c) in captured]
        for tool_name, expected in EXPECTED_COMMANDS.items():
            self.assertIn(expected, issued, f"{tool_name} did not issue {expected!r}")
        # Every captured command targets the requested store's host.
        self.assertTrue(all(s == 8 for (s, _c) in captured))

    def test_composite_reuses_one_session(self):
        config = make_config()
        tools = registered_tools(config)
        captured = []

        def fake_run(self, store, command, timeout=None):
            captured.append(command)
            if command.startswith("show session all filter source"):
                return ("show session all filter source 172.16.90.1\n"
                        "--------------------------------------------------------------------------------\n"
                        "ID          Application    State   Type Flag  Src[Sport]/Zone/Proto (translated IP[Port])\n"
                        "--------------------------------------------------------------------------------\n"
                        "261          SIP_override   ACTIVE  FLOW  NS   172.16.90.1[59319]/Voice/6  (50.168.130.178[37296])\n"
                        "aeadmin@PA-08-Atlanta>")
            return ("show sdwan session path-select session-id 261\n"
                    "Total path quality changes: 0\n"
                    "Recent path selection events not available\n"
                    "aeadmin@PA-08-Atlanta>")

        with mock.patch.object(clientmod.PaloClient, "run", fake_run):
            result = tools["diagnose_phone_session"](store=8, source_ip="172.16.90.1")

        self.assertIn("show session all filter source 172.16.90.1", captured)
        self.assertIn("show sdwan session path-select session-id 261", captured)
        self.assertIsNotNone(result["path_select"])
        self.assertFalse(result["path_select"]["recent_path_changes"])
        self.assertEqual(result["path_select"]["session_id"], "261")

    def test_result_envelope_on_connection_error(self):
        from paloalto_branches_mcp.client import PaloAltoError
        config = make_config()
        tools = registered_tools(config)

        def boom(self, store, command, timeout=None):
            raise PaloAltoError("connection refused")

        with mock.patch.object(clientmod.PaloClient, "run", boom):
            result = tools["show_vpn_flow"](store=8)
        self.assertFalse(result["ok"])
        self.assertIn("connection refused", result["error"])
        self.assertEqual(result["host"], "10.102.8.250")

    def test_host_for_store_via_client(self):
        client = PaloClient(make_config())
        self.assertEqual(client.host_for_store(22), "10.102.22.250")


class ServerBuildTest(unittest.TestCase):
    def test_build_server_registers_tools(self):
        try:
            from fastmcp import FastMCP  # noqa: F401
        except Exception:
            self.skipTest("fastmcp not installed")
        from paloalto_branches_mcp.server import build_server
        mcp = build_server(config=make_config())
        self.assertIsNotNone(mcp)


if __name__ == "__main__":
    unittest.main(verbosity=2)