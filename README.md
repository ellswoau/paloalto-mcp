# Palo Alto Branches MCP Server (Python / FastMCP)

A [Model Context Protocol](https://modelcontextprotocol.io) server exposing
NOC / helpdesk troubleshooting tools for Palo Alto Networks **branch
firewalls** ("PaloAltoBranches"), built with Python `FastMCP`.

Every tool maps to a **PAN-OS operational CLI command** and is executed over a
**persistent SSH session** to the branch firewall, so several commands against
the same firewall reuse one login instead of re-authenticating each time.

> Works both as a direct `python -m` process **and** as a Docker container
> (see "Running via Docker").

## Addressing model (store number -> firewall)

Firewalls are addressed by **store number**, which is the **third octet** of
the management IP:

| Store | Management IP   |
|-------|-----------------|
| 6     | `10.102.6.250`  |
| 22    | `10.102.22.250` |
| 5     | `10.102.5.250`  |

The mapping is a template (`PALO_IP_TEMPLATE`, default `10.102.{store}.250`)
and can be re-pointed with an env var without code changes.

## Login flow (handled automatically)

The branch firewalls present a keyboard-interactive login. The client answers
the acknowledgement question with `yes`, then supplies the password, and waits
for the PAN-OS prompt:

```
You are logging in to a Weller-owned network device. ...
(aeadmin@10.102.5.250) Do you accept and acknowledge the statement above ? (yes/no) : yes
(aeadmin@10.102.5.250) Password:
Last login: Wed May 27 08:00:00 2026 from 10.201.80.16
aeadmin@PA-05-Grandville>
```

After login the client opens a shell channel, sends `set cli pager off`
(per-session on PAN-OS) and also answers any pager prompt defensively, so long
tables arrive in a single read.

## Tools

Each tool takes a `store` number (the third octet) and returns the raw CLI
`output` plus, where possible, parsed `rows` and a summary.

**Connectivity / session management**
- `palo_config` — redacted view of the configured environment
- `palo_ping` — open/reuse an SSH session and report the device hostname
- `palo_ssh_sessions` — list the persistent SSH sessions currently held
- `close_ssh_session` / `close_all_ssh_sessions` — drop sessions
- `run_show_command` — run any read-only `show` command (escape hatch)

**VPN**
- `show_vpn_flow` — `show vpn flow`: all IPSec tunnels up/down + summary

**SD-WAN**
- `show_sdwan_connection` — `show sdwan connection all`: link/state, with
  datacenter labels for known peer IPs (`74.204.122.83` = Grand Rapids
  primary DC, `184.175.154.179` = Indianapolis secondary DC)
- `list_sdwan_policies` — list SD-WAN traffic-steering policies
- `sdwan_session_distribution` — `show sdwan session distribution policy-name
  "<name>"`, tagged with which internet hand-off each link uses
- `sdwan_session_path_select` — `show sdwan session path-select session-id
  <id>`, flags recent path-quality changes

**DHCP**
- `show_dhcp_leases` — `show dhcp server lease interface <iface>` (e.g.
  `ethernet1/3.2090`): leased IP / MAC / hostname

**Sessions (find / clear)**
- `find_session_by_source` / `show_sessions` — `show session all filter source
  <ip>`: NAT translation + session id
- `clear_session_by_id` — `clear session id <id>`
- `clear_session_by_source` — `clear session all filter source <ip>`
- `clear_sessions_by_subnet` — `clear session all filter source <subnet>`
- `clear_dhcp_sessions` — `clear session all filter application dhcp`
- `diagnose_phone_session` — composite: session lookup **then** path-select on
  the same persistent session (for voice/phone issues)

**Meta**
- `palo_version` — server name/version

## Typical voice troubleshooting flow

1. `show_dhcp_leases(store, "ethernet1/3.2090")` — find the phone's IP; match
   the MAC/hostname to the device serial (RingCentral MCP or the last 4 digits
   on the phone).
2. `find_session_by_source(store, "172.16.90.1")` — see which internet
   connection (`ethernet1/1` primary / `ethernet1/2` secondary) the phone is
   NAT'd out of and note the **session id**.
3. `sdwan_session_path_select(store, "261")` — check for recent path changes
   (an internet quality issue / outage indicator).
4. `show_vpn_flow(store)` / `show_sdwan_connection(store)` — if tunnels are
   down, suspect the internet connection.
5. If the phone misbehaves (one-way voice, red buttons, not registered):
   `clear_session_by_id(store, "261")` or
   `clear_session_by_source(store, "172.16.90.1")`.
6. If **all** phones at a branch are affected:
   `clear_sessions_by_subnet(store, "172.16.90.0/24")`.
7. If a **data-network** device won't get an IP:
   `clear_dhcp_sessions(store)`.

## Requirements

- Python 3.9+ (tested on 3.12/3.14)
- Install: `pip install -r requirements.txt`

## Configuration (secure credentials)

Credentials are never hard-coded. Provide them via a config JSON file or
environment variables (precedence: explicit args > env > file).

### Option A — interactive wizard (recommended)

```bash
cd paloalto-branches-mcp
python -m paloalto_branches_mcp config init --config ./palo.json
```

This prompts for the SSH username and password (password entered without
echoing) and writes the file with `0600` owner-only permissions. Example:

```json
{
  "username": "aeadmin",
  "password": "…",
  "ip_template": "10.102.{store}.250",
  "ssh_port": 22,
  "statement_response": "yes",
  "pager_off": true
}
```

### Option B — environment variables

```bash
export PALO_USERNAME="aeadmin"
export PALO_PASSWORD="…"
export PALO_IP_TEMPLATE="10.102.{store}.250"   # default
export PALO_SSH_PORT="22"
export PALO_TIMEOUT="60"
export PALO_CONNECT_TIMEOUT="15"
export PALO_STATEMENT_RESPONSE="yes"
export PALO_PAGER_OFF="true"
export PALO_STRICT_HOST_KEY="false"
# export PALO_KNOWN_HOSTS="/etc/ssh/ssh_known_hosts"
export PALO_CONFIG_FILE="./palo.json"          # optional
```

A `.env` file is honored if `python-dotenv` is installed and loaded (see
`.env.example`). All `PALO_*` vars are defined in
`paloalto_branches_mcp/config.py`.

### Verify credentials before connecting to an MCP client

```bash
python -m paloalto_branches_mcp ping --store 5 --config ./palo.json
```

## Running the MCP server

```bash
# stdio transport (used by Claude Desktop / MCP clients)
PALO_CONFIG_FILE=./palo.json python -m paloalto_branches_mcp
```

### Example MCP client config (Claude Desktop `claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "paloalto-branches": {
      "command": "python",
      "args": ["-m", "paloalto_branches_mcp"],
      "env": {
        "PALO_CONFIG_FILE": "/abs/path/to/palo.json"
      }
    }
  }
}
```

## Running via Docker

The project ships a `Dockerfile`, `docker-compose.yml` and `.dockerignore`.

### Build

```bash
docker build -t paloalto-branches-mcp .
```

### Option A — stdio (embedded MCP client)

```bash
docker run -i --rm \
  -e PALO_CONFIG_FILE=/config/palo.json \
  -v "$(pwd)/palo.json:/config/palo.json:ro" \
  paloalto-branches-mcp
```

Or pass secrets via `-e`:

```bash
docker run -i --rm \
  -e PALO_USERNAME=aeadmin \
  -e PALO_PASSWORD='…' \
  -e PALO_IP_TEMPLATE='10.102.{store}.250' \
  paloalto-branches-mcp
```

> **File-permission note:** the container runs as an unprivileged user, so a
> mounted `palo.json` must be readable by it (env vars avoid the issue).

### Option B — network daemon (HTTP / SSE / streamable-http)

```bash
docker run -d --name palo-mcp -p 8000:8000 \
  -e PALO_CONFIG_FILE=/config/palo.json \
  -e PALO_MCP_AUTH_TOKEN="$PALO_MCP_AUTH_TOKEN" \
  -v "$(pwd)/palo.json:/config/palo.json:ro" \
  paloalto-branches-mcp --transport http --host 0.0.0.0 --port 8000
```

or with Compose (bundled):

```bash
export PALO_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
docker compose up -d --build
```

Then connect an MCP client that supports HTTP/SSE to
`http://<host>:8000/mcp`. Transports: `stdio` (default), `sse`,
`streamable-http`, `http`.

### Verify the daemon is up

```bash
curl -i http://localhost:8000/health        # HTTP 200 + JSON status (no creds)
curl -i http://localhost:8000/healthz       # alias
```

## Authentication (bearer token)

The network transport is gated behind a **bearer token** when configured. With
a token set, every endpoint except `/health` and `/healthz` requires
`Authorization: Bearer <token>` and returns `401` otherwise. Set it via
`PALO_MCP_AUTH_TOKEN` or `--token`:

```bash
export PALO_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
```

When unset/empty, auth is **disabled** (open) — preserving default behaviour.
The bundled `docker-compose.yml` *requires* the variable so daemon deployments
are secured by default. `/health` stays public for monitors.

## Persistent SSH sessions

- One interactive SSH shell is held **per firewall host**, created lazily on
  first use and reused by every subsequent tool call for that store.
- Sessions are health-checked; if a channel dies mid-command the client
  rebuilds it and retries the command once.
- `palo_ssh_sessions` lists them; `close_ssh_session` /
  `close_all_ssh_sessions` drop them. They also close on process exit.

## Security notes

- Passwords are never logged; `redacted()` masks them and config files are
  written `0600`.
- Host keys: by default the client accepts an unknown host key on first use
  (`AutoAddPolicy`). For production, point `PALO_KNOWN_HOSTS` at a managed
  known_hosts file and set `PALO_STRICT_HOST_KEY=true`.
- Tool arguments are strictly validated before being interpolated into a CLI
  command (IPv4/CIDR, session id, interface name, policy name, store number).
- `run_show_command` only permits read-only `show` commands.
- Mutating tools (`clear_*`) change live firewall state — use deliberately.

## Project layout

```
paloalto-branches-mcp/
├── README.md
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
├── .env.example
├── tests_sanity.py
└── paloalto_branches_mcp/
    ├── __init__.py
    ├── __main__.py          # python -m entrypoint
    ├── server.py            # FastMCP app + CLI (config init / ping / run)
    ├── config.py            # secure config & credential resolution
    ├── client.py            # persistent SSH client + shell session pool
    └── tools/
        ├── __init__.py      # registers all tool modules
        ├── _common.py       # validation, table parsing, result envelope
        ├── connection_tools.py
        ├── vpn_tools.py
        ├── sdwan_tools.py
        ├── session_tools.py
        └── dhcp_tools.py
```

## Notes / assumptions

- `list_sdwan_policies` uses `show sdwan policy`. The notes listed the
  configured SD-WAN policy names without showing the command that produced
  them; if a PAN-OS build names it differently, use `run_show_command` to run
  the correct `show` command, or adjust `sdwan_tools.py` (one line).
- The `clear session` commands from the notes are exposed as separate tools
  (`clear_session_by_id`, `clear_session_by_source`,
  `clear_sessions_by_subnet`, `clear_dhcp_sessions`).