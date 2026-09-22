---
name: paloalto-branches
description: >-
  Troubleshoot Palo Alto branch firewalls ("PaloAltoBranches") via the
  PaloAltoBranches MCP server over persistent SSH. Covers IPSec VPN tunnel
  state, SD-WAN connection/policy/session distribution, DHCP leases, PAN-OS
  sessions, and clearing sessions for voice or DHCP problems. Firewalls are
  addressed by store number (the third octet of 10.102.<store>.250).
---

# Palo Alto Branch Firewall Troubleshooting

Use when a branch's network/voice/DHCP behaves badly — VPN tunnels down,
internet problems, phones with one-way voice or red/offline buttons, or a
device that will not get an IP. Pairs with the **PaloAltoBranches MCP server**,
which SSHes into the branch firewall and rotates through the PAN-OS commands
below. The SSH login persists across tool calls, so several commands on the
same store reuse one session.

## How to address a firewall

Pass the **store number** to every tool — it is the *third octet* of the
management IP:

| Store | Host            |
|-------|-----------------|
| 5     | `10.102.5.250`  |
| 6     | `10.102.6.250`  |
| 22    | `10.102.22.250` |

## Reference facts (memorise these)

- **Datacenters:** `74.204.122.83/28` = Grand Rapids (primary DC),
  `184.175.154.179/28` = Indianapolis (secondary DC).
- **Internet hand-offs:** `ethernet1/1` is the primary (fiber DIA),
  `ethernet1/2` is the secondary. Voice traffic *should* leave via `ethernet1/1`.
- **SD-WAN VIFs:** `sdwan.901` routes straight to the internet; `sdwan.902` /
  `sdwan.903` route to a datacenter — identify which by the tunnel's peer IP.
- **Tunnel names matter:** the `tl_<x>_<DC-id>_...` name tells you which
  datacenter a tunnel serves.
- **Phone subnet example:** `172.16.90.0/24` on `ethernet1/3.2090` (voice VLAN).

## STEP 1 — ORIENT (cheap, always first)

1. `palo_ping(store)` — confirms SSH reachability and returns the device
   hostname. If this fails, the branch may be offline; say so before digging.
2. `palo_config()` — redacted view of the environment (never shows the password).
3. `palo_ssh_sessions()` — see which firewalls you already hold a live session to.

Done when: you can name the firewall hostname and confirm the session is up.

## STEP 2 — PICK THE PLAYBOOK

### A. "The branch is having internet / VPN problems"

1. `show_vpn_flow(store)` — lists all IPSec tunnels and whether they are `up`.
   **If one or two tunnels are down, suspect the branch's internet connection.**
   The response includes an up/down `summary`.
2. `show_sdwan_connection(store)` — check the `ethernet1/1` / `ethernet1/2`
   link states and the `sdwan.9xx` paths. Rows are labelled with the datacenter
   when the peer IP is a known DC.
3. If both underlays look bad at multiple stores, escalate as a systemic/carrier
   issue with the evidence.

Done when: you can state which tunnels/links are down and whether it is
localised to one store or widespread.

### B. "Voice quality / phones are down at a branch"

1. Identify the phone. Either use the RingCentral MCP server, or ask the user
   for a photo of the phone / the last 4 digits of its serial.
2. `show_dhcp_leases(store, "ethernet1/3.2090")` — find the phone's IP by
   matching the MAC/hostname to the device serial.
3. `find_session_by_source(store, "<phone-ip>")` — shows the NAT translation:
   note which internet connection the phone is NAT'd out of, and **save the
   session id**.
4. `sdwan_session_path_select(store, "<session-id>")` — recent path-quality
   changes indicate an internet quality problem. `recent_path_changes: false`
   means no recent changes (good).
5. `sdwan_session_distribution(store, "Voice to Internet")` — confirm the share
   of voice sessions on `ethernet1/1` vs `ethernet1/2`. A significant share on
   `ethernet1/2` (secondary) indicates a problem.
6. **Fix it** if the phone misbehaves (one-way voice, red buttons, not
   registered): `clear_session_by_id(store, "<session-id>")`, or
   `clear_session_by_source(store, "<phone-ip>")`.
7. **All phones at the branch** affected: `clear_sessions_by_subnet(store,
   "172.16.90.0/24")` clears the SIP sessions for every device at once.

Done when: the phone has a fresh session and (re-checked) `find_session_by_source`
shows it NAT'd out of the expected connection.

### C. "A device won't get an IP address"

`clear_dhcp_sessions(store)` — clears only the DHCP-application sessions; safe
and non-disruptive for other traffic. Then re-check the device.

Done when: the DHCP sessions are cleared and the device obtains a lease
(`show_dhcp_leases`).

### D. Something not covered

`run_show_command(store, "show ...")` — the escape hatch for any **read-only**
`show` command (e.g. `show interface ethernet1/1`). `clear` and config commands
are rejected here; use the dedicated `clear_*` tools instead.

## STEP 3 — VERIFY, then report

- Re-run the relevant `show_*` tool after any change and quote the new state.
- Report store, firewall hostname, the command(s) run, and the evidence.
- Distinguish *one store* (local issue) from *several stores* (systemic).

## Pitfalls

- Never guess a phone's IP: always resolve it via DHCP lease (or the user's
  serial photo) first — clearing the wrong session disrupts someone else.
- The SD-WAN session table lists several rows per policy; the meaningful column
  is which `Link` (i.e. `ethernet1/1` vs `ethernet1/2`) carries the traffic.
- `show sdwan session path-select` returning "Recent path selection events not
  available" means *no recent changes* — that is a clean result, not an error.
- Tool inputs are validated (IP/CIDR, session id, interface, policy name,
  store). A rejected argument means the value was malformed — fix it, do not
  retry blindly.
- `list_sdwan_policies` runs `show sdwan policy`; if your PAN-OS build names it
  differently, use `run_show_command` with the correct `show` variant.
- Sessions persist; close them with `close_ssh_session(store)` (or
  `close_all_ssh_sessions()`) when you are finished with a firewall.
- Keep credentials out of everything you report.