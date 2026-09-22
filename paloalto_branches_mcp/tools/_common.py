"""Shared helpers for tool implementations.

Includes PAN-OS input validation (values are interpolated into a CLI command,
so they must be tightly constrained), a lightweight parser for PAN-OS
dash-ruled tables, and the common result envelope returned by every tool.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional

from ..client import PaloClient, PaloAltoError

#: Matches a PAN-OS column-rule line, e.g. ``--    ----------  -----``.
_RULE_RE = re.compile(r"(?:-{2,}[ \t]*)+")
_DASH_GROUPS_RE = re.compile(r"-{2,}")

#: Fragments that indicate the CLI rejected a command (returned, not raised).
_ERROR_FRAGMENTS = (
    "invalid syntax",
    "unknown keyword",
    "not found",
    "no such",
    "unrecognized",
    "invalid value",
)


# --------------------------------------------------------------------- input
def validate_store(store) -> int:
    """Validate a store number (third octet, 1-254)."""
    from ..config import ConfigError, _coerce_store

    try:
        return _coerce_store(store)
    except ConfigError as exc:
        raise ValueError(str(exc)) from exc


def validate_ip(value: str) -> str:
    """Validate and normalise an IPv4 address."""
    try:
        return str(ipaddress.IPv4Address((value or "").strip()))
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"{value!r} is not a valid IPv4 address.") from exc


def validate_subnet(value: str) -> str:
    """Validate and normalise an IPv4 subnet in CIDR notation."""
    try:
        net = ipaddress.IPv4Network((value or "").strip(), strict=False)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"{value!r} is not a valid IPv4 subnet (CIDR).") from exc
    return str(net)


def validate_session_id(value) -> str:
    """Validate a PAN-OS session id (positive integer)."""
    s = str(value).strip()
    if not s.isdigit() or int(s) < 1:
        raise ValueError(f"{value!r} is not a valid session id (positive integer).")
    return s


_IFACE_RE = re.compile(r"^(?:ethernet|ae|vlan|loopback|tunnel|sdwan|redundant)[0-9]+(?:/[0-9]+)?(?:\.[0-9]+)?$")


def validate_interface(value: str) -> str:
    """Validate a PAN-OS interface name such as ``ethernet1/3.2090``."""
    s = (value or "").strip()
    if not _IFACE_RE.match(s):
        raise ValueError(
            f"{value!r} is not a valid interface name (e.g. 'ethernet1/3.2090')."
        )
    return s


def validate_policy_name(value: str) -> str:
    """Validate an SD-WAN policy name (interpolated inside double quotes)."""
    s = (value or "").strip()
    if not s:
        raise ValueError("policy_name must not be empty.")
    if len(s) > 128:
        raise ValueError("policy_name is unexpectedly long.")
    if any(ch in s for ch in ('"', "\\", "\n", "\r", "\t", ";", "|", "&", "$", "`")):
        raise ValueError(
            "policy_name contains characters that are not allowed in a CLI argument."
        )
    return s


def validate_show_command(value: str) -> str:
    """Validate a free-form, read-only ``show`` command."""
    s = (value or "").strip()
    if not s:
        raise ValueError("command must not be empty.")
    if len(s) > 512:
        raise ValueError("command is unexpectedly long.")
    if "\n" in s or "\r" in s:
        raise ValueError("command must be a single line.")
    if any(ch in s for ch in (";", "&", "$", "`", ">", "<")):
        raise ValueError("command contains characters that are not allowed.")
    if not s.lower().startswith(("show ", "show\n", "show\t")) and s.lower() != "show":
        raise ValueError(
            "Only read-only 'show' commands are allowed through this tool; "
            "use the dedicated tools for clear/action commands."
        )
    return s


# -------------------------------------------------------------------- parsing
def _is_rule(line: str) -> bool:
    s = line.strip()
    return len(s) >= 4 and bool(_RULE_RE.fullmatch(s.replace("\t", " ")))


def parse_tables(text: str) -> List[dict]:
    """Parse PAN-OS dash-ruled tables out of ``text``.

    PAN-OS renders tables as a header line, a rule line made of dash groups,
    then rows. The dash groups give the column boundaries, so each row can be
    sliced by the same offsets. Returns one entry per detected table:
    ``{"columns": [...], "rows": [{col: value, ...}, ...]}``.
    """
    lines = [ln.rstrip() for ln in (text or "").splitlines()]
    tables: List[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if _is_rule(line) and i > 0:
            header = lines[i - 1]
            spans = [(m.start(), m.end()) for m in _DASH_GROUPS_RE.finditer(line)]
            if len(spans) >= 2:
                names = []
                for idx, (start, _end) in enumerate(spans):
                    stop = spans[idx + 1][0] if idx + 1 < len(spans) else None
                    names.append(header[start:stop].strip())
                # Require most columns to carry a header name.
                if sum(1 for n in names if n) >= max(2, len(names) // 2):
                    rows: List[dict] = []
                    j = i + 1
                    while j < len(lines):
                        row_line = lines[j]
                        if not row_line.strip() or _is_rule(row_line):
                            break
                        row: Dict[str, str] = {}
                        for idx, (start, _end) in enumerate(spans):
                            stop = spans[idx + 1][0] if idx + 1 < len(spans) else None
                            value = row_line[start:stop].strip() if start < len(row_line) else ""
                            if names[idx]:
                                row[names[idx]] = value
                        if any(row.values()):
                            rows.append(row)
                        j += 1
                    tables.append({"columns": [n for n in names if n], "rows": rows})
                    i = j
                    continue
        i += 1
    return tables


_WS_COL_RE = re.compile(r"[A-Za-z0-9_/\-]+")


def _split_cols(line: str) -> List[str]:
    """Split a whitespace-aligned table line on runs of 2+ spaces."""
    return [c for c in re.split(r"\s{2,}", (line or "").strip()) if c]


def parse_whitespace_table(text: str) -> Optional[dict]:
    """Fallback parser for PAN-OS tables rendered without a dash rule line
    (e.g. ``show dhcp server lease``). Detects a header line of column names
    followed by >=2 rows with the same column count."""
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        header = _split_cols(line)
        if len(header) < 3:
            continue
        if not all(_WS_COL_RE.fullmatch(h) for h in header):
            continue
        rows: List[dict] = []
        j = i + 1
        while j < len(lines) and lines[j].strip():
            values = _split_cols(lines[j])
            if len(values) != len(header):
                break
            rows.append(dict(zip(header, values)))
            j += 1
        if len(rows) >= 2:
            return {"columns": header, "rows": rows}
    return None


def parse_table(text: str) -> List[dict]:
    """Return the rows of the first parseable table in ``text`` (or [])."""
    tables = parse_tables(text)
    if tables:
        return tables[0]["rows"]
    fallback = parse_whitespace_table(text)
    return fallback["rows"] if fallback else []


def output_looks_like_error(text: str) -> bool:
    low = (text or "").lower()
    return any(frag in low for frag in _ERROR_FRAGMENTS)


# --------------------------------------------------------------------- result
def run_and_report(client: PaloClient, store, command: str,
                   timeout: Optional[int] = None, parse: bool = True) -> dict:
    """Run ``command`` on ``store``'s firewall and return the result envelope.

    The envelope always carries the raw CLI ``output`` (what the agent needs)
    plus, when parseable, structured ``rows``.
    """
    n = validate_store(store)
    host = client.host_for_store(n)
    result: dict = {
        "store": n,
        "host": host,
        "command": command,
        "output": "",
        "rows": [],
        "ok": True,
    }
    try:
        raw = client.run(n, command, timeout=timeout)
    except PaloAltoError as exc:
        result["ok"] = False
        result["error"] = str(exc)
        return result
    result["output"] = raw
    if parse:
        result["rows"] = parse_table(raw)
    if output_looks_like_error(raw) and not result["rows"]:
        result["ok"] = False
        result["error"] = raw.strip().splitlines()[-1] if raw.strip() else "command failed"
    return result