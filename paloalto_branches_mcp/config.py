"""Configuration and secure credential handling for the Palo Alto Branches MCP
server.

Credentials can be supplied from (in order of precedence):
  1. Explicit keyword arguments (e.g. when called programmatically)
  2. Environment variables (PALO_*)
  3. A JSON config file (PALO_CONFIG_FILE, or --config)

Password values are never logged, and config files are written with ``0600``
permissions when created via the ``config init`` wizard.

Addressing model
----------------
Branch firewalls are addressed by **store number**, which is the *third octet*
of the management IP. For example store 6 -> ``10.102.6.250`` and store 22 ->
``10.102.22.250``. The mapping is controlled by ``PALO_IP_TEMPLATE`` (default
``10.102.{store}.250``), so it can be re-pointed without code changes.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# Environment variable names
ENV_USERNAME = "PALO_USERNAME"
ENV_PASSWORD = "PALO_PASSWORD"
ENV_IP_TEMPLATE = "PALO_IP_TEMPLATE"
ENV_SSH_PORT = "PALO_SSH_PORT"
ENV_TIMEOUT = "PALO_TIMEOUT"
ENV_CONNECT_TIMEOUT = "PALO_CONNECT_TIMEOUT"
ENV_STATEMENT_RESPONSE = "PALO_STATEMENT_RESPONSE"
ENV_PAGER_OFF = "PALO_PAGER_OFF"
ENV_KNOWN_HOSTS = "PALO_KNOWN_HOSTS"
ENV_STRICT_HOST_KEY = "PALO_STRICT_HOST_KEY"
ENV_CONFIG_FILE = "PALO_CONFIG_FILE"
# Optional bearer token that gates the network MCP endpoints when set.
ENV_MCP_TOKEN = "PALO_MCP_AUTH_TOKEN"

DEFAULT_IP_TEMPLATE = "10.102.{store}.250"
DEFAULT_SSH_PORT = 22
DEFAULT_TIMEOUT = 60
DEFAULT_CONNECT_TIMEOUT = 15
#: Answer sent to the "Do you accept and acknowledge the statement above ?"
#: login prompt. The notes show ``yes``.
DEFAULT_STATEMENT_RESPONSE = "yes"

_PASSWORD_TAG = "***REDACTED***"

#: Matches the ``{store}`` placeholder (with optional format spec).
_STORE_PLACEHOLDER_RE = re.compile(r"\{store[^}]*\}")


@dataclass
class PaloConfig:
    """Resolved configuration for the Palo Alto branch firewall fleet."""

    username: str = ""
    password: str = ""
    #: ``str.format`` template producing the management IP from a store number.
    ip_template: str = DEFAULT_IP_TEMPLATE
    ssh_port: int = DEFAULT_SSH_PORT
    #: Per-command read timeout (seconds).
    timeout: int = DEFAULT_TIMEOUT
    #: TCP/SSH handshake + authentication timeout (seconds).
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT
    #: Response sent to the acknowledgement ("yes/no") login prompt.
    statement_response: str = DEFAULT_STATEMENT_RESPONSE
    #: Send ``set cli pager off`` right after login (per-session on PAN-OS).
    pager_off: bool = True
    #: Optional known_hosts file. When empty, host keys are accepted on first
    #: use (AutoAddPolicy) unless ``strict_host_key`` is set.
    known_hosts: str = ""
    strict_host_key: bool = False

    # --------------------------------------------------------------- helpers
    def host_for_store(self, store) -> str:
        """Return the management IP for a store number.

        ``store`` may be an int (6, 22) or a numeric string ("6", "22"). The
        store number is the third octet of the firewall's management address.
        """
        n = _coerce_store(store)
        if not _STORE_PLACEHOLDER_RE.search(self.ip_template or ""):
            raise ConfigError(
                "PALO_IP_TEMPLATE must contain a '{store}' placeholder; got "
                f"{self.ip_template!r}."
            )
        try:
            host = self.ip_template.format(store=n)
        except (KeyError, IndexError) as exc:  # pragma: no cover - config error
            raise ConfigError(
                f"PALO_IP_TEMPLATE is malformed: {self.ip_template!r}."
            ) from exc
        return host.strip()

    def redacted(self) -> dict:
        """Return a dict safe for logging (password redacted)."""
        d = asdict(self)
        d["password"] = _PASSWORD_TAG if d.get("password") else ""
        # Config-derived (non-secret) convenience field for the agent/UI.
        d["example_hosts"] = {
            "store 6": self.host_for_store(6) if self.ip_template else "",
            "store 22": self.host_for_store(22) if self.ip_template else "",
        }
        return d

    def is_complete(self) -> bool:
        return bool(self.username and self.password)

    @property
    def client_id(self) -> str:
        """Stable cache key for the shared client (no secrets)."""
        return f"{self.username}@{self.ip_template}"


class ConfigError(Exception):
    """Raised when configuration/credentials are missing or invalid."""


def _coerce_store(store) -> int:
    """Validate a store number (third octet) and return it as an int."""
    if isinstance(store, bool):  # bool is an int subclass; reject explicitly
        raise ConfigError("store must be a number between 1 and 254.")
    try:
        n = int(str(store).strip())
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"store must be a number between 1 and 254; got {store!r}.") from exc
    if not 1 <= n <= 254:
        raise ConfigError(f"store must be between 1 and 254 (third octet); got {n}.")
    return n


def _as_bool(value, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value, default: int) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def load_config(
    config_file: Optional[str] = None,
    *,
    username: Optional[str] = None,
    password: Optional[str] = None,
    ip_template: Optional[str] = None,
    ssh_port: Optional[int] = None,
    timeout: Optional[int] = None,
    connect_timeout: Optional[int] = None,
    statement_response: Optional[str] = None,
    pager_off: Optional[bool] = None,
    known_hosts: Optional[str] = None,
    strict_host_key: Optional[bool] = None,
) -> PaloConfig:
    """Load and merge configuration from kwargs, env and a config file.

    Raises :class:`ConfigError` if essential credentials are missing.
    """
    cfg = PaloConfig()

    # 1. Load from the well-known config file (env or explicit path).
    config_file = config_file or os.environ.get(ENV_CONFIG_FILE)
    if config_file and Path(config_file).exists():
        data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        for key in ("username", "password", "ip_template", "ssh_port",
                    "timeout", "connect_timeout", "statement_response",
                    "pager_off", "known_hosts", "strict_host_key"):
            if key in data and data[key] is not None:
                setattr(cfg, key, data[key])

    # 2. Environment variables override the file.
    if os.environ.get(ENV_USERNAME):
        cfg.username = os.environ[ENV_USERNAME].strip()
    if os.environ.get(ENV_PASSWORD):
        cfg.password = os.environ[ENV_PASSWORD]
    if os.environ.get(ENV_IP_TEMPLATE):
        cfg.ip_template = os.environ[ENV_IP_TEMPLATE].strip()
    if os.environ.get(ENV_SSH_PORT) is not None:
        cfg.ssh_port = _as_int(os.environ[ENV_SSH_PORT], cfg.ssh_port)
    if os.environ.get(ENV_TIMEOUT) is not None:
        cfg.timeout = _as_int(os.environ[ENV_TIMEOUT], cfg.timeout)
    if os.environ.get(ENV_CONNECT_TIMEOUT) is not None:
        cfg.connect_timeout = _as_int(os.environ[ENV_CONNECT_TIMEOUT], cfg.connect_timeout)
    if os.environ.get(ENV_STATEMENT_RESPONSE):
        cfg.statement_response = os.environ[ENV_STATEMENT_RESPONSE].strip()
    if os.environ.get(ENV_PAGER_OFF) is not None:
        cfg.pager_off = _as_bool(os.environ[ENV_PAGER_OFF], True)
    if os.environ.get(ENV_KNOWN_HOSTS):
        cfg.known_hosts = os.environ[ENV_KNOWN_HOSTS].strip()
    if os.environ.get(ENV_STRICT_HOST_KEY) is not None:
        cfg.strict_host_key = _as_bool(os.environ[ENV_STRICT_HOST_KEY], False)

    # 3. Explicit keyword arguments win.
    for name, val in (
        ("username", username), ("password", password),
        ("ip_template", ip_template), ("statement_response", statement_response),
        ("known_hosts", known_hosts),
    ):
        if val is not None:
            setattr(cfg, name, val.strip() if isinstance(val, str) else val)
    if ssh_port is not None:
        cfg.ssh_port = int(ssh_port)
    if timeout is not None:
        cfg.timeout = int(timeout)
    if connect_timeout is not None:
        cfg.connect_timeout = int(connect_timeout)
    if pager_off is not None:
        cfg.pager_off = bool(pager_off)
    if strict_host_key is not None:
        cfg.strict_host_key = bool(strict_host_key)

    if not cfg.is_complete():
        missing = [name for name, val in (("username", cfg.username),
                                          ("password", cfg.password)) if not val]
        raise ConfigError(
            "Incomplete Palo Alto credentials. Missing: " + ", ".join(missing)
            + ". Set PALO_USERNAME / PALO_PASSWORD env vars or run "
              "`python -m paloalto_branches_mcp config init --config <file>`."
        )

    # Fail fast on a malformed template (raises ConfigError).
    cfg.host_for_store(1)
    return cfg


def configure_interactive(config_file: str) -> str:
    """Prompt securely for credentials and write a 0600 config file.

    The password is requested with ``getpass`` so it is never echoed to the
    terminal, and the resulting file is only readable by the owner.
    """
    import getpass

    data = {}
    p = Path(config_file).expanduser()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = {}

    print("Palo Alto branch firewalls\n--------------------------")
    data["username"] = (input(
        f"SSH username [{data.get('username', '')}]: "
    ).strip() or data.get("username", ""))
    data["password"] = (getpass.getpass("SSH password: ")
                        or data.get("password", ""))
    data["ip_template"] = (input(
        f"Management IP template [{data.get('ip_template', DEFAULT_IP_TEMPLATE)}]: "
    ).strip() or data.get("ip_template", DEFAULT_IP_TEMPLATE))
    data["ssh_port"] = data.get("ssh_port", DEFAULT_SSH_PORT)
    data["statement_response"] = data.get("statement_response", DEFAULT_STATEMENT_RESPONSE)
    data["pager_off"] = data.get("pager_off", True)

    if not (data.get("username") and data.get("password")):
        raise ConfigError("username and password are required.")

    # Validate the template before writing it out.
    if not _STORE_PLACEHOLDER_RE.search(data.get("ip_template", "")):
        raise ConfigError("IP template must contain a '{store}' placeholder.")

    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)
    return str(p)