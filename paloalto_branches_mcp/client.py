"""Persistent SSH client for Palo Alto branch firewalls (PAN-OS CLI).

One interactive SSH shell is kept per firewall (keyed by management IP) so
multiple tool calls reuse the same login session instead of re-authenticating
for every command. Sessions are created lazily on first use and are
health-checked; a dead channel is transparently rebuilt on the next call.

Login flow (the Weller branch firewalls)
----------------------------------------
::

    You are logging in to a Weller-owned network device. ...
    (aeadmin@10.102.5.250) Do you accept and acknowledge the statement above ? (yes/no) : yes
    (aeadmin@10.102.5.250) Password:
    ...
    aeadmin@PA-05-Grandville>

Both prompts are delivered by the SSH server as a *keyboard-interactive*
exchange, so the client answers the acknowledgement prompt with ``yes`` (see
``PALO_STATEMENT_RESPONSE``) and the password prompt with the configured
password. If the server offers only plain ``password`` auth, that is used as a
fallback.

After authentication a shell channel is opened and the client waits for the
PAN-OS operational prompt (``user@HOSTNAME>``). Because output paging is
enabled by default on PAN-OS, the client sends ``set cli pager off`` (a
per-session setting) and also answers any pager prompt defensively while
reading command output.
"""
from __future__ import annotations

import re
import socket
import threading
import time
from typing import Dict, List, Optional

import paramiko

from .config import PaloConfig, ConfigError

#: PAN-OS operational/configure prompt, e.g. ``aeadmin@PA-08-Atlanta>`` or
#: ``aeadmin@PA-08-Atlanta#`` (configuration mode).
_PROMPT_RE = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+[>#]\s*$")

#: Pager markers used by PAN-OS when output exceeds the terminal height.
_PAGER_RE = re.compile(r"(?:<)?-{2,}\s*More\s*-{2,}(?:>)?")

#: Login acknowledgement prompt fragments.
_ACK_FRAGMENTS = ("accept", "acknowledge", "yes/no", "statement")

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class PaloAltoError(Exception):
    """Raised for SSH/CLI errors talking to a firewall."""


class ConnectionLost(PaloAltoError):
    """Raised when the SSH channel/transport dies mid-command.

    The caller may safely reconnect and retry the command once.
    """


def _clean(text: str) -> str:
    """Normalise a raw terminal buffer into plain text."""
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # PAN-OS pads lines with trailing spaces; trim per line and drop the
    # synthetic blank lines the terminal emits.
    return "\n".join(line.rstrip() for line in text.split("\n"))


def _strip_command_echo(text: str, command: str) -> str:
    """Remove the echoed command line from the start of ``text``."""
    lines = text.split("\n")
    # Drop leading blank lines.
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].strip() == command.strip():
        lines.pop(0)
    # Drop blank lines the terminal emitted between the echo and the output.
    while lines and not lines[0].strip():
        lines.pop(0)
    # Trim a trailing prompt line.
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and _PROMPT_RE.match(lines[-1].strip()):
        lines.pop()
    # Trim trailing blank lines left after removing the prompt.
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


class SSHShell:
    """A single persistent interactive SSH session to one firewall."""

    def __init__(self, host: str, config: PaloConfig):
        self.host = host
        self.config = config
        self.hostname: Optional[str] = None  # PAN-OS device hostname (from prompt)
        self.created_at: float = 0.0
        self.last_used: float = 0.0
        self._transport: Optional[paramiko.Transport] = None
        self._chan: Optional[paramiko.Channel] = None
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- status
    def alive(self) -> bool:
        try:
            return bool(self._transport and self._transport.is_active()
                        and self._chan and not self._chan.closed)
        except Exception:  # pragma: no cover - defensive
            return False

    # ------------------------------------------------------------ connection
    def _build_transport(self) -> paramiko.Transport:
        cfg = self.config
        sock = socket.create_connection((self.host, cfg.ssh_port),
                                        timeout=cfg.connect_timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = cfg.connect_timeout
        transport.auth_timeout = cfg.connect_timeout
        transport.start_client(timeout=cfg.connect_timeout)
        return transport

    def _authenticate(self, transport: paramiko.Transport, method: str) -> None:
        """Authenticate ``transport`` using ``method`` ('interactive'|'password')."""
        cfg = self.config

        def handler(title, instructions, prompt_list):
            responses = []
            for idx, (prompt_text, _echo) in enumerate(prompt_list):
                low = (prompt_text or "").lower()
                if any(frag in low for frag in _ACK_FRAGMENTS):
                    responses.append(cfg.statement_response)
                elif "password" in low or "passcode" in low:
                    responses.append(cfg.password)
                elif idx == 0:
                    # Unknown first prompt is the acceptance statement.
                    responses.append(cfg.statement_response)
                else:
                    responses.append(cfg.password)
            return responses

        if method == "interactive":
            transport.auth_interactive(cfg.username, handler)
        else:
            transport.auth_password(cfg.username, cfg.password)

        if not transport.is_authenticated():
            raise PaloAltoError(f"SSH authentication to {self.host} did not complete.")

    def _open(self, method: str) -> None:
        cfg = self.config
        transport = self._build_transport()
        try:
            self._authenticate(transport, method)
            chan = transport.open_session()
            chan.get_pty(term="vt100", width=512, height=1000)
            chan.settimeout(cfg.connect_timeout)
            chan.invoke_shell()
        except Exception:
            try:
                transport.close()
            except Exception:
                pass
            raise

        self._transport = transport
        self._chan = chan

        # Wait for the initial prompt so the session is ready for commands.
        banner = self._read_until_prompt(timeout=cfg.connect_timeout)
        self.hostname = self._parse_hostname(banner)
        self.created_at = time.time()
        self.last_used = self.created_at

        # Disable per-session paging so long tables arrive in one read.
        if cfg.pager_off:
            try:
                self._run_locked("set cli pager off", timeout=cfg.timeout)
            except PaloAltoError:
                # Harmless if unsupported on this PAN-OS build.
                pass

    def connect(self) -> None:
        """(Re)establish the SSH session, trying interactive then password auth."""
        with self._lock:
            if self.alive():
                return
            self._teardown()

            last_err: Optional[Exception] = None
            for method in ("interactive", "password"):
                try:
                    self._open(method)
                    return
                except paramiko.AuthenticationException as exc:
                    last_err = exc
                    self._teardown()
                except (paramiko.SSHException, OSError) as exc:
                    last_err = exc
                    self._teardown()
            raise PaloAltoError(
                f"Could not open an SSH session to {self.host}:{self.config.ssh_port} "
                f"as {self.config.username!r}: {last_err}"
            )

    def close(self) -> None:
        with self._lock:
            self._teardown()

    def _teardown(self) -> None:
        for obj in (self._chan, self._transport):
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
        self._chan = None
        self._transport = None

    # ---------------------------------------------------------------- reading
    def _parse_hostname(self, banner: str) -> Optional[str]:
        m = re.search(r"@([A-Za-z0-9._-]+)[>#]", banner or "")
        return m.group(1) if m else None

    def _read_until_prompt(self, timeout: int) -> str:
        """Read from the shell channel until the PAN-OS prompt is seen."""
        chan = self._chan
        assert chan is not None
        deadline = time.time() + timeout
        buf = ""
        while True:
            if time.time() > deadline:
                # Return whatever we have rather than losing the banner; the
                # caller decides whether the session is usable.
                return _clean(buf)
            if chan.recv_ready():
                chunk = chan.recv(65536)
                if not chunk:
                    raise ConnectionLost(f"SSH channel to {self.host} closed unexpectedly.")
                buf += chunk.decode("utf-8", "replace")
                buf = self._handle_pager(chan, buf)
                continue
            if _PROMPT_RE.search(_clean(buf).rstrip("\n")):
                # Give the terminal a moment to flush anything trailing.
                if not chan.recv_ready():
                    time.sleep(0.05)
                    if not chan.recv_ready():
                        return _clean(buf)
            else:
                time.sleep(0.05)

    def _handle_pager(self, chan: paramiko.Channel, buf: str) -> str:
        """Answer a PAN-OS pager prompt by sending a space, returning clean buf."""
        m = _PAGER_RE.search(buf)
        if m:
            try:
                chan.send(" ")
            except Exception as exc:  # pragma: no cover - defensive
                raise ConnectionLost(f"SSH channel to {self.host} died sending pager key: {exc}")
            buf = buf[:m.start()] + buf[m.end():]
        return buf

    # -------------------------------------------------------------- execution
    def run(self, command: str, timeout: Optional[int] = None) -> str:
        """Run one CLI command on the persistent shell and return its output."""
        with self._lock:
            if not self.alive():
                self.connect()
            return self._run_locked(command, timeout=timeout)

    def _run_locked(self, command: str, timeout: Optional[int] = None) -> str:
        cmd = (command or "").strip()
        if not cmd:
            raise PaloAltoError("Empty command.")
        timeout = timeout or self.config.timeout
        chan = self._chan
        if chan is None:
            raise ConnectionLost(f"No SSH channel to {self.host}.")

        # Clear any stale/unsolicited bytes left over from a previous command.
        self._drain(chan, grace=0.2)

        try:
            chan.send(cmd + "\n")
        except Exception as exc:
            raise ConnectionLost(f"SSH channel to {self.host} died: {exc}")

        raw = self._read_command(chan, cmd, timeout)
        self.last_used = time.time()
        return _strip_command_echo(raw, cmd)

    def _read_command(self, chan: paramiko.Channel, cmd: str, timeout: int) -> str:
        deadline = time.time() + timeout
        buf = ""
        while True:
            if time.time() > deadline:
                raise PaloAltoError(
                    f"Timed out after {timeout}s waiting for output of {cmd!r} "
                    f"on {self.host}."
                )
            if chan.recv_ready():
                chunk = chan.recv(65536)
                if not chunk:
                    raise ConnectionLost(f"SSH channel to {self.host} closed during {cmd!r}.")
                buf += chunk.decode("utf-8", "replace")
                buf = self._handle_pager(chan, buf)
                continue
            if _PROMPT_RE.search(_clean(buf).rstrip("\n")):
                if not chan.recv_ready():
                    time.sleep(0.05)
                    if not chan.recv_ready():
                        return _clean(buf)
            else:
                time.sleep(0.05)

    @staticmethod
    def _drain(chan: paramiko.Channel, grace: float = 0.2) -> None:
        end = time.time() + grace
        while time.time() < end:
            if chan.recv_ready():
                try:
                    chan.recv(65536)
                except Exception:
                    return
            else:
                time.sleep(0.02)

    # ------------------------------------------------------------------ info
    def describe(self) -> dict:
        now = time.time()
        return {
            "host": self.host,
            "device_hostname": self.hostname,
            "username": self.config.username,
            "port": self.config.ssh_port,
            "connected": self.alive(),
            "connected_seconds": int(now - self.created_at) if self.created_at else 0,
            "idle_seconds": int(now - self.last_used) if self.last_used else 0,
        }


class PaloClient:
    """Holds persistent :class:`SSHShell` sessions, one per firewall host."""

    def __init__(self, config: PaloConfig):
        self.config = config
        self._shells: Dict[str, SSHShell] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------- addressing
    def host_for_store(self, store) -> str:
        return self.config.host_for_store(store)

    def shell(self, store) -> SSHShell:
        """Return a live shell for ``store``, connecting on first use."""
        host = self.host_for_store(store)
        with self._lock:
            shell = self._shells.get(host)
            if shell is None or not shell.alive():
                if shell is not None:
                    shell.close()
                shell = SSHShell(host, self.config)
                self._shells[host] = shell
        shell.connect()
        return shell

    # -------------------------------------------------------------- execution
    def run(self, store, command: str, timeout: Optional[int] = None) -> str:
        """Run ``command`` on ``store``'s firewall, reusing its SSH session."""
        shell = self.shell(store)
        try:
            return shell.run(command, timeout=timeout)
        except ConnectionLost:
            # Session died mid-command: rebuild once and retry.
            shell.close()
            shell = self.shell(store)
            return shell.run(command, timeout=timeout)

    def run_many(self, store, commands: List[str],
                 timeout: Optional[int] = None) -> List[dict]:
        """Run several commands over the *same* persistent session."""
        results = []
        for cmd in commands:
            results.append({"command": cmd, "output": self.run(store, cmd, timeout=timeout)})
        return results

    # ----------------------------------------------------------- inspection
    def sessions(self) -> List[dict]:
        with self._lock:
            shells = list(self._shells.values())
        return [s.describe() for s in shells]

    def close(self, store) -> dict:
        host = self.host_for_store(store)
        with self._lock:
            shell = self._shells.pop(host, None)
        if shell is None:
            return {"host": host, "closed": False, "reason": "no active session"}
        shell.close()
        return {"host": host, "closed": True}

    def close_all(self) -> int:
        with self._lock:
            shells = list(self._shells.values())
            self._shells.clear()
        for s in shells:
            s.close()
        return len(shells)

    def test_connection(self, store) -> dict:
        """Open a session for ``store`` and return basic connectivity info."""
        shell = self.shell(store)
        info = shell.describe()
        info["ok"] = True
        return info


# Registry so tools share one client per resolved config (keyed, no secrets).
_client_registry: Dict[str, PaloClient] = {}
_registry_lock = threading.Lock()


def get_client(config: PaloConfig) -> PaloClient:
    key = config.client_id
    with _registry_lock:
        client = _client_registry.get(key)
        if client is None or client.config != config:
            client = PaloClient(config)
            _client_registry[key] = client
        return client


def clear_client(key: str) -> None:
    with _registry_lock:
        client = _client_registry.pop(key, None)
    if client:
        try:
            client.close_all()
        except Exception:
            pass


__all__ = [
    "PaloAltoError",
    "ConnectionLost",
    "SSHShell",
    "PaloClient",
    "get_client",
    "clear_client",
    "ConfigError",
]