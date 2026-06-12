"""Shared JSON-RPC 2.0 client for the netblind Unix socket."""

from __future__ import annotations

import json
import socket
import threading
from typing import Any


SOCKET_TIMEOUT = 5.0


class NetblindError(Exception):
    """Base exception for netblind client errors."""


class DaemonNotRunning(NetblindError):
    """Raised when the netblind daemon is not reachable."""


class PermissionDenied(NetblindError):
    """Raised when the socket exists but access is denied."""


class RPCError(NetblindError):
    """Raised when the daemon returns a JSON-RPC error response."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"RPC error {code}: {message}")
        self.code = code
        self.message = message


class NetblindRPC:
    """Thread-safe JSON-RPC 2.0 client for the netblind daemon.

    Usage::

        with NetblindRPC() as rpc:
            stats = rpc.get_stats()
    """

    def __init__(self, socket_path: str = "/run/netblind.sock") -> None:
        self._socket_path = socket_path
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._id_counter = 0

    # ── context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> "NetblindRPC":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disconnect()

    # ── connection management ─────────────────────────────────────────────────

    def connect(self) -> None:
        """Open the Unix socket connection to the daemon."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect(self._socket_path)
            self._sock = sock
        except FileNotFoundError:
            raise DaemonNotRunning(
                "netblind daemon is not running. "
                "Start it with: sudo systemctl start netblind"
            )
        except PermissionError:
            raise PermissionDenied(
                f"Permission denied accessing {self._socket_path}. "
                "Add yourself to the 'netblind' group: sudo usermod -aG netblind $USER"
            )
        except OSError as exc:
            raise DaemonNotRunning(f"Cannot connect to daemon: {exc}") from exc

    def disconnect(self) -> None:
        """Close the socket connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _reconnect(self) -> None:
        """Disconnect and reconnect."""
        self.disconnect()
        self.connect()

    # ── low-level RPC ─────────────────────────────────────────────────────────

    def send(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """Send a JSON-RPC request and return the result.

        Raises DaemonNotRunning, PermissionDenied, or RPCError on failure.
        Automatically reconnects once if the connection was reset.
        """
        if params is None:
            params = {}

        with self._lock:
            self._id_counter += 1
            req_id = self._id_counter

            payload = json.dumps({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": req_id,
            }).encode() + b"\n"

            for attempt in range(2):
                try:
                    if self._sock is None:
                        self.connect()

                    self._sock.sendall(payload)  # type: ignore[union-attr]
                    raw = self._recv_response()
                    break
                except (ConnectionResetError, BrokenPipeError, OSError):
                    if attempt == 0:
                        self._reconnect()
                        continue
                    raise DaemonNotRunning(
                        "netblind daemon is not running. "
                        "Start it with: sudo systemctl start netblind"
                    )

        response = json.loads(raw)
        if "error" in response and response["error"] is not None:
            err = response["error"]
            raise RPCError(err.get("code", -1), err.get("message", "unknown error"))

        return response.get("result")

    def _recv_response(self) -> bytes:
        """Read a complete newline-terminated JSON response from the socket."""
        buf = b""
        assert self._sock is not None
        while b"\n" not in buf:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionResetError("daemon closed the connection")
            buf += chunk
        return buf.split(b"\n", 1)[0]

    # ── convenience methods ───────────────────────────────────────────────────

    def ping(self) -> dict[str, str]:
        """Check that the daemon is alive."""
        return self.send("ping")  # type: ignore[return-value]

    def get_connections(self) -> list[dict[str, Any]]:
        """Return the current active connection list."""
        return self.send("get_connections") or []  # type: ignore[return-value]

    def get_rules(self) -> list[dict[str, Any]]:
        """Return all persistent allow/block/ask rules."""
        return self.send("get_rules") or []  # type: ignore[return-value]

    def set_rule(self, app_path: str, action: str) -> None:
        """Set a rule for the given app path. action must be allow|block|ask."""
        if action not in ("allow", "block", "ask"):
            raise ValueError(f"action must be allow|block|ask, got {action!r}")
        self.send("set_rule", {"app_path": app_path, "action": action})

    def delete_rule(self, app_path: str) -> None:
        """Delete the rule for the given app path."""
        self.send("delete_rule", {"app_path": app_path})

    def get_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent traffic log entries."""
        return self.send("get_log", {"limit": limit}) or []  # type: ignore[return-value]

    def get_stats(self) -> dict[str, int]:
        """Return summary statistics: total_connections, blocked_today, allowed_today, apps_count."""
        return self.send("get_stats") or {}  # type: ignore[return-value]
