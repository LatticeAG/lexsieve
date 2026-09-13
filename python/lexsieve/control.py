"""Local control socket (spec 12): an owner-only Unix domain socket next to
the SQLite receipt database. One JCS request per connection of at most
16384 bytes, one JCS response, then close; connections expire after
5000 ms and reload calls are processed serially.

On Linux the server verifies SO_PEERCRED against the service uid; on other
platforms owner-only semantics are enforced by the socket file mode (0600)
and operator-controlled directory ownership.
"""

import os
import socket
import struct
import threading

from .errors import ClosedError
from .ids import csprng_allocator
from .jcs import jcs, parse_json

CONTROL_MAX_REQUEST_BYTES = 16384
CONTROL_CONN_TIMEOUT_MS = 5000

_RETRYABLE = frozenset(
    {"NOT_READY", "RATE_LIMITED", "CHAIN_GAP", "STORAGE_UNAVAILABLE", "DEADLINE"}
)


def rpc_error(code, ids=None):
    ids = ids or csprng_allocator()
    return {
        "v": 1,
        "error": {
            "code": code,
            "retryable": code in _RETRYABLE,
            "request_id": ids.next("lsreq"),
        },
    }


def validate_control_request(v):
    if not isinstance(v, dict):
        raise ClosedError("INVALID_REQUEST", "control request")
    o = v
    if (
        sorted(o.keys()) != ["command", "config_path", "v"]
        or o["v"] != 1
        or o["command"] != "reload"
        or not isinstance(o["config_path"], str)
    ):
        raise ClosedError("INVALID_REQUEST", "control request")
    return {"v": 1, "command": "reload", "config_path": o["config_path"]}


def _peer_uid(conn):
    """Linux SO_PEERCRED; returns None where unsupported."""
    try:
        creds = conn.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        pid, uid, gid = struct.unpack("3i", creds)
        return uid
    except (AttributeError, OSError):
        return None


class ControlServer:
    """Owner-only control socket server. `on_reload(config_path)` returns
    the new active epoch."""

    def __init__(self, socket_path, config_dir, on_reload):
        self.socket_path = socket_path
        self.config_dir = os.path.realpath(config_dir)
        self.on_reload = on_reload
        self.ids = csprng_allocator()
        self._lock = threading.Lock()
        self._sock = None
        self._closed = threading.Event()

    def serve_forever(self):
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock = srv
        srv.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        srv.listen(8)
        srv.settimeout(0.25)
        while not self._closed.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def close(self):
        self._closed.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _reply(self, conn, body):
        try:
            conn.sendall((jcs(body) + "\n").encode("utf-8"))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle(self, conn):
        conn.settimeout(CONTROL_CONN_TIMEOUT_MS / 1000)
        try:
            uid = _peer_uid(conn)
            if uid is not None and uid != os.getuid():
                self._reply(conn, rpc_error("FORBIDDEN", self.ids))
                return
            chunks = []
            total = 0
            while True:
                try:
                    d = conn.recv(65536)
                except socket.timeout:
                    self._reply(conn, rpc_error("DEADLINE", self.ids))
                    return
                if not d:
                    break
                total += len(d)
                if total > CONTROL_MAX_REQUEST_BYTES:
                    self._reply(conn, rpc_error("INVALID_REQUEST", self.ids))
                    return
                chunks.append(d)
            try:
                req = validate_control_request(
                    parse_json(b"".join(chunks).decode("utf-8").rstrip("\r\n\t "))
                )
            except ClosedError as e:
                self._reply(conn, rpc_error(e.code, self.ids))
                return
            except Exception:
                self._reply(conn, rpc_error("INVALID_REQUEST", self.ids))
                return
            # reload calls are processed serially
            with self._lock:
                try:
                    p = os.path.realpath(req["config_path"])
                    if not os.path.isabs(req["config_path"]) or (
                        p != self.config_dir
                        and not p.startswith(self.config_dir + os.sep)
                    ):
                        self._reply(conn, rpc_error("FORBIDDEN", self.ids))
                        return
                    epoch = self.on_reload(p)
                    self._reply(conn, {"v": 1, "active_epoch": epoch})
                except ClosedError as e:
                    self._reply(conn, rpc_error(e.code, self.ids))
                except Exception:
                    self._reply(conn, rpc_error("INTERNAL", self.ids))
        finally:
            try:
                conn.close()
            except OSError:
                pass
