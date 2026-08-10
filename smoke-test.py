#!/usr/bin/env python3
"""Smoke test for the Bluetooth netplay matching server.

Speaks the emulator's wire protocol from several loopback source addresses, so
that the server sees the test clients as distinct peers (it deliberately never
reports a peer that shares the requester's address).

    python3 smoke-test.py [host] [port]
"""

from __future__ import annotations

import socket
import sys
import time

OPCODE_GET_PLAYERS = 0x04
OPCODE_NOTIFY_PLAYER_EXISTENCE = 0x05
OPCODE_SERVER_LOGIN = 0x09
OPCODE_SERVER_LOGOUT = 0x0A

failures = 0


class Peer:
    def __init__(self, host: str, port: int, source: str) -> None:
        family = socket.AF_INET6 if ":" in source else socket.AF_INET
        target = host if family == socket.AF_INET else ("::1" if host in ("127.0.0.1", "localhost") else host)

        self.source = source
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind((source, 0))
        self.sock.settimeout(5)
        self.sock.connect((target, port))

    def login(self, password: bytes) -> None:
        self.sock.sendall(bytes([OPCODE_SERVER_LOGIN, len(password)]) + password)

    def logout(self) -> None:
        self.sock.sendall(bytes([OPCODE_SERVER_LOGOUT]))

    def players(self) -> list[str]:
        self.sock.sendall(bytes([OPCODE_GET_PLAYERS]))
        head = self.recv_exactly(2)

        assert head[0] == OPCODE_NOTIFY_PLAYER_EXISTENCE, f"bad opcode {head[0]:#04x}"

        found = []
        for _ in range(head[1]):
            is_v4 = self.recv_exactly(1)[0]
            raw = self.recv_exactly(4 if is_v4 else 16)
            found.append(socket.inet_ntop(socket.AF_INET if is_v4 else socket.AF_INET6, raw))

        return sorted(found)

    def recv_exactly(self, count: int) -> bytes:
        buf = b""
        while len(buf) < count:
            chunk = self.sock.recv(count - len(buf))
            if not chunk:
                raise EOFError("server closed the connection")
            buf += chunk
        return buf

    def close(self) -> None:
        self.sock.close()


def check(name: str, got, want) -> None:
    global failures
    if got == want:
        print(f"  ok    {name}: {got}")
    else:
        failures += 1
        print(f"  FAIL  {name}: got {got}, want {want}")


def check_eventually(name: str, probe, want) -> None:
    """Like check(), for state the server only reaches once a peer's socket dies.

    A disconnect is not something the test can round-trip against, so poll.
    """
    deadline = time.monotonic() + 3
    got = probe()

    while got != want and time.monotonic() < deadline:
        time.sleep(0.1)
        got = probe()

    check(name, got, want)


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2] if len(sys.argv) > 2 else 27138)

    print(f"testing {host}:{port}")

    a = Peer(host, port, "127.0.0.2")
    b = Peer(host, port, "127.0.0.3")
    c = Peer(host, port, "127.0.0.4")

    a.login(b"smoke")
    check("alone in the room", a.players(), [])

    b.login(b"smoke")
    check("b sees a", b.players(), ["127.0.0.2"])
    check("a sees b", a.players(), ["127.0.0.3"])

    c.login(b"other")
    check("c is in its own room", c.players(), [])
    check("a does not see c", a.players(), ["127.0.0.3"])

    # A client that never logs in -- an emulator built before the login fix --
    # lands in the default room, not in a password-protected one.
    legacy = Peer(host, port, "127.0.0.5")
    check("legacy client sees nobody", legacy.players(), [])
    check("a still only sees b", a.players(), ["127.0.0.3"])

    v6 = None
    try:
        v6 = Peer(host, port, "::1")
    except OSError as err:
        print(f"  skip  IPv6 peer: {err}")

    if v6 is not None:
        v6.login(b"smoke")
        # This round trip is also the barrier that proves the login above landed
        # before the next query goes out on a different connection.
        check("IPv6 peer sees the room", v6.players(), ["127.0.0.2", "127.0.0.3"])
        check("a sees the IPv6 peer too", a.players(), ["127.0.0.3", "::1"])
        v6.close()
        check_eventually("IPv6 peer drops out after close", a.players, ["127.0.0.3"])

    b.logout()
    check("logout leaves b connected but hidden", b.players(), [])
    check("logout removes b from a's view", a.players(), [])

    b.login(b"smoke")
    check("re-login puts b back", b.players(), ["127.0.0.2"])
    check("a sees b again", a.players(), ["127.0.0.3"])

    b.close()
    check_eventually("disconnect removes b", a.players, [])

    bad = Peer(host, port, "127.0.0.6")
    bad.sock.sendall(bytes([0x7F]))
    try:
        check("unknown opcode hangs up", bad.sock.recv(16), b"")
    except OSError as err:
        check("unknown opcode hangs up", f"reset ({err})", "reset")
    bad.close()

    for peer in (a, c, legacy):
        peer.close()

    print("FAILED" if failures else "PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
