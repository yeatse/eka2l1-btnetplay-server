#!/usr/bin/env python3
"""Central matching server for EKA2L1 Bluetooth netplay.

The emulator's "proxy server" discovery mode (btnet-discovery-mode: 3) keeps one
TCP connection to this server for the whole session and uses it purely as a
rendezvous point: the server never carries game traffic, it only tells a client
the public IP addresses of the other clients that share its password. Everything
after that -- name queries, virtual Bluetooth address queries, L2CAP/RFCOMM
payloads -- goes directly peer to peer over UDP.

Wire protocol (see src/emu/services/.../btmidman_proxserv_matching.cpp):

    client -> server
        0x09 <len:u8> <password bytes>      log in / join the room named by the password
        0x04                                 give me the other players in my room
        0x0A                                 log out
        0x0B <port:u16>                      advertise UDP discovery port (new clients)

    server -> client
        0x0B 0x01                            port-extension capability, after login
        0x05 <count:u8> <entry>*             the other players in the room
        entry := 0x01 <ipv4:4 bytes>         network byte order
               | 0x00 <ipv6:16 bytes>        network byte order
               | 0x02 <ipv4:4> <port:u16>   extended entry, network byte order
               | 0x03 <ipv6:16> <port:u16>  extended entry, network byte order

The peer address is taken from the TCP connection, so a client never gets to
declare where it lives. Current clients advertise only their UDP discovery port;
legacy clients continue to use the fixed HARBOUR_PORT (35689).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import os
import signal
import socket
import struct
import sys

OPCODE_GET_PLAYERS = 0x04
OPCODE_NOTIFY_PLAYER_EXISTENCE = 0x05
OPCODE_SERVER_LOGIN = 0x09
OPCODE_SERVER_LOGOUT = 0x0A
OPCODE_SERVER_PORT_EXTENSION = 0x0B

DEFAULT_PORT = 27138

# MAX_INET_DEVICE_AROUND in the emulator: it drops everything past the tenth.
MAX_PLAYERS_IN_REPLY = 10

# The emulator walks the reply with a plain `char` cursor, so a reply longer than
# 127 bytes makes that cursor go negative and the parse loop runs off the packet.
# Seven IPv6 entries already reach the limit; stop before it.
MAX_REPLY_SIZE = 127

# The Qt netplay dialog caps the password at 16 characters, and the length is a
# single byte on the wire anyway.
MAX_PASSWORD_LENGTH = 32

MAX_ROOM_SIZE = 64
MAX_CONNECTIONS_PER_IP = 8
MAX_TOTAL_CONNECTIONS = 1024

# Nothing legitimate ever buffers more than a login packet's worth of bytes.
MAX_PENDING_BYTES = 256

# The emulator can sit silent on this socket for a whole play session, so the
# only way to notice a client that vanished is TCP keepalive.
KEEPALIVE_IDLE_S = 60
KEEPALIVE_INTERVAL_S = 20
KEEPALIVE_COUNT = 5

log = logging.getLogger("btnetplay")


class Client:
    __slots__ = ("writer", "ip", "packed", "is_v4", "password", "registered", "logged_out", "port", "tag")

    def __init__(self, writer: asyncio.StreamWriter, ip: ipaddress._BaseAddress, tag: str) -> None:
        self.writer = writer
        self.ip = ip
        self.is_v4 = isinstance(ip, ipaddress.IPv4Address)
        self.packed = ip.packed
        self.password = b""
        self.registered = False
        # Set by an explicit logout, so that a later query does not silently put
        # the client back in a room it asked to leave.
        self.logged_out = False
        self.port: int | None = None
        self.tag = tag

    def __repr__(self) -> str:  # pragma: no cover - logging only
        return self.tag


class MatchingServer:
    def __init__(self, allow_same_address: bool = False, same_address_override: ipaddress._BaseAddress | None = None) -> None:
        self.rooms: dict[bytes, list[Client]] = {}
        self.per_ip: dict[bytes, int] = {}
        self.total = 0
        self.allow_same_address = allow_same_address
        self.same_address_override = same_address_override

    # -- room bookkeeping ---------------------------------------------------

    def register(self, client: Client) -> None:
        if client.registered:
            return

        room = self.rooms.setdefault(client.password, [])
        if len(room) >= MAX_ROOM_SIZE:
            log.warning("%s: room %s is full, not registering", client, room_name(client.password))
            return

        room.append(client)
        client.registered = True
        log.info("%s: joined room %s (%d player(s))", client, room_name(client.password), len(room))

    def unregister(self, client: Client) -> None:
        if not client.registered:
            return

        room = self.rooms.get(client.password)
        client.registered = False

        if room is None:
            return

        try:
            room.remove(client)
        except ValueError:
            return

        if room:
            log.info("%s: left room %s (%d player(s))", client, room_name(client.password), len(room))
        else:
            del self.rooms[client.password]
            log.info("%s: left room %s (now empty)", client, room_name(client.password))

    def peers_of(self, client: Client) -> list[Client]:
        # A client that logged out, or that could not be admitted, is not part of
        # the room and does not get to see who is in it.
        if not client.registered:
            return []

        room = self.rooms.get(client.password, ())
        seen: set[tuple[bytes, int | None]] = {(client.packed, client.port)}
        peers: list[Client] = []

        for other in room:
            if other is client:
                continue

            # Legacy clients cannot distinguish endpoints that share an address.
            # Current clients can when they advertise different discovery ports.
            endpoint = (other.packed, other.port)
            if not self.allow_same_address:
                # Legacy clients cannot distinguish two peers at the same IP.
                # Extended clients can, provided their advertised ports differ.
                if other.packed == client.packed and (client.port is None or other.port is None):
                    continue
                if endpoint in seen:
                    continue

            seen.add(endpoint)

            peers.append(other)

        return peers

    # -- protocol -----------------------------------------------------------

    def build_player_list(self, client: Client) -> bytes:
        peers = self.peers_of(client)

        entries = bytearray()
        count = 0

        extended = client.port is not None
        for peer in peers:
            if count >= MAX_PLAYERS_IN_REPLY:
                break

            advertised_ip = peer.ip
            if self.same_address_override is not None and peer.ip == client.ip:
                advertised_ip = self.same_address_override

            if extended:
                is_v4 = isinstance(advertised_ip, ipaddress.IPv4Address)
                entry = (b"\x02" if is_v4 else b"\x03") + advertised_ip.packed + struct.pack("!H", peer.port or 35689)
            else:
                is_v4 = isinstance(advertised_ip, ipaddress.IPv4Address)
                entry = (b"\x01" if is_v4 else b"\x00") + advertised_ip.packed
            if 2 + len(entries) + len(entry) > MAX_REPLY_SIZE:
                break

            entries += entry
            count += 1

        if count < len(peers):
            log.info("%s: truncating player list to %d of %d", client, count, len(peers))

        log.debug("%s: advertising %d extended=%s endpoint(s): %s", client, count, extended, [
            (str(peer.ip), peer.port) for peer in peers[:count]
        ])
        return bytes(bytearray([OPCODE_NOTIFY_PLAYER_EXISTENCE, count])) + bytes(entries)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername")
        if not peername:
            writer.close()
            return

        ip = normalize_ip(peername[0])
        if ip is None:
            log.warning("rejecting connection from unparsable address %r", peername)
            writer.close()
            await wait_closed(writer)
            return

        tag = f"[{ip}]:{peername[1]}"

        if self.total >= MAX_TOTAL_CONNECTIONS:
            log.warning("%s: rejected, server is at %d connections", tag, self.total)
            writer.close()
            await wait_closed(writer)
            return

        if self.per_ip.get(ip.packed, 0) >= MAX_CONNECTIONS_PER_IP:
            log.warning("%s: rejected, address already has %d connections", tag, MAX_CONNECTIONS_PER_IP)
            writer.close()
            await wait_closed(writer)
            return

        enable_keepalive(writer.get_extra_info("socket"))

        client = Client(writer, ip, tag)
        self.total += 1
        self.per_ip[ip.packed] = self.per_ip.get(ip.packed, 0) + 1
        log.debug("%s: connected (%d total)", client, self.total)

        pending = bytearray()

        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                pending += data
                if len(pending) > MAX_PENDING_BYTES:
                    log.warning("%s: dropping, %d bytes of unparsed input", client, len(pending))
                    break

                if not await self.consume(client, pending):
                    break
        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            pass
        except OSError as err:
            log.debug("%s: socket error: %s", client, err)
        finally:
            self.unregister(client)
            self.total -= 1
            remaining = self.per_ip.get(ip.packed, 1) - 1
            if remaining > 0:
                self.per_ip[ip.packed] = remaining
            else:
                self.per_ip.pop(ip.packed, None)

            log.debug("%s: disconnected (%d total)", client, self.total)
            writer.close()
            await wait_closed(writer)

    async def consume(self, client: Client, pending: bytearray) -> bool:
        """Drain every complete message from `pending`. False means hang up."""
        while pending:
            opcode = pending[0]

            if opcode == OPCODE_SERVER_LOGIN:
                if len(pending) < 2:
                    return True

                length = pending[1]
                if length > MAX_PASSWORD_LENGTH:
                    log.warning("%s: login with a %d byte password, dropping", client, length)
                    return False

                if len(pending) < 2 + length:
                    return True

                password = bytes(pending[2 : 2 + length])
                del pending[: 2 + length]

                if client.registered and password != client.password:
                    self.unregister(client)

                client.password = password
                client.logged_out = False
                self.register(client)
                client.writer.write(bytes([OPCODE_SERVER_PORT_EXTENSION, 1]))
                await client.writer.drain()

            elif opcode == OPCODE_GET_PLAYERS:
                del pending[:1]

                # An emulator built before the login fix never sends 0x09 at all,
                # so a client that has not logged in yet joins the default room
                # here. One that logged out stays out until it logs back in.
                if not client.logged_out:
                    self.register(client)

                reply = self.build_player_list(client)
                log.info("%s: player list for room %s -> %d peer(s)", client, room_name(client.password), reply[1])

                client.writer.write(reply)
                await client.writer.drain()

            elif opcode == OPCODE_SERVER_LOGOUT:
                del pending[:1]
                client.logged_out = True
                self.unregister(client)

            elif opcode == OPCODE_SERVER_PORT_EXTENSION:
                if len(pending) < 3:
                    return True

                port = struct.unpack("!H", pending[1:3])[0]
                del pending[:3]
                if port == 0:
                    log.warning("%s: advertised invalid UDP port zero, dropping", client)
                    return False
                client.port = port
                log.debug("%s: advertised UDP discovery port %d", client, port)

            else:
                log.warning("%s: unknown opcode 0x%02X, dropping", client, opcode)
                return False

        return True


def room_name(password: bytes) -> str:
    if not password:
        return "<default>"

    try:
        return repr(password.decode("utf-8"))
    except UnicodeDecodeError:
        return repr(password)


def normalize_ip(host: str):
    # Link-local addresses arrive with a %scope suffix, and an IPv4 client on the
    # dual-stack listener arrives as ::ffff:a.b.c.d -- the emulator wants it back
    # as a plain 4 byte IPv4 entry.
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return None

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped

    return ip


def enable_keepalive(sock: socket.socket | None) -> None:
    if sock is None:
        return

    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE_S)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL_S)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError) as err:
        log.debug("could not set keepalive options: %s", err)


async def wait_closed(writer: asyncio.StreamWriter) -> None:
    try:
        await writer.wait_closed()
    except (OSError, asyncio.CancelledError):
        pass


def make_listen_socket(host: str, port: int) -> socket.socket:
    if host in ("::", ""):
        try:
            return socket.create_server(("::", port), family=socket.AF_INET6, dualstack_ipv6=True, backlog=128)
        except OSError as err:
            log.warning("no dual-stack IPv6 listener (%s), falling back to IPv4 only", err)
            return socket.create_server(("0.0.0.0", port), family=socket.AF_INET, backlog=128)

    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    return socket.create_server((host, port), family=family, backlog=128)


async def amain(args: argparse.Namespace) -> int:
    same_address_override = normalize_ip(args.same_address_override) if args.same_address_override else None
    if args.same_address_override and same_address_override is None:
        raise ValueError(f"invalid same-address override: {args.same_address_override!r}")

    server_state = MatchingServer(
        allow_same_address=args.allow_same_address,
        same_address_override=same_address_override,
    )
    if args.allow_same_address:
        log.info("reporting peers that share the requester's address")
    if same_address_override is not None:
        log.warning("rewriting same-address peers to %s (testing mode)", same_address_override)

    sock = make_listen_socket(args.host, args.port)

    server = await asyncio.start_server(server_state.handle, sock=sock)
    log.info("listening on %s", ", ".join(str(s.getsockname()) for s in server.sockets))

    stop = asyncio.get_running_loop().create_future()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, lambda: stop.done() or stop.set_result(None))
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass

    async with server:
        await stop

    log.info("shutting down")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="EKA2L1 Bluetooth netplay central matching server")
    parser.add_argument("--host", default=os.environ.get("BTNETPLAY_HOST", "::"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("BTNETPLAY_PORT", DEFAULT_PORT)))
    parser.add_argument("--log-level", default=os.environ.get("BTNETPLAY_LOG_LEVEL", "info"))
    parser.add_argument(
        "--allow-same-address",
        action="store_true",
        default=os.environ.get("BTNETPLAY_ALLOW_SAME_ADDRESS", "").lower() in ("1", "true", "yes"),
        help="report peers that share the requester's public address, including legacy/duplicate endpoints",
    )
    parser.add_argument(
        "--same-address-override",
        default=os.environ.get("BTNETPLAY_SAME_ADDRESS_OVERRIDE", ""),
        help="testing only: rewrite peers sharing the requester address to this IP",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

    return asyncio.run(amain(args))


if __name__ == "__main__":
    raise SystemExit(main())
