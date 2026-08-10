#!/usr/bin/env python3
"""A stand-in for a second EKA2L1 instance, for testing the matching server.

It logs in to the central server so that a real emulator discovers it, and
answers the UDP queries the emulator sends straight afterwards (harbour port
35689): device name, virtual Bluetooth address, and the virtual/real port
mapping. A guest Bluetooth device search should list it by name.

    python3 fake-peer.py --server btnetplay.yeatse.com --password room [--name "Fake Nokia"]
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import threading

OPCODE_GET_NAME = 0x00
OPCODE_GET_VIRTUAL_BLUETOOTH_ADDRESS = 0x01
OPCODE_IS_REAL_PORT_MAPPED = 0x02
OPCODE_GET_REAL_PORT_FROM_VIRTUAL_PORT = 0x03
OPCODE_GET_PLAYERS = 0x04
OPCODE_SERVER_LOGIN = 0x09
OPCODE_SERVER_LOGOUT = 0x0A
OPCODE_RESULT_START = 100

HARBOUR_PORT = 35689

log = logging.getLogger("fake-peer")


def serve_queries(port: int, name: str, device_address: bytes, port_offset: int) -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    log.info("answering Bluetooth queries on UDP %d as %r", port, name)

    while True:
        data, sender = sock.recvfrom(2048)
        if len(data) < 5:
            continue

        asker_id = data[:4]
        opcode = data[4]
        reply = None

        if opcode == OPCODE_GET_NAME:
            encoded = name.encode("utf-8")
            reply = asker_id + bytes([OPCODE_RESULT_START + opcode, len(encoded)]) + encoded

        elif opcode == OPCODE_GET_VIRTUAL_BLUETOOTH_ADDRESS:
            reply = asker_id + bytes([OPCODE_RESULT_START + opcode]) + device_address

        elif opcode == OPCODE_IS_REAL_PORT_MAPPED and len(data) >= 9:
            real_port = struct.unpack_from("<I", data, 5)[0]
            mapped = port_offset <= real_port < port_offset + 60
            reply = asker_id + bytes([OPCODE_RESULT_START + opcode]) + (b"1" if mapped else b"0")

        elif opcode == OPCODE_GET_REAL_PORT_FROM_VIRTUAL_PORT and len(data) >= 7:
            virtual_port = struct.unpack_from("<H", data, 5)[0]
            real_port = 0 if virtual_port == 0 else port_offset + virtual_port - 1
            reply = asker_id + bytes([OPCODE_RESULT_START + opcode]) + struct.pack("<I", real_port)

        if reply is None:
            log.warning("unhandled query opcode %d from %s", opcode, sender[0])
            continue

        log.info("query opcode %d from %s -> %d byte reply", opcode, sender[0], len(reply))
        sock.sendto(reply, sender)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fake EKA2L1 Bluetooth netplay peer")
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--server-port", type=int, default=27138)
    parser.add_argument("--password", default="")
    parser.add_argument("--name", default="Fake Peer")
    parser.add_argument("--harbour-port", type=int, default=HARBOUR_PORT)
    parser.add_argument("--port-offset", type=int, default=15000)
    parser.add_argument("--device-address", default="02:00:de:ad:be:ef")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    device_address = bytes(int(part, 16) for part in args.device_address.split(":")) + b"\x00\x00"
    assert len(device_address) == 8, "device address must be 6 hex octets"

    threading.Thread(
        target=serve_queries,
        args=(args.harbour_port, args.name, device_address, args.port_offset),
        daemon=True,
    ).start()

    password = args.password.encode("utf-8")
    sock = socket.create_connection((args.server, args.server_port), 10)
    log.info("logged in to %s:%d from %s, room %r", args.server, args.server_port, sock.getsockname()[0], args.password)
    sock.sendall(bytes([OPCODE_SERVER_LOGIN, len(password)]) + password)

    try:
        while True:
            # Ask for players now and then, so the server log shows both directions.
            sock.sendall(bytes([OPCODE_GET_PLAYERS]))
            sock.settimeout(30)
            try:
                reply = sock.recv(256)
            except TimeoutError:
                continue

            if not reply:
                log.warning("server closed the connection")
                return 1

            log.info("player list: %s", reply.hex())
            threading.Event().wait(15)
    except KeyboardInterrupt:
        sock.sendall(bytes([OPCODE_SERVER_LOGOUT]))
        sock.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
