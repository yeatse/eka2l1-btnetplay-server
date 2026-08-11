# EKA2L1 Bluetooth netplay central server

A rendezvous server for [EKA2L1](https://github.com/EKA2L1/EKA2L1)'s *proxy
server* Bluetooth netplay discovery mode — the mode where every emulator holds a
TCP connection to one central host that introduces players to each other.

It carries no game traffic: it only tells each client the public IP endpoints of
the other clients that logged in with the same password. Everything after that —
device name queries, virtual Bluetooth address queries, L2CAP/RFCOMM payloads —
goes directly peer to peer over UDP.

## Why this exists when EKA2L1/btnet-server does

[`EKA2L1/btnet-server`](https://github.com/EKA2L1/btnet-server) implements the
protocol the emulator used in August 2022: ASCII `l0`/`l1`/`cr` over TCP, with
the server pushing the requester's address to the other peers over UDP. In March
2023 the emulator was rewritten onto the binary opcode protocol documented below
and the server was never updated, so the two have not been able to talk to each
other since. This server implements what the emulator actually sends today,
written against its client code.

## Running it

```sh
git clone https://github.com/yeatse/eka2l1-btnetplay-server
cd eka2l1-btnetplay-server
docker compose up -d --build
```

That listens on TCP 27138, dual-stack. Open the port on your firewall and point
a DNS record at the host.

Host networking is deliberate: the server's whole job is to report the public
address a client connected from, and Docker's IPv6 userland proxy would replace
every peer address with the bridge gateway.

### Pointing the emulator at it

Qt: *Bluetooth netplay* dialog. iOS: netplay settings. Or `config.yml` directly:

```yaml
btnet-discovery-mode: 3          # 3 = proxy server
bt-central-server-url: your.host.example
btnet-password: whatever-both-players-type
```

Everyone who types the same password ends up in the same room and sees each
other; different passwords are fully isolated. An empty password is a valid
room, shared with everybody else who left it empty.

### What the server cannot do for you

It only introduces peers. The UDP traffic that follows goes directly between
them, so each player must be reachable on UDP 35689 plus the virtual port range
starting at `btnet-port-offset` (default 15000, 60 ports). Behind NAT that means
UPnP (`enable-upnp: true`) or manual port forwarding; carrier-grade NAT and most
mobile networks will not work.

Both players also have to reach the server over the same address family, because
the family a client is advertised with is whichever one it used to connect here.
If your hostname has an AAAA record, dual-stack clients are advertised as IPv6
and an IPv4-only friend cannot reach them. Note that the emulator picks the AAAA
result and never falls back, so a stale AAAA breaks discovery outright.

## Wire protocol

```
client -> server
    0x09 <len:u8> <password>     log in, joining the room named by the password
    0x04                          list the other players in my room
    0x0A                          log out
    0x0B <port:u16>               advertise UDP discovery port (current clients)

server -> client
    0x0B 0x01                     port-extension capability, after login
    0x05 <count:u8> <entry>*
    entry := 0x01 <ipv4:4>        network byte order
           | 0x00 <ipv6:16>       network byte order
           | 0x02 <ipv4:4> <port:u16>
           | 0x03 <ipv6:16> <port:u16>
```

A client's address comes from its TCP connection, never from the client itself.
Current clients advertise their UDP discovery port after the server capability
message. Legacy clients remain compatible and use harbour port 35689.

Two details are forced by the client and worth keeping in any reimplementation:

- Replies are capped at 10 peers and 127 bytes. `MAX_INET_DEVICE_AROUND` is 10,
  and the emulator walks the reply with an 8-bit signed cursor that goes negative
  past 127 bytes — seven IPv6 entries are enough to hit that.
- By default, legacy peers sharing one address are filtered because they cannot
  distinguish endpoints. Current peers with distinct advertised ports can share
  one public address. `BTNETPLAY_ALLOW_SAME_ADDRESS=1` additionally disables the
  legacy and duplicate-endpoint filter.

Emulator builds without [the proxy-mode client
fixes](https://github.com/yeatse/EKA2L1/blob/ios/docs/bluetooth-netplay-central-server.md)
never send the login packet and mis-parse the player list. The server puts such a
client in the default room so it at least reaches the right code path, but it
cannot make the reply parse.

## Operations

```sh
docker compose ps
docker compose logs -f
git pull && docker compose up -d --build   # update
python3 smoke-test.py                      # protocol regression against localhost
```

`smoke-test.py` connects from several 127.0.0.0/8 source addresses so the server
treats the test clients as distinct peers. Plain script, no dependencies, does
not need the container rebuilt.

### Testing against a real emulator

`fake-peer.py` stands in for a second EKA2L1 instance: it logs in to a room and
answers the UDP queries (name, virtual Bluetooth address, port mapping) the
emulator sends to harbour port 35689 right after discovery. A guest Bluetooth
device search then lists it by name.

```sh
ufw allow 35689/udp                                  # only while testing
BTNETPLAY_ALLOW_SAME_ADDRESS=1 docker compose up -d
python3 fake-peer.py --server <public ip> --password room --name "Fake Nokia"
```

`BTNETPLAY_ALLOW_SAME_ADDRESS` switches off the remaining same-address and
duplicate-endpoint filter. This deployment keeps it enabled so same-source
clients are visible. `BTNETPLAY_SAME_ADDRESS_OVERRIDE` is a test-only escape
hatch for a matching server and emulators that share one host; it must not be set
for normal production traffic.

## Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `BTNETPLAY_HOST` | `::` | Bind address; `::` means dual-stack |
| `BTNETPLAY_PORT` | `27138` | TCP port the emulator expects |
| `BTNETPLAY_LOG_LEVEL` | `info` | `debug` also logs connects and disconnects |
| `BTNETPLAY_ALLOW_SAME_ADDRESS` | `0` | Also report legacy/duplicate peers sharing the requester address |
| `BTNETPLAY_SAME_ADDRESS_OVERRIDE` | empty | Testing only: rewrite same-address peers to this IP |

## License

MIT, see [LICENSE](./LICENSE).
