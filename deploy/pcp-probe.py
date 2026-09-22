#!/usr/bin/env python3
"""A PCP and NAT-PMP client probe (RFC 6887 / RFC 6886).

Stdlib only, no dependencies: it builds the datagrams the way the RFCs
lay them out and prints what comes back, so the daemon's answers can be
read against the specification rather than against the daemon's own
codec. It is the client tool plan/0009's `#pcp` verification line asks
for, and it is written to be run from another host on the LAN:

    ./pcp-probe.py 192.168.21.1 --int-port 3074

Each step prints one line per datagram sent: what was sent, what came
back, and the result code by name. A request that answers nothing is
printed as a drop, which is what a mapping whose discovery is still in
flight must look like: the client's own retransmission is the recovery
the protocol provides, so a MAP is retried once after four seconds.

Result codes are the RFC 6877 section 7.4 numbering, which is the one
the daemon ships (the implementation notes' compressed table was wrong).
"""
import argparse
import socket
import struct
import sys
import time

VERSION = 2
OP_ANNOUNCE, OP_MAP, OP_PEER = 0, 1, 2
OPT_THIRD_PARTY, OPT_PREFER_FAILURE, OPT_FILTER = 1, 2, 3

RC = {
    0: "SUCCESS",
    1: "UNSUPP_VERSION",
    2: "NOT_AUTHORIZED",
    3: "MALFORMED_REQUEST",
    4: "UNSUPP_OPCODE",
    5: "UNSUPP_OPTION",
    6: "MALFORMED_OPTION",
    7: "NETWORK_FAILURE",
    8: "NO_RESOURCES",
    9: "UNSUPP_PROTOCOL",
    10: "USER_EX_QUOTA",
    11: "CANNOT_PROVIDE_EXTERNAL",
    12: "ADDRESS_MISMATCH",
    13: "EXCESSIVE_REMOTE_PEERS",
}

NP = {0: "SUCCESS", 1: "UNSUPP_VERSION", 2: "NOT_AUTHORIZED", 3: "NETWORK_FAILURE",
      4: "NO_RESOURCES", 5: "UNSUPP_OPCODE"}

NONCE = bytes.fromhex("0f1e2d3c4b5a69788796a5b4")


def mapped(ip):
    return b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ip)


def pcp_header(opcode, lifetime, client):
    return struct.pack("!BBHI", VERSION, opcode, 0, lifetime) + mapped(client)


def pcp_map_body(proto, int_port, sug_port, sug_ip="0.0.0.0"):
    return (NONCE + bytes([proto]) + b"\x00" * 3
            + struct.pack("!HH", int_port, sug_port) + mapped(sug_ip))


def option(code, payload):
    pad = (-len(payload)) % 4
    return bytes([code, 0]) + struct.pack("!H", len(payload)) + payload + b"\x00" * pad


def send(sock, payload, wait=4.0):
    # The socket is connected, so the kernel picks the source address and the
    # probe can name it in the PCP client field: a request whose field does
    # not match the source it arrives with earns ADDRESS_MISMATCH, which is
    # the rule the server must apply (RFC 6887 section 8.2).
    sock.send(payload)
    sock.settimeout(wait)
    try:
        return sock.recv(2048)
    except socket.timeout:
        return None


def show_pcp(name, resp, sent_at):
    if resp is None:
        print(f"{name}: no answer (drop) after {time.time() - sent_at:.1f}s")
        return None
    if len(resp) < 24 or resp[0] != VERSION:
        print(f"{name}: not a PCP response: {resp.hex()}")
        return None
    opcode = resp[1] & 0x7F
    code = resp[3]
    lifetime, epoch = struct.unpack("!II", resp[4:12])
    line = f"{name}: opcode {opcode} code {code} ({RC.get(code, '?')}) lifetime {lifetime} epoch {epoch}"
    if opcode in (OP_MAP, OP_PEER) and len(resp) >= 60:
        proto = resp[36]
        int_port, ext_port = struct.unpack("!HH", resp[40:44])
        ext_ip = ".".join(str(b) for b in resp[56:60])
        line += f" proto {proto} internal {int_port} assigned {ext_ip}:{ext_port}"
    print(line)
    return resp


def natpmp(sock, op, body=b""):
    req = bytes([0, op]) + b"\x00\x00" + body
    resp = send(sock, req, wait=2.0)
    name = f"NAT-PMP op {op}"
    if resp is None:
        print(f"{name}: no answer")
        return None
    code = struct.unpack("!H", resp[2:4])[0]
    epoch = struct.unpack("!I", resp[4:8])[0]
    line = f"{name}: op {resp[1]} code {code} ({NP.get(code, '?')}) epoch {epoch}"
    if op == 0 and len(resp) >= 12:
        line += f" external {'.'.join(str(b) for b in resp[8:12])}"
    if op in (1, 2) and len(resp) >= 16:
        int_port, ext_port, lt = struct.unpack("!HHI", resp[8:16])
        line += f" internal {int_port} mapped {ext_port} lifetime {lt}"
    print(line)
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gateway", help="the PCP server's LAN address")
    ap.add_argument("--port", type=int, default=5351)
    ap.add_argument("--int-port", type=int, default=3074,
                    help="the client's own listening port (the MAP key)")
    ap.add_argument("--proto", type=int, default=17, help="17 UDP, 6 TCP")
    ap.add_argument("--suggest", type=int, default=0,
                    help="a suggested external port; 0 asks for any")
    ap.add_argument("--client", default=None,
                    help="the address the server sees this client at. The "
                         "default is the kernel's own choice, which is right "
                         "only when no other NAT sits between the probe and "
                         "the server: a client that cannot see itself must "
                         "learn this address, and the server answers "
                         "ADDRESS_MISMATCH until it does")
    ap.add_argument("--lifetime", type=int, default=120,
                    help="the lifetime to ask for, in seconds. The server "
                         "caps it; 120 is the RFC's own default and the "
                         "value every earlier run asked for")
    ap.add_argument("--keepalive", action="store_true",
                    help="after a successful MAP, keep the mapping and stay: "
                         "the client goes silent and this socket is where the "
                         "outside's probes land, so every arrival is printed "
                         "with the epoch that places it against that silence")
    args = ap.parse_args()
    addr = (args.gateway, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(addr)
    local = sock.getsockname()
    client = args.client or local[0]
    print(f"client {client}:{local[1]} -> {addr[0]}:{addr[1]}")

    # The version, and the opcode that asks for nothing.
    show_pcp("ANNOUNCE", send(sock, pcp_header(OP_ANNOUNCE, 0, client)), time.time())
    show_pcp("MAP proto 132 (unsupported)",
             send(sock, pcp_header(OP_MAP, 120, client)
                  + pcp_map_body(132, args.int_port, args.suggest)), time.time())

    # A filter this datapath cannot install, then the same MAP without it.
    filtered = (pcp_header(OP_MAP, 120, client) + pcp_map_body(args.proto, args.int_port, args.suggest)
                + option(OPT_FILTER, b"\x00\x20" + struct.pack("!H", 3074) + mapped("203.0.113.7")))
    show_pcp("MAP with FILTER", send(sock, filtered), time.time())
    prefer = (pcp_header(OP_MAP, 120, client) + pcp_map_body(args.proto, args.int_port, args.suggest)
              + option(OPT_PREFER_FAILURE, b""))
    show_pcp("MAP with PREFER_FAILURE", send(sock, prefer), time.time())

    # The real thing: a MAP, retried once because a mapping whose discovery
    # is in flight is dropped rather than answered with a guess.
    req = pcp_header(OP_MAP, args.lifetime, client) + pcp_map_body(args.proto, args.int_port, args.suggest)
    sent_at = time.time()
    resp = send(sock, req, wait=4.0)
    got = show_pcp("MAP", resp, sent_at)
    if got is None:
        print("retrying the MAP after 4s (the protocol's own recovery)")
        sent_at = time.time()
        got = show_pcp("MAP (retry)", send(sock, req, wait=8.0), sent_at)
    if args.hold and got is not None and got[3] == 0:
        # The mapping is held open on purpose. The client now goes silent and
        # answers nothing, and this socket is where the outside's probes land.
        # The association the requests used is dissolved first: a connected
        # UDP socket delivers only from the peer it is connected to, and the
        # probes come from an unrelated address; Linux dissolves the
        # association when the socket is connected to the wildcard.
        sock.connect(("0.0.0.0", 0))
        sock.settimeout(None)
        print("KEEPALIVEING: the client is silent; the mapping is the daemon's", flush=True)
        while True:
            data, peer = sock.recvfrom(2048)
            print(f"RX {len(data)} bytes from {peer[0]}:{peer[1]} at {time.time():.3f}",
                  flush=True)
    if got is not None and got[3] == 0:
        print("renewing: the same key must refresh, not move")
        show_pcp("MAP (renew)", send(sock, req, wait=8.0), time.time())
        dele = pcp_header(OP_MAP, 0, client) + pcp_map_body(args.proto, args.int_port, 0)
        show_pcp("MAP lifetime 0 (delete)", send(sock, dele, wait=8.0), time.time())

    # NAT-PMP on the same port.
    natpmp(sock, 0)
    natpmp(sock, 1, struct.pack("!HHI", 3074, 3074, 7200))
    natpmp(sock, 1, struct.pack("!HHI", 3074, 3074, 0))
    resp = send(sock, bytes([0, 9]) + b"\x00" * 10, wait=2.0)
    if resp is None:
        print("NAT-PMP op 9: no answer")
    else:
        code = struct.unpack("!H", resp[2:4])[0]
        print(f"NAT-PMP op 9: op {resp[1]} code {code} ({NP.get(code, '?')})")

    sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())