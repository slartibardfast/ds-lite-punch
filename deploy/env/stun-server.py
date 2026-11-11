#!/usr/bin/env python3
"""A minimal RFC 5389 STUN binding responder for the carrier environment.

It answers a binding request with the address it was received from, which
through the carrier's translation is exactly the external tuple the flow was
given. Run it in the internet actor:

    python3 deploy/env/stun-server.py --bind 10.9.0.10 --port 3478
"""
import argparse
import socket
import struct
import zlib

MAGIC = 0x2112A442
HEADER = 20
FINGERPRINT_XOR = 0x5354554E


def attr(atype, value):
    pad = (-len(value)) % 4
    return struct.pack("!HH", atype, len(value)) + value + b"\0" * pad


def answer(msg, peer):
    if len(msg) < HEADER:
        return None
    mtype, mlen, cookie = struct.unpack("!HHI", msg[:8])
    if mtype != 0x0001 or cookie != MAGIC:
        return None
    txn = msg[8:20]
    out = bytearray(struct.pack("!HHI", 0x0101, 0, MAGIC) + txn)
    ip, port = peer[0], peer[1]
    addr = struct.unpack("!I", socket.inet_aton(ip))[0]
    xport = port ^ (MAGIC >> 16)
    xaddr = addr ^ MAGIC
    out += attr(0x0020, struct.pack("!BBHI", 0, 0x01, xport, xaddr))
    out += attr(0x0001, struct.pack("!BBHI", 0, 0x01, port, addr))
    out += attr(0x8022, b"env-stun")
    fp_header = struct.pack("!HH", 0x8028, 4)
    crc = zlib.crc32(bytes(out) + fp_header) & 0xFFFFFFFF
    out += fp_header + struct.pack("!I", crc ^ FINGERPRINT_XOR)
    struct.pack_into("!H", out, 2, len(out) - HEADER)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3478)
    args = ap.parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print("stun responder on %s:%d" % (args.bind, args.port), flush=True)
    while True:
        msg, peer = sock.recvfrom(65535)
        out = answer(msg, peer)
        if out is not None:
            print("stun request from %s:%d answered" % (peer[0], peer[1]),
                  flush=True)
            sock.sendto(out, peer)


if __name__ == "__main__":
    main()
