#!/usr/bin/env python3
"""The carrier watch's cooperating probe (call/0033).

The daemon cannot send from a foreign address, so the one thing that proves
the carrier still forwards a stranger's traffic is a datagram arriving from
one. This script is that stranger: it runs on a host outside the line, binds a
fixed source port, and sends a marked datagram to a mapping's learned external
tuple on an interval.

The mark is the payload's first eight bytes, `dslp-prb`, which the daemon's
datapath counts in its `carrier_probe` counter without terminating the packet.
The rest of the payload carries the epoch, for a reader.

    ./carrier-probe.py 37.228.213.83 59292 --interval 900

Each send prints one line. The daemon logs `carrier-probe` when a probe
arrives and `carrier-silent` after three intervals with none, and this
script's own log is what separates a carrier that stopped forwarding from a
helper that stopped sending.
"""
import argparse
import socket
import struct
import time

MARK = b"dslp-prb"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip", help="the mapping's external address")
    ap.add_argument("port", type=int, help="the mapping's external port")
    ap.add_argument("--interval", type=int, default=900,
                    help="seconds between probes, matching the daemon's interval")
    ap.add_argument("--source-port", type=int, default=41000,
                    help="the fixed source port the daemon's rule is written against")
    ap.add_argument("--once", action="store_true", help="send one probe and exit")
    a = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", a.source_port))
    dst = (a.ip, a.port)
    while True:
        now = int(time.time())
        s.sendto(MARK + struct.pack(">Q", now), dst)
        print(
            "SENT source-port %d -> %s:%d at %d" % (a.source_port, a.ip, a.port, now),
            flush=True,
        )
        if a.once:
            return
        time.sleep(a.interval)


if __name__ == "__main__":
    main()