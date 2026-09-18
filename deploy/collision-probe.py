#!/usr/bin/env python3
"""Does this router's NAPT translate a flow into a port a local socket holds?

Run it on the router. A holds (NAT, R) the way a slot's shadow socket does. B
sends from a console's address at the same port number, so the flow is policy
routed out the VM line and the masquerade has to choose a source port: port
preservation asks for R first, and the question is whether a locally bound
port is excluded from the answer.

Measured 2026-09-18 (call/0028): it is not. The reply tuple reads
192.168.0.21 and the source port stays R, so the NAPT does land on a held
port, which is why the late-collision rule exists and why the probe that
steers the allocator is only half the answer.

    python3 collision-probe.py [R] [--no-hold]

With `--no-hold` the probe does not bind A, which is the mode for proving the
daemon's own yield: the slot's shadow socket holds the port, a console-sourced
flow is translated onto it, and the daemon is expected to move the slot and
say so. Without it the probe holds the port itself, which is how the question
in call/0028 was asked.

IP_TRANSPARENT is set on B because a console's address is not local to the
router; it is the same primitive forward.rs uses for source preservation.
"""
import socket
import sys
import time

args = [a for a in sys.argv[1:] if not a.startswith("--")]
R = int(args[0]) if args else 52021
hold_a = "--no-hold" not in sys.argv

NAT = "192.168.0.21"   # the hub-LAN address, where slots bind
SRC = "192.168.21.68"  # a console: its source rule routes it out the VM line
DST = ("8.8.8.8", 45678)
IP_TRANSPARENT = 19

a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if hold_a:
    a.bind((NAT, R))
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
b.bind((SRC, R))
print(
    f"A {'holds' if hold_a else 'does not hold'} {NAT}:{R} | "
    f"B sends from {SRC}:{R} to {DST[0]}:{DST[1]}",
    flush=True,
)
b.sendto(b"collide", DST)
time.sleep(1)
for line in open("/proc/net/nf_conntrack"):
    if f"dst={DST[0]}" in line and f"dport={DST[1]}" in line:
        print("conntrack:", line.strip(), flush=True)
print(
    "held: yes if the reply tuple names the NAT address and sport stayed R"
    " (call/0028 measured yes)",
    flush=True,
)
if hold_a:
    a.close()
b.close()