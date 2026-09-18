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

    python3 collision-probe.py [R]

IP_TRANSPARENT is set on B because a console's address is not local to the
router; it is the same primitive forward.rs uses for source preservation.
"""
import socket
import sys
import time

R = int(sys.argv[1]) if len(sys.argv) > 1 else 52021
NAT = "192.168.0.21"   # the hub-LAN address, where slots bind
SRC = "192.168.21.68"  # a console: its source rule routes it out the VM line
DST = ("8.8.8.8", 45678)
IP_TRANSPARENT = 19

a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.bind((NAT, R))
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
b.bind((SRC, R))
print(f"A holds {NAT}:{R} | B sends from {SRC}:{R} to {DST[0]}:{DST[1]}", flush=True)
b.sendto(b"collide", DST)
time.sleep(1)
for line in open("/proc/net/nf_conntrack"):
    if f"dst={DST[0]}" in line and f"dport={DST[1]}" in line:
        print("conntrack:", line.strip(), flush=True)
print("held: yes if the reply tuple names the NAT address and sport stayed R", flush=True)
a.close()
b.close()