#!/usr/bin/env python3
"""The hold's acceptance client: gauge a flow so the arm claims it, then go
silent while an outside vantage probes the learned tuple.

The flow has to be bidirectional before the arm will claim it (the
observation predicate wants reply packets), and the tuple the outside world
sees is learned with a STUN exchange from the flow's own socket. So this
client sends one binding request, reads its own external tuple out of the
answer, hands that tuple to the vantage, and then says nothing at all: the
silence is the experiment. The vantage's probe outcomes are recorded on the
router's WAN capture, not here, because the router is the last hop this
daemon owns and a client behind a second NAT is not.

    ./hold-acceptance.py <local-port> <seconds-of-silence> [vantage] [offsets...]

With no vantage, the offsets are printed and nothing is probed: useful for
reading the daemon's own claim and learned-tuple lines. With a vantage, the
tuple is handed to it over ssh and it sends a probe at each offset, which is
where the 30/60/120/300 silent windows of plan/0009's acceptance come from.
"""
import os
import socket
import struct
import subprocess
import sys
import time

MAGIC = 0x2112A442
STUN_SERVER = ("stun.l.google.com", 19302)
VANTAGE = "ubuntu@170.9.238.141"
VANTAGE_SWEEP = "/tmp/probe_sweep.py"


def stun_tuple(sock, server=STUN_SERVER):
    """The tuple this socket's flow looks like from outside."""
    txid = os.urandom(12)
    sock.sendto(struct.pack("!HHI", 1, 0, MAGIC) + txid, server)
    sock.settimeout(3.0)
    data, _ = sock.recvfrom(2048)
    if struct.unpack("!H", data[:2])[0] != 0x0101:
        return None
    i = 20
    while i + 4 <= len(data):
        at, al = struct.unpack("!HH", data[i : i + 4])
        v = data[i + 4 : i + 4 + al]
        if at == 0x0020 and len(v) >= 8 and v[1] == 1:
            port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
            ip = bytes(b ^ m for b, m in zip(v[4:8], struct.pack("!I", MAGIC)))
            return socket.inet_ntoa(ip), port
        i += 4 + ((al + 3) & ~3)
    return None


def main():
    port = int(sys.argv[1])
    hold = int(sys.argv[2])
    vantage = sys.argv[3] if len(sys.argv) > 3 else None
    offsets = sys.argv[4:] or ["30", "60", "120", "300"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    t = stun_tuple(s)
    t0 = time.time()
    print(
        f"T0_EPOCH={t0:.3f} tuple={t} (silence begins; the arm holds it only if"
        " this device is on the allowlist)",
        flush=True,
    )
    if t is None:
        return 1
    if vantage:
        out = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=8", vantage, "python3", VANTAGE_SWEEP, t[0], str(t[1])]
            + offsets,
            capture_output=True,
            text=True,
            timeout=60 + hold,
        )
        print(out.stdout.strip(), flush=True)
    else:
        print("no vantage given: offsets not probed:", " ".join(offsets), flush=True)
    time.sleep(max(0.0, t0 + hold - time.time()))
    print("client done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())