#!/usr/bin/env python3
"""The router-side event sampler: stands beside the daemon and samples what
the line looks like from inside.

One sample reads three things: the daemon's own event log since the sampler
last looked (new lines are carried verbatim, and warn lines are always), the
WAN interface's byte counters, and the conntrack table's weight. A sample
whose numbers moved emits one JSON event line, so a line anomaly arrives with
the router-side mechanism named beside the external monitor's.

    python3 deploy/monitor/router-sampler.py \
        --log /var/log/ds-lite-punch.log --iface eth1 --interval 30

`--once` runs a single sample and exits 0.
"""
import argparse
import glob
import json
import os
import time


def iface_counters(iface):
    base = "/sys/class/net/" + iface + "/statistics"
    out = {}
    for name in ("rx_bytes", "tx_bytes"):
        try:
            with open(base + "/" + name) as fh:
                out[name] = int(fh.read().strip())
        except OSError:
            out[name] = None
    return out


def conntrack_weight():
    paths = glob.glob("/proc/net/nf_conntrack") + glob.glob(
        "/proc/net/ip_conntrack")
    for path in paths:
        try:
            with open(path) as fh:
                return sum(1 for _ in fh)
        except OSError:
            continue
    return None


def new_log_lines(path, offset):
    out = []
    try:
        with open(path, errors="replace") as fh:
            fh.seek(offset)
            for line in fh:
                out.append(line.strip())
            offset = fh.tell()
    except OSError:
        pass
    return out, offset


def sample(path, offset, iface):
    lines, offset = new_log_lines(path, offset)
    events = {}
    warns = []
    for line in lines:
        if line.startswith("warn:"):
            warns.append(line[:160])
        marker = '"event":"'
        at = line.find(marker)
        if at >= 0:
            name = line[at + len(marker):].split('"')[0]
            events[name] = events.get(name, 0) + 1
    state = {"event": "sampler", "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
             "iface": iface_counters(iface), "conntrack": conntrack_weight(),
             "daemon_events": events, "daemon_lines": len(lines)}
    if warns:
        state["warns"] = warns
    return state, offset


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True,
                    help="the daemon's event log, as the environment's "
                         "harness and the router's init both write it")
    ap.add_argument("--iface", default="eth1",
                    help="the line-facing interface whose counters move")
    ap.add_argument("--interval", type=int, default=30)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    offset = 0
    previous = None
    while True:
        state, offset = sample(args.log, offset, args.iface)
        moved = previous is None or state["iface"] != previous["iface"] or \
            state["daemon_events"] != previous["daemon_events"] or \
            state["daemon_lines"] != previous["daemon_lines"]
        if moved or args.once:
            print(json.dumps(state), flush=True)
        previous = state
        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
