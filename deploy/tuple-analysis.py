#!/usr/bin/env python3
"""Analyse the daemon's own tuple events for the uplink's mapping behaviour.

The question call/0027 leaves open, and which nothing else can answer: does
the AFTR ever hand one external port to two inner tuples at once? The daemon
learns each mapping's external tuple from the outside (the observation arm's
STUN replies, the facade's slot churn), so its log is the only record of what
the uplink allocated.

Read the daemon's log on stdin:

    logread | deploy/tuple-analysis.py

It prints, for the window the log covers, three views of the same evidence:

  * each inner tuple (client ip:port) and the external tuples it learned. One
    inner under two externals *at once* is the client-visible split: a console
    holding two external tuples scores Strict or Moderate.
  * each external tuple and the inner tuples that learned it. One external
    under two inners *at once* is the uplink's own collision: the second
    client cannot be reached.
  * each external tuple learned by both a slot and an inner tuple, which is
    expected when a device-key pin made a device's flow egress as the slot's
    tuple, and is ordinary reuse otherwise.

Liveness is decided from event times, which is all the log carries. Events
that interleave are concurrent and are reported as a hazard; events where one
owner's last event precedes the other's first are sequential reuse, which is
ordinary allocator behaviour and is reported apart.
"""
import collections
import json
import re
import sys
import time

LINE = re.compile(
    r"^(\w{3} \w{3} +\d+ \d\d:\d\d:\d\d) .*?ds-lite-punch\[\d+\]: (\{.*\})$"
)
CHURN = re.compile(r"slot (\d+) confirmed (\S+)")
OBS = re.compile(r"(\S+) -> (\S+) ")
RESCUE = re.compile(r"claim (\S+) -> \S+ -> (\d+) ")


def secs(ts):
    return time.mktime(time.strptime(ts, "%a %b %d %H:%M:%S"))


def events(text):
    out = []
    for ln in text.splitlines():
        m = LINE.match(ln)
        if not m:
            continue
        try:
            d = json.loads(m.group(2))
        except ValueError:
            continue
        out.append((m.group(1), secs(m.group(1)), d))
    return out


def verdict(entries):
    """Concurrent or sequential, from the event times of two or more owners.

    `entries` is a list of (epoch, timestamp, owner). Interleaved events mean
    the owners were live together; one owner's last event before another's
    first means the first mapping was over.
    """
    owners = {}
    for t, ts, o in entries:
        first, last = owners.get(o, (t, t))
        owners[o] = (min(first, t), max(last, t))
    order = sorted(owners, key=lambda o: owners[o][0])
    for a, b in zip(order, order[1:]):
        if owners[b][0] < owners[a][1]:
            return "CONCURRENT"
    return "sequential"


def main():
    ev = events(sys.stdin.read())
    if not ev:
        print("no tuple events on stdin")
        return 1
    print(f"window: {ev[0][0]} .. {ev[-1][0]}  ({len(ev)} events)")
    print()

    slots = collections.defaultdict(list)
    pairs = []
    for ts, t, d in ev:
        kind = d.get("event")
        if kind == "tuple" and d.get("slot") is not None:
            slots[d["slot"]].append((t, ts, f"{d.get('ip')}:{d.get('port')}"))
        elif kind == "churn":
            m = CHURN.search(d.get("detail", ""))
            if m:
                slots[int(m.group(1))].append((t, ts, m.group(2)))
        elif kind == "observed-tuple":
            m = OBS.search(d.get("detail", ""))
            if m:
                pairs.append((t, ts, m.group(1), m.group(2)))
        elif kind == "rescue":
            # The refresh line's third field is the router's own translated port, a namespace of its own beside the external tuples.
            m = RESCUE.search(d.get("detail", ""))
            if m:
                pairs.append((t, ts, m.group(1), f"router:{m.group(2)}"))

    print("=== each slot's learned external tuples, in order ===")
    for s in sorted(slots):
        seen = []
        for _, _, tup in slots[s]:
            if tup not in seen:
                seen.append(tup)
        print(f"  slot {s}: {len(slots[s])} events, learned {seen}")
    print()

    externals = collections.defaultdict(list)   # external -> [(t, ts, inner)]
    inners = collections.defaultdict(list)      # inner -> [(t, ts, external)]
    for t, ts, inner, ext in pairs:
        if ext.startswith("router:"):
            continue
        externals[ext].append((t, ts, inner))
        inners[inner].append((t, ts, ext))

    print("=== one inner tuple under more than one external tuple ===")
    print("    (the client-visible split: two externals at once is Strict or Moderate)")
    split = False
    for inner in sorted(inners):
        exts = {e for _, _, e in inners[inner]}
        if len(exts) < 2:
            continue
        split = True
        print(f"  {inner}: {len(exts)} externals")
        for t, ts, e in sorted(inners[inner]):
            print(f"      {ts}  {e}")
        print(f"      verdict: {verdict(inners[inner])}")
    if not split:
        print("  none: every inner tuple held one external tuple")
    print()

    print("=== one external tuple under more than one inner tuple ===")
    print("    (the uplink's own collision: the second client cannot be reached)")
    collision = False
    slot_ext = {}
    for s in sorted(slots):
        for _, _, tup in slots[s]:
            slot_ext.setdefault(tup, s)
    for ext in sorted(externals):
        owners = {i for _, _, i in externals[ext]}
        if len(owners) < 2:
            continue
        collision = True
        print(f"  {ext}: {len(owners)} inner tuples")
        for t, ts, i in sorted(externals[ext]):
            print(f"      {ts}  {i}")
        print(f"      verdict: {verdict(externals[ext])}")
    if not collision:
        print("  none")
    print()

    print("=== one external tuple learned by both a slot and an inner tuple ===")
    shared = sorted(set(slot_ext) & set(externals))
    if shared:
        for ext in shared:
            entries = [(t, ts, f"slot {slot_ext[ext]}") for t, ts, _ in slots[slot_ext[ext]]
                       if _ == ext] + externals[ext]
            entries.sort()
            print(f"  {ext}: slot {slot_ext[ext]} and {sorted({i for _, _, i in externals[ext]})}")
            for t, ts, o in entries:
                print(f"      {ts}  {o}")
            print(f"      verdict: {verdict(entries)}")
    else:
        print("  none")
    print()

    print("=== the sample ===")
    print(f"  distinct inner tuples:    {len(inners)}")
    print(f"  distinct external tuples: {len(externals)}")
    print(f"  pairs (inner -> external): {sum(len(v) for v in inners.values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())