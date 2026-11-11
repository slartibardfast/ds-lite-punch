#!/usr/bin/env python3
"""The carrier's policy plane: it watches the inside wire, allocates external
tuples per its profile, programs the nft data plane, admits the peers a poke
reached, and expires mappings in silence.

Run it inside the carrier namespace, as root (or the mapped root of a user
namespace), from the repository root:

    nsenter -n -t <carrier-holder> python3 deploy/env/carrier-policy.py \
        --profile deploy/env/profiles/vm-dslite.conf \
        --inside in0 --public pub0 \
        --inside-ip 10.9.2.2 --public-ip 10.9.0.1

The data plane is the kernel's (nft dnat and snat rules the policy adds and
removes by handle); the policy plane owns the decisions the record measured:
per-destination or endpoint-independent mapping, admission scoped per the
profile's filtering behaviour, the answered-poke precondition, and the short
silent timer. Unmapped inside traffic is dropped on the public side, because a
carrier never forwards a datagram that crossed it un-natted.
"""
import argparse
import ipaddress
import pathlib
import random
import re
import selectors
import socket
import struct
import subprocess
import sys
import time

ETH_P_ALL = 0x0003
MARKER = b"dslp-poke"
PROTO_NAMES = {17: "udp", 6: "tcp"}
IDLE_DEFAULT = {"udp": 12, "tcp": 60}
ICMP_UNREACH = 3

def read_profile(path):
    conf = {}
    for raw in pathlib.Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition("=")
        conf[key.strip()] = value.strip()
    return conf

def nft(args):
    subprocess.run(["nft"] + args, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def nft_out(args):
    proc = subprocess.run(["nft"] + args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("carrier-policy: nft %s failed: %s" % (
            " ".join(args), (proc.stderr or "").strip()))
    return proc.stdout

def setup_plane():
    nft(["add", "table", "ip", "carrier"])
    nft(["add", "chain", "ip", "carrier", "prerouting",
         "{ type nat hook prerouting priority dstnat; }"])
    nft(["add", "chain", "ip", "carrier", "postrouting",
         "{ type nat hook postrouting priority srcnat; }"])
    nft(["add", "chain", "ip", "carrier", "leak",
         "{ type filter hook postrouting priority filter + 10; }"])
    nft(["add", "rule", "ip", "carrier", "leak",
         "oifname", '"%s"' % PUB, "iifname", '"%s"' % INSIDE, "drop"])

def parse(frame, inside_ip):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    iph = frame[14:]
    ihl = (iph[0] & 0x0F) * 4
    if len(iph) < ihl:
        return None
    src = str(ipaddress.IPv4Address(iph[12:16]))
    dst = str(ipaddress.IPv4Address(iph[16:20]))
    proto_num = iph[9]
    if proto_num not in PROTO_NAMES or src != INSIDE_IP:
        return None
    proto = PROTO_NAMES[proto_num]
    off = ihl
    sport, dport = struct.unpack("!HH", iph[off:off + 4])
    if proto == "tcp" and len(iph) > off + 13:
        flags = iph[off + 13]
        syn = bool(flags & 0x02)
    else:
        syn = None
    payload = iph[off + (8 if proto == "udp" else 20):]
    return {"proto": proto, "src": src, "sport": sport, "dst": dst,
            "dport": dport, "syn": syn, "payload": payload}

def parse_icmp(frame, inside_ip):
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    iph = frame[14:]
    ihl = (iph[0] & 0x0F) * 4
    if iph[9] != 1 or len(iph) < ihl + 8:
        return None
    if iph[ihl] != ICMP_UNREACH or len(iph) < ihl + 4 + 28:
        return None
    emb = iph[ihl + 8:]
    e_ihl = (emb[0] & 0x0F) * 4
    src = str(ipaddress.IPv4Address(emb[12:16]))
    dst = str(ipaddress.IPv4Address(emb[16:20]))
    proto_num = emb[9]
    if proto_num not in PROTO_NAMES or src != inside_ip:
        return None
    proto = PROTO_NAMES[proto_num]
    off = e_ihl
    sport, dport = struct.unpack("!HH", emb[off:off + 4])
    return {"proto": proto, "src": src, "sport": sport, "dst": dst,
            "dport": dport}

class Carrier:
    def __init__(self, conf):
        self.conf = conf
        self.mappings = {}
        self.used_ports = set()
        self.seq = conf.get("sequential_base", "30000")
        self.log = pathlib.Path(ARGS.log).open("w")

    def emit(self, line):
        stamp = time.strftime("%H:%M:%S")
        print("%s %s" % (stamp, line), flush=True)
        self.log.write("%s %s\n" % (stamp, line))
        self.log.flush()

    def free_port(self, want):
        if want and want not in self.used_ports and want > 1024:
            return want
        if self.conf.get("port_assignment") == "sequential":
            base = int(self.seq)
            for port in range(base, 65536):
                if port not in self.used_ports and port > 1024:
                    return port
            raise SystemExit("carrier: the port pool is exhausted")
        for _ in range(200):
            port = random.randint(30000, 60000)
            if port not in self.used_ports and port != want:
                return port
        raise SystemExit("carrier: no free port")

    def key_of(self, pkt):
        proto = pkt["proto"]
        src, sport = pkt["src"], pkt["sport"]
        if self.conf.get("mapping") == "EIM":
            return (proto, src, sport)
        return (proto, src, sport, pkt["dst"], pkt["dport"])

    def program(self, pkt, ext):
        proto = pkt["proto"]
        restrict = ""
        if self.conf.get("filtering") in ("ADF", "APDF"):
            restrict = "ip saddr %s " % pkt["dst"]
            if self.conf.get("filtering") == "APDF":
                restrict += "udp sport %s " % pkt["dport"] if proto == "udp" \
                    else "tcp sport %s " % pkt["dport"]
        out = nft_out(["-ae", "add", "rule", "ip", "carrier", "prerouting",
                       "iifname", '"%s"' % PUB, proto, "dport", str(ext),
                       restrict, "ip daddr", PUB_IP,
                       "dnat ip to", "%s:%d" % (INSIDE_IP, pkt["sport"])])
        pre_handle = re.search(r"# handle (\d+)", out).group(1)
        dest_match = ""
        if self.conf.get("mapping") != "EIM":
            dest_match = "ip daddr %s " % pkt["dst"]
        out = nft_out(["-ae", "add", "rule", "ip", "carrier", "postrouting",
                       "iifname", '"%s"' % INSIDE, proto, "sport",
                       str(pkt["sport"]), dest_match, "snat ip to",
                       "%s:%d" % (PUB_IP, ext)])
        post_handle = re.search(r"# handle (\d+)", out).group(1)
        return pre_handle, post_handle

    def handle_flow(self, pkt):
        key = self.key_of(pkt)
        now = time.time()
        if key in self.mappings:
            self.mappings[key]["last"] = now
            return
        if pkt["proto"] == "tcp" and not pkt["syn"]:
            return
        ext = self.free_port(pkt["sport"]
                             if self.conf.get("port_assignment") == "preserve"
                             else None)
        self.used_ports.add(ext)
        pre, post = self.program(pkt, ext)
        self.mappings[key] = {"ext": ext, "last": now,
                              "pre": pre, "post": post}
        self.emit("ALLOC %s inside=%s:%d dest=%s:%d external=%s:%d" % (
            pkt["proto"], pkt["src"], pkt["sport"], pkt["dst"], pkt["dport"],
            PUB_IP, ext))

    def revoke(self, flow):
        key = (flow["proto"], flow["src"], flow["sport"], flow["dst"],
               flow["dport"])
        for k in [key for k in self.mappings if k[:5] == key[:5]][:1]:
            m = self.mappings.pop(k)
            self.used_ports.discard(m["ext"])
            for handle in (m["pre"], m["post"]):
                subprocess.run(["nft", "delete", "rule", "ip", "carrier",
                                "prerouting", "handle", handle],
                               capture_output=True)
                subprocess.run(["nft", "delete", "rule", "ip", "carrier",
                                "postrouting", "handle", handle],
                               capture_output=True)
            self.emit("REVOKE refused poke inside=%s:%d dest=%s:%d" % (
                flow["src"], flow["sport"], flow["dst"], flow["dport"]))

    def sweep(self):
        now = time.time()
        for key in list(self.mappings):
            idle = IDLE_DEFAULT[key[0]]
            m = self.mappings[key]
            if now - m["last"] <= int(self.conf.get(
                    key[0] + "_idle_s", idle)):
                continue
            self.used_ports.discard(m["ext"])
            for handle in (m["pre"], m["post"]):
                subprocess.run(["nft", "delete", "rule", "ip", "carrier",
                                "prerouting", "handle", handle],
                               capture_output=True)
                subprocess.run(["nft", "delete", "rule", "ip", "carrier",
                                "postrouting", "handle", handle],
                               capture_output=True)
            del self.mappings[key]
            self.emit("EXPIRE silent %s mapping inside=%s:%d" % (
                key[0], key[1], key[2]))

def main():
    global ARGS, INSIDE_IP, PUB, INSIDE
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--inside", default="in0")
    ap.add_argument("--public", default="pub0")
    ap.add_argument("--inside-ip", default="10.9.2.2")
    ap.add_argument("--public-ip", default="10.9.0.1")
    ap.add_argument("--log", default="/tmp/carrier-policy.log")
    ap.add_argument("--runtime", type=int, default=86400,
                    help="seconds the policy plane serves before exiting")
    global ARGS, INSIDE, PUB, INSIDE_IP, PUB_IP
    ARGS = ap.parse_args()
    INSIDE, PUB = ARGS.inside, ARGS.public
    INSIDE_IP, PUB_IP = ARGS.inside_ip, ARGS.public_ip
    conf = read_profile(ARGS.profile)
    subprocess.run(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"],
                   capture_output=True)
    setup_plane()
    carrier = Carrier(conf)
    sel = selectors.DefaultSelector()
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                            socket.ntohs(ETH_P_ALL))
    sniffer.bind((INSIDE, 0))
    sel.register(sniffer, selectors.EVENT_READ)
    last_sweep = time.time()
    deadline = time.time() + int(ARGS.runtime)
    while time.time() < deadline:
        events = sel.select(timeout=1.0)
        for _ in events:
            frame = sniffer.recv(65535)
            icmp = parse_icmp(frame, INSIDE_IP)
            if icmp is not None:
                carrier.revoke(icmp)
                continue
            pkt = parse(frame, INSIDE_IP)
            if pkt is not None:
                carrier.handle_flow(pkt)
        if time.time() - last_sweep >= 1.0:
            carrier.sweep()
            last_sweep = time.time()
    carrier.sweep()

if __name__ == "__main__":
    main()