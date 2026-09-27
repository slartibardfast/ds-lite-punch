#!/usr/bin/env python3
"""Learn the line's tuple from the poke, and write the front's forward target.

The daemon pokes this port from a slot's own socket, so the source address of the
arrival is the line's external tuple for that protocol. Nothing else can tell the
front what it is: the carrier admits a peer the line has spoken to, and the peer
is the only party that sees the mapping.

The table this writes is what the front routes to, one line per protocol:

    udp 37.228.213.83:59348
    tcp 37.228.213.83:59237

Run it beside nginx on the front. Give it the same port the daemon pokes, a path
for the table, and, when the front should pick the table up, a reload command.

    poke-listener.py --listen 0.0.0.0:41001 --out /etc/front-door/upstreams \\
        --reload "nginx -s reload"
"""
import argparse
import os
import socket
import subprocess
import sys
import threading
import time

MARK = b"dslp-poke"


def write_table(path, table, reload_cmd, name):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        if "udp" in table and "udp_port" in table:
            fh.write("%s %s;\n" % (table["udp_port"], table["udp"]))
        if "tcp" in table:
            fh.write("%s %s;\n" % (name, table["tcp"]))
    os.replace(tmp, path)
    if reload_cmd:
        subprocess.run(reload_cmd, shell=True, check=False)


def udp_loop(bind, table, path, reload_cmd, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    while True:
        data, peer = sock.recvfrom(2048)
        if not data.startswith(MARK):
            continue
        table["udp"] = "%s:%d" % (peer[0], peer[1])
        table["udp_seen"] = time.time()
        print("udp poke from %s:%d" % (peer[0], peer[1]), flush=True)
        write_table(path, table, reload_cmd, name)


def handler(conn, table, path, reload_cmd, name):
    peer = conn.getpeername()
    table["tcp"] = "%s:%d" % (peer[0], peer[1])
    table["tcp_seen"] = time.time()
    print("tcp poke from %s:%d" % (peer[0], peer[1]), flush=True)
    write_table(path, table, reload_cmd, name)
    conn.close()


def tcp_loop(bind, table, path, reload_cmd, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        threading.Thread(
            target=handler, args=(conn, table, path, reload_cmd, name), daemon=True
        ).start()


def lease_watch(table, path, reload_cmd, name, lease):
    if lease <= 0:
        return
    while True:
        time.sleep(1)
        now = time.time()
        dropped = False
        for proto in ("udp", "tcp"):
            if proto in table and now - table.get(proto + "_seen", now) > lease:
                del table[proto]
                dropped = True
        if dropped:
            print("lease expired: the entry went with it", flush=True)
            write_table(path, table, reload_cmd, name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="the port the daemon pokes")
    ap.add_argument("--out", required=True, help="the include the front routes with")
    ap.add_argument("--name", required=True, help="the name this front serves")
    ap.add_argument("--udp-port", default="", help="the public UDP port the UDP map is keyed on")
    ap.add_argument("--lease", type=int, default=0, help="withdraw an entry this many seconds after its last poke; 0 keeps it")
    ap.add_argument("--reload", default="", help="a command to run after a change")
    args = ap.parse_args()
    host, _, port = args.listen.rpartition(":")
    bind = (host or "0.0.0.0", int(port))
    table = {}
    if args.udp_port:
        table["udp_port"] = args.udp_port
    write_table(args.out, table, "", args.name)
    threading.Thread(
        target=udp_loop, args=(bind, table, args.out, args.reload, args.name), daemon=True
    ).start()
    threading.Thread(
        target=tcp_loop, args=(bind, table, args.out, args.reload, args.name), daemon=True
    ).start()
    threading.Thread(
        target=lease_watch,
        args=(table, args.out, args.reload, args.name, args.lease),
        daemon=True,
    ).start()
    print("listening for pokes on %s:%d" % bind, flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())