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
With --http-listen it also takes the daemon's control-channel push and answers
it: the push's body is the table the daemon routes with, and the answer carries
the tuple this front routes on for each protocol, and which view supplied it.

Two views teach this front, in a fixed order (call/0046). The poke's own source
is authoritative for its protocol while the lease holds it. A table the push
carries fills a protocol the poke has not reached, and every line the include
and the answer carry names its source, so a fallback never wins quietly and a
protocol with neither says so.

The socket is also the datagram leg. A datagram that is not a poke goes onward
to the tuple the front routes on, from this same socket, because the carrier
admits a peer by the exact tuple the line's mapping spoke to, and one flow at a
time holds it: a datagram from a new client takes the socket over, and the
slot's own datagrams go back to that client. --udp-only leaves the TCP half of
the port to another process, which is what a front whose TCP side is nginx does.

    poke-listener.py --listen 0.0.0.0:41001 --out /etc/front-door/upstreams \\
        --reload "nginx -s reload"
"""
import argparse
import http.server
import os
import socket
import subprocess
import sys
import threading
import time

MARK = b"dslp-poke"
PUSH_TTL = 180
PROTOCOLS = {"17": "udp", "6": "tcp"}


def picked(table, pushed, proto, now):
    """The tuple this front routes on for a protocol, and the view that supplied it, the poke's first."""
    if proto in table:
        return table[proto], "poke"
    entry = pushed.get(proto)
    if entry and now - entry[1] <= PUSH_TTL:
        return entry[0], "push"
    return None, "none"


def write_table(path, table, pushed, reload_cmd, name):
    lines = []
    for proto, key in (("udp", table.get("udp_port")), ("tcp", name)):
        if not key:
            continue
        tuple_, source = picked(table, pushed, proto, time.time())
        if tuple_:
            lines.append("%s %s; # %s" % (key, tuple_, source))
    text = "".join(line + "\n" for line in lines)
    try:
        with open(path, encoding="utf-8") as fh:
            if fh.read() == text:
                return
    except OSError:
        pass
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
    print("routing table: %s" % (text.replace("\n", " ").strip() or "(empty)"), flush=True)
    if reload_cmd:
        subprocess.run(reload_cmd, shell=True, check=False)


class Report(http.server.BaseHTTPRequestHandler):
    """Take the daemon's table from its push, and answer with the tuple this front routes on."""

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            pushed = {}
            body = self.rfile.read(length).decode("utf-8", "replace")
            print("the push carried: %s" % body.replace("\n", " ").strip(), flush=True)
            for line in body.splitlines():
                parts = line.split()
                proto = PROTOCOLS.get(parts[1]) if len(parts) >= 3 else None
                if proto:
                    pushed[proto] = (parts[2], time.time())
            if pushed:
                self.server.pushed.update(pushed)
                self.server.rewrite()
        lines = []
        for proto in ("udp", "tcp"):
            tuple_, source = picked(
                self.server.table, self.server.pushed, proto, time.time()
            )
            lines.append("%s %s %s" % (proto, tuple_ or "none", source))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, fmt, *args):
        print("report: " + (fmt % args), flush=True)


class ReportServer(http.server.ThreadingHTTPServer):
    """Carry the front's two views to the handler, which answers every push with the picked one."""

    def __init__(self, bind, table, pushed, rewrite):
        self.table = table
        self.pushed = pushed
        self.rewrite = rewrite
        super().__init__(bind, Report)


def slot_of(tuple_):
    """The host and port a `host:port` tuple names, or None when it names nothing."""
    host, _, port = tuple_.rpartition(":")
    if not host or not port.isdigit():
        return None
    return (host, int(port))


def udp_loop(bind, table, pushed, path, reload_cmd, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    client = None
    while True:
        data, peer = sock.recvfrom(65535)
        if data.startswith(MARK):
            table["udp"] = "%s:%d" % (peer[0], peer[1])
            table["udp_seen"] = time.time()
            print("udp poke from %s:%d" % (peer[0], peer[1]), flush=True)
            write_table(path, table, pushed, reload_cmd, name)
            sock.sendto(MARK, peer)
            continue
        tuple_, source = picked(table, pushed, "udp", time.time())
        slot = slot_of(tuple_) if tuple_ else None
        if slot is None:
            continue
        if peer == client:
            sock.sendto(data, slot)
            continue
        if peer == slot and client is not None:
            sock.sendto(data, client)
            continue
        # one flow at a time on this socket: the arrival from a new client takes it over
        client = peer
        print("udp client %s:%d follows the %s tuple at %s" % (peer[0], peer[1], source, tuple_), flush=True)
        sock.sendto(data, slot)


def handler(conn, table, pushed, path, reload_cmd, name):
    peer = conn.getpeername()
    table["tcp"] = "%s:%d" % (peer[0], peer[1])
    table["tcp_seen"] = time.time()
    print("tcp poke from %s:%d" % (peer[0], peer[1]), flush=True)
    write_table(path, table, pushed, reload_cmd, name)
    conn.close()


def tcp_loop(bind, table, pushed, path, reload_cmd, name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(bind)
    sock.listen(16)
    while True:
        conn, _ = sock.accept()
        threading.Thread(
            target=handler,
            args=(conn, table, pushed, path, reload_cmd, name),
            daemon=True,
        ).start()


def lease_watch(table, pushed, path, reload_cmd, name, lease):
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
            write_table(path, table, pushed, reload_cmd, name)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="the port the daemon pokes")
    ap.add_argument("--out", required=True, help="the include the front routes with")
    ap.add_argument("--name", required=True, help="the name this front serves")
    ap.add_argument("--udp-port", default="", help="the public UDP port the UDP map is keyed on")
    ap.add_argument("--lease", type=int, default=0, help="withdraw an entry this many seconds after its last poke; 0 keeps it")
    ap.add_argument("--reload", default="", help="a command to run after a change")
    ap.add_argument("--http-listen", default="", help="the address the daemon's push is answered on; empty leaves the report off")
    ap.add_argument("--udp-only", action="store_true", help="own the port for datagrams alone, for a front whose TCP side is another process's")
    args = ap.parse_args()
    host, _, port = args.listen.rpartition(":")
    bind = (host or "0.0.0.0", int(port))
    table = {}
    pushed = {}
    if args.udp_port:
        table["udp_port"] = args.udp_port

    def rewrite():
        write_table(args.out, table, pushed, args.reload, args.name)

    rewrite()
    threading.Thread(
        target=udp_loop,
        args=(bind, table, pushed, args.out, args.reload, args.name),
        daemon=True,
    ).start()
    if not args.udp_only:
        threading.Thread(
            target=tcp_loop,
            args=(bind, table, pushed, args.out, args.reload, args.name),
            daemon=True,
        ).start()
    threading.Thread(
        target=lease_watch,
        args=(table, pushed, args.out, args.reload, args.name, args.lease),
        daemon=True,
    ).start()
    print("listening for pokes on %s:%d" % bind, flush=True)
    if args.http_listen:
        hhost, _, hport = args.http_listen.rpartition(":")
        report = ReportServer((hhost or "127.0.0.1", int(hport)), table, pushed, rewrite)
        threading.Thread(target=report.serve_forever, daemon=True).start()
        print(
            "answering the daemon's push on %s:%d"
            % (report.server_address[0], report.server_address[1]),
            flush=True,
        )
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())