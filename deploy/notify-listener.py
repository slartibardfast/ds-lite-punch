#!/usr/bin/env python3
"""The callback a control point needs to read the daemon's events.

A GENA subscription points at a callback, and the daemon connects to it with
each NOTIFY. The subscriber's own listening socket is the usual answer, but a
client sitting behind a second NAT cannot be reached that way: the daemon's
connection is a new inbound flow to it, and that NAT drops it. So the callback
is served where the daemon can always reach it, and this script is what the
acceptance run started on the router itself:

    scp notify-listener.py root@192.168.21.1:/tmp/
    ssh root@192.168.21.1 'python3 /tmp/notify-listener.py &'

With it listening, subscribe from the machine whose namespace you want to
watch, naming this listener in CALLBACK:

    SUBSCRIBE /ctl/IPConn HTTP/1.1
    HOST: 192.168.21.1:49152
    CALLBACK: <http://192.168.21.1:4567/cb>
    NT: upnp:event
    TIMEOUT: Second-300

Every NOTIFY is written to /tmp/notify.log with its head and its propertyset. The
run that proved plan/0009's `#signal` used exactly this, with the subscription
sent from the workstation and the callback here, so the caller the daemon
captured was the workstation (which is what the containment keys on) while the
callback address was the router's.
"""
import socket
import time

PORT = 4567
LOG = "/tmp/notify.log"
LIFETIME_S = 900


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(4)
    srv.settimeout(5)
    end = time.time() + LIFETIME_S
    log = open(LOG, "a")
    print(f"listening on {PORT}, writing {LOG}", flush=True)
    while time.time() < end:
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        data = b""
        conn.settimeout(2)
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                head, _, body = data.partition(b"\r\n\r\n")
                want = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        want = int(line.split(b":")[1])
                if body and len(body) >= want:
                    break
        except socket.timeout:
            pass
        log.write(f"--- {time.strftime('%H:%M:%S')} NOTIFY from {addr[0]}:{addr[1]} ---\n")
        log.write(data.decode(errors="replace") + "\n")
        log.flush()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        conn.close()
    log.write("listener done\n")
    log.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())