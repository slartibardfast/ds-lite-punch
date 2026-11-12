#!/usr/bin/env python3
"""The fake target service: one port, both protocols, and every byte that
arrives goes back to whoever sent it, so the slot's round trip through the
daemon has a peer that answers.

    python3 deploy/env/service-echo.py --bind 192.168.77.2 --port 40001
"""
import argparse
import socket
import ssl
import threading


def udp_loop(sock):
    while True:
        data, peer = sock.recvfrom(65535)
        sock.sendto(data, peer)


def tcp_serve(sock, tls_ctx):
    while True:
        conn, _ = sock.accept()
        try:
            if tls_ctx is not None:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
            threading.Thread(target=tcp_echo, args=(conn,), daemon=True).start()
        except (OSError, ssl.SSLError):
            conn.close()


def tcp_echo(conn):
    try:
        while True:
            data = conn.recv(65535)
            if not data:
                break
            conn.sendall(data)
    except OSError:
        pass
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=40001)
    ap.add_argument("--tls-cert", default="",
                    help="the service's own certificate, for a TCP side that "
                         "presents itself end to end through a passthrough "
                         "front")
    ap.add_argument("--tls-key", default="")
    args = ap.parse_args()
    tls_ctx = None
    if args.tls_cert:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(args.tls_cert, args.tls_key)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.bind, args.port))
    threading.Thread(target=udp_loop, args=(udp,), daemon=True).start()
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((args.bind, args.port))
    tcp.listen(16)
    print("echo service on %s:%d, udp and tcp%s" % (
        args.bind, args.port, ", tls" if tls_ctx is not None else ""),
        flush=True)
    tcp_serve(tcp, tls_ctx)


if __name__ == "__main__":
    main()
