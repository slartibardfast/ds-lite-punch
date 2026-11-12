#!/usr/bin/env python3
"""The external monitor: watches the published path from outside the line.

Every pass asks the protected name for the daemon's table over TLS with the
household identity, and asks the passthrough name for the service's own
certificate. A check whose answer changes emits one JSON event line, so a
line anomaly arrives with its mechanism named on the same wire that noticed
it.

    python3 deploy/monitor/external-monitor.py \
        --endpoint 10.9.0.11:8443 --protected protected.env \
        --passthru passthru.env --ca ca.crt \
        --client-cert client.crt --client-key client.key \
        --service-cert-sha256 <hex> --interval 30

`--once` runs a single pass and exits: 0 when every check answered as it
currently should, 2 when one did not. On the deployed line the endpoint is
the published DNS name and the files are the deployed identity's.
"""
import argparse
import hashlib
import json
import socket
import ssl
import sys
import time


def protected_answer(host, port, name, ca, cert, key):
    """The table answer over TLS with the household identity."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca)
    ctx.load_cert_chain(cert, key)
    raw = socket.create_connection((host, port), timeout=10)
    with ctx.wrap_socket(raw, server_hostname=name) as s:
        s.sendall(b"GET /table HTTP/1.0\r\nHost: " + name.encode() +
                  b"\r\n\r\n")
        return s.read(4096).decode(errors="replace")


def passthrough_certificate(host, port, name):
    """The hash of the certificate the passthrough name presents."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=10)
    with ctx.wrap_socket(raw, server_hostname=name) as s:
        return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--protected", required=True)
    ap.add_argument("--passthru", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--client-cert", required=True)
    ap.add_argument("--client-key", required=True)
    ap.add_argument("--service-cert-sha256", default="",
                    help="the service certificate's hash; empty skips the "
                         "passthrough check")
    ap.add_argument("--interval", type=int, default=30)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    host, _, port = args.endpoint.rpartition(":")
    checks = {}
    while True:
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            answer = protected_answer(host, int(port), args.protected,
                                      args.ca, args.client_cert,
                                      args.client_key)
            checks["protected"] = (True, "200 OK" in answer)
        except (OSError, ssl.SSLError) as err:
            checks["protected"] = (False, str(err))
        if args.service_cert_sha256:
            try:
                served = passthrough_certificate(host, int(port),
                                                 args.passthru)
                checks["passthrough"] = (served == args.service_cert_sha256,
                                          served[:12])
            except (OSError, ssl.SSLError) as err:
                checks["passthrough"] = (False, str(err))
        for check, (ok, detail) in sorted(checks.items()):
            print(json.dumps({"event": "external", "at": now,
                              "check": check,
                              "state": "ok" if ok else "fail",
                              "detail": str(detail)[:120]}), flush=True)
        if args.once:
            sys.exit(0 if all(ok for ok, _ in checks.values()) else 2)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
