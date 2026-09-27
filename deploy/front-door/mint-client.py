#!/usr/bin/env python3
"""Mint a client certificate for an identity the DeviceProtection store accepts.

The authority lives on the line (call/0040). This tool holds it, checks a
password against the store the daemon already keeps, and signs a certificate that
carries what its identity may reach:

    printf '%s\\n' "$password" | mint-client.py --store /tmp/dslp/dp.tsv \\
        --name alice --allow passthru.example --ca-dir /etc/front-door/ca \\
        --out-dir /etc/front-door/clients

The password arrives on standard input, so it stays out of a process list and out
of a shell history. The store's rows are the daemon's own: a `U` row per user,
carrying the name, the salt, the stored hash and the roles, tab separated.

The key derivation is the one DeviceProtection:1 states, and the daemon
implements independently: STORED is the first 128 bits of PBKDF2-HMAC-SHA-256 over
the password, with the name and the salt concatenated as the salt and five
thousand iterations.
"""
import argparse
import getpass
import hashlib
import os
import subprocess
import sys


def stored_hash(name, salt, password):
    salt_bytes = name.encode() + salt.encode()
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt_bytes, 5000, dklen=32
    )[:16].hex()


def load_identity(path, name):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            cols = line.rstrip("\n").split("\t")
            if len(cols) >= 5 and cols[0] == "U" and cols[1] == name:
                return {"salt": cols[2], "stored": cols[3], "roles": cols[4]}
    return None


def ensure_authority(ca_dir):
    key = os.path.join(ca_dir, "ca.key")
    crt = os.path.join(ca_dir, "ca.crt")
    if not os.path.exists(key) or not os.path.exists(crt):
        os.makedirs(ca_dir, exist_ok=True)
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
             "-subj", "/CN=ds-lite-punch front door CA", "-keyout", key, "-out", crt],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    return key, crt


def mint(ca_key, ca_crt, out_dir, name, allow, days):
    os.makedirs(out_dir, exist_ok=True)
    key = os.path.join(out_dir, name + ".key")
    csr = os.path.join(out_dir, name + ".csr")
    crt = os.path.join(out_dir, name + ".crt")
    # The permission travels in the subject's organisational unit, which the front can read from a client certificate's distinguished name.
    subj = "/CN=%s/OU=%s" % (name, allow)
    subprocess.run(
        ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", subj,
         "-keyout", key, "-out", csr],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ["openssl", "x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key,
         "-CAcreateserial", "-days", str(days), "-out", crt],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    os.unlink(csr)
    return crt, key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True, help="the DeviceProtection store, dp.tsv")
    ap.add_argument("--name", required=True, help="the identity to mint for")
    ap.add_argument("--allow", required=True, help="the name this certificate may reach")
    ap.add_argument("--require-role", default="Admin", help="a role the identity must hold")
    ap.add_argument("--ca-dir", default="front-door-ca", help="where the authority lives")
    ap.add_argument("--out-dir", default="front-door-clients", help="where the pair is written")
    ap.add_argument("--days", type=int, default=30, help="how long the certificate lasts")
    args = ap.parse_args()

    identity = load_identity(args.store, args.name)
    if identity is None:
        print("no such identity in %s" % args.store, file=sys.stderr)
        return 1

    password = sys.stdin.readline().rstrip("\n")
    if not password:
        password = getpass.getpass("password for %s: " % args.name)
    if stored_hash(args.name, identity["salt"], password) != identity["stored"]:
        print("the password does not match %s" % args.name, file=sys.stderr)
        return 1

    roles = [r.strip() for r in identity["roles"].replace("|", ",").split(",")]
    if args.require_role not in roles:
        print("%s holds %s, and this needs %s" % (args.name, roles, args.require_role),
              file=sys.stderr)
        return 1

    ca_key, ca_crt = ensure_authority(args.ca_dir)
    crt, key = mint(ca_key, ca_crt, args.out_dir, args.name, args.allow, args.days)
    print("minted %s: CN=%s, OU=%s, %d days, key %s" % (crt, args.name, args.allow, args.days, key))
    return 0


if __name__ == "__main__":
    sys.exit(main())