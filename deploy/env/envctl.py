#!/usr/bin/env python3
"""The carrier environment's control plane.

One process owns a user namespace and a network namespace, and orchestrates the
five actors (carrier, front, b4, service, internet), each living in its own
child network namespace. Everything the harness needs runs from inside: the
topology stands up unprivileged, the carrier's policy plane runs in the carrier
actor, and the probes run in the actors they probe.

    python3 deploy/env/envctl.py up             stand the topology up
    python3 deploy/env/envctl.py down           tear it down
    python3 deploy/env/envctl.py verify         prove the datagram path
    python3 deploy/env/envctl.py verify-policy  prove the carrier policy rows

setns into a child namespace requires capability over the current namespace's
owner as well, which is why the controller moves itself into its own network
namespace before it creates or enters any other.

Addresses and wiring (deploy/env): a public bridge in the internet actor
carries the carrier's external side, the front and the peer; the carrier's
inside side faces the daemon's WAN (named eth1, because the daemon keys its nft
rules on that name); a management link carries the daemon's push the way the
tunnel does in production; the service hangs off the daemon's LAN.
"""
import argparse
import contextlib
import ctypes
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
CLONE_NEWNET = 0x40000000
CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
libc = ctypes.CDLL("libc.so.6", use_errno=True)

ACTORS = ("carrier", "front", "b4", "service", "internet")
ADDRESSES = {
    "carrier": {"pub0": "10.9.0.1/24", "in0": "10.9.2.1/24"},
    "front": {"pub0": "10.9.0.11/24", "mgmt0": "10.9.3.1/30"},
    "b4": {"eth1": "10.9.2.2/24", "mgmt0": "10.9.3.2/30",
           "lan0": "192.168.77.1/24"},
    "service": {"eth0": "192.168.77.2/24"},
    "internet": {"pub0": "10.9.0.10/24"},
}
CARRIER_PUB = "10.9.0.1"
B4_WAN_IP = "10.9.2.2"
B4_PORT = 40000
FRONT_PUB = "10.9.0.11"
INTERNET_PUB = "10.9.0.10"
STATE = pathlib.Path("/tmp/env-holders.txt")
HOLDERS = {}
POLICIES = []


def unshare(flags):
    if libc.unshare(flags) != 0:
        err = ctypes.get_errno()
        raise SystemExit("envctl: unshare failed (%s)" % os.strerror(err))


def setns(fd):
    if libc.setns(fd, 0) != 0:
        err = ctypes.get_errno()
        raise SystemExit("envctl: setns failed (%s)" % os.strerror(err))


def enter_own_namespaces():
    uid, gid = os.getuid(), os.getgid()
    unshare(CLONE_NEWUSER | CLONE_NEWNS)
    for path, content in (("/proc/self/setgroups", "deny"),
                          ("/proc/self/gid_map", "0 %d 1" % gid),
                          ("/proc/self/uid_map", "0 %d 1" % uid)):
        with open(path, "w") as fh:
            fh.write(content)
    unshare(CLONE_NEWNET)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)


@contextlib.contextmanager
def netns(name):
    """Context manager: the process runs inside the actor's network namespace."""
    save = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open("/proc/%d/ns/net" % HOLDERS[name], os.O_RDONLY)
    setns(target)
    os.close(target)
    try:
        yield
    finally:
        setns(save)
        os.close(save)


def sh(name, *argv):
    with netns(name):
        proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("envctl: `%s` in %s failed: %s" % (
            " ".join(argv), name, (proc.stderr or proc.stdout).strip()))
    return proc


def run(name, *argv):
    sh(name, *argv)


def hold(name):
    pid = os.fork()
    if pid == 0:
        try:
            unshare(CLONE_NEWNET)
            subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
            time.sleep(100000)
        finally:
            os._exit(0)
    HOLDERS[name] = pid
    # The child unshares and brings lo up on its own schedule; the parent's
    # first setns races that and would land in the wrong namespace.
    deadline = time.time() + 10
    while time.time() < deadline:
        with netns(name):
            out = subprocess.run(["ip", "link", "show", "lo"],
                                 capture_output=True, text=True)
            if "UP" in out.stdout:
                return
        time.sleep(0.05)
    raise SystemExit("envctl: the %s namespace never settled" % name)


def cmd_down():
    for pid in POLICIES + [HOLDERS.get(name) for name in ACTORS]:
        if pid:
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
    for pid in POLICIES:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    STATE.unlink(missing_ok=True)


def cmd_up():
    enter_own_namespaces()
    for name in ACTORS:
        hold(name)
    run("internet", "ip", "link", "add", "env-pub0", "type", "bridge")
    run("internet", "ip", "link", "set", "env-pub0", "up")
    attach("carrier", "pub0", ADDRESSES["carrier"]["pub0"])
    attach("front", "pub0", ADDRESSES["front"]["pub0"])
    attach("internet", "pub0", ADDRESSES["internet"]["pub0"])
    pair("carrier", "in0", ADDRESSES["carrier"]["in0"],
         "b4", "eth1", ADDRESSES["b4"]["eth1"])
    run("b4", "ip", "route", "replace", "default", "via", "10.9.2.1")
    pair("front", "mgmt0", ADDRESSES["front"]["mgmt0"],
         "b4", "mgmt0", ADDRESSES["b4"]["mgmt0"])
    pair("b4", "lan0", ADDRESSES["b4"]["lan0"],
         "service", "eth0", ADDRESSES["service"]["eth0"])
    run("service", "ip", "route", "replace", "default", "via", "192.168.77.1")
    with open(STATE, "w") as fh:
        for name in ACTORS:
            fh.write("%s %d\n" % (name, HOLDERS[name]))
    print("up: five actors stand on the bridge, the carrier inside, two side links")


def attach(name, iface, cidr):
    with netns("internet"):
        sh("internet", "ip", "link", "add", "e-" + name, "type", "veth",
           "peer", "name", "e-" + name + "-p")
        sh("internet", "ip", "link", "set", "e-" + name + "-p", "master",
           "env-pub0")
        sh("internet", "ip", "link", "set", "e-" + name, "netns",
           str(HOLDERS[name]))
    with netns(name):
        sh(name, "ip", "link", "set", "e-" + name, "name", iface)
        sh(name, "ip", "addr", "add", cidr, "dev", iface)
        sh(name, "ip", "link", "set", iface, "up")
    sh("internet", "ip", "link", "set", "e-" + name + "-p", "up")


def pair(name_a, iface_a, cidr_a, name_b, iface_b, cidr_b):
    tag = "p-" + name_a + "-" + name_b
    with netns("internet"):
        subprocess.run(["ip", "link", "add", tag, "type", "veth",
                        "peer", "name", tag + "-x"], check=True)
        subprocess.run(["ip", "link", "set", tag, "netns",
                        str(HOLDERS[name_a])], check=True)
        subprocess.run(["ip", "link", "set", tag + "-x", "netns",
                        str(HOLDERS[name_b])], check=True)
    with netns(name_a):
        subprocess.run(["ip", "link", "set", tag, "name", iface_a], check=True)
        subprocess.run(["ip", "addr", "add", cidr_a, "dev", iface_a],
                       check=True)
        subprocess.run(["ip", "link", "set", iface_a, "up"], check=True)
    with netns(name_b):
        subprocess.run(["ip", "link", "set", tag + "-x", "name", iface_b],
                       check=True)
        subprocess.run(["ip", "addr", "add", cidr_b, "dev", iface_b],
                       check=True)
        subprocess.run(["ip", "link", "set", iface_b, "up"], check=True)


def start_policy(profile):
    pid = os.fork()
    if pid == 0:
        with netns("carrier"):
            os.execv(sys.executable, [sys.executable,
                     str(HERE / "carrier-policy.py"),
                     "--profile", str(HERE / "profiles" / (profile + ".conf")),
                     "--inside", "in0", "--public", "pub0",
                     "--inside-ip", B4_WAN_IP, "--public-ip", CARRIER_PUB,
                     "--log", "/tmp/carrier-policy-" + profile + ".log"])
    POLICIES.append(pid)
    return pid


def policy_log(profile):
    path = pathlib.Path("/tmp/carrier-policy-" + profile + ".log")
    return path.read_text() if path.exists() else ""


def kill_policy(pid):
    try:
        os.kill(pid, 15)
        os.waitpid(pid, 0)
    except (ProcessLookupError, ChildProcessError):
        pass


def poke_from_b4(dest_ip, dest_port):
    with netns("b4"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((B4_WAN_IP, B4_PORT))
        sock.sendto(b"dslp-poke", (dest_ip, dest_port))
        sock.close()


def cross_from(ns, ip, port, dest_ip, dest_port, payload=b"probe"):
    """Sends one datagram from inside an actor and returns what the b4's
    listener received."""
    pathlib.Path("/tmp/b4-rx.txt").unlink(missing_ok=True)
    ready_read, ready_write = os.pipe()
    listener = os.fork()
    if listener == 0:
        os.close(ready_read)
        with netns("b4"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((B4_WAN_IP, B4_PORT))
            # The bind is signalled before the send, so the arrival can never
            # outrun the socket it is meant for.
            os.write(ready_write, b"1")
            sock.settimeout(4)
            try:
                data, peer = sock.recvfrom(256)
                with open("/tmp/b4-rx.txt", "a") as fh:
                    fh.write("%r from %s:%d\n" % (data, peer[0], peer[1]))
            except socket.timeout:
                pass
        os._exit(0)
    os.close(ready_write)
    os.read(ready_read, 1)
    os.close(ready_read)
    with netns(ns):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if ip:
            sock.bind((ip, port))
        sock.sendto(payload, (dest_ip, dest_port))
        sock.close()
    time.sleep(1.5)
    os.kill(listener, 15)
    os.waitpid(listener, 0)
    path = pathlib.Path("/tmp/b4-rx.txt")
    return path.read_text() if path.exists() else ""


def allocations(profile):
    return re.findall(r"external=10\.9\.0\.1:(\d+)", policy_log(profile))


# The per-profile expectations: what each profile SHOULD deliver, per the
# research note. A profile row that fails is a policy defect, not a test
# defect, until the profile is corrected in the record.
EXPECTATIONS = {
    "vm-dslite": {
        "cross_port": 9999,    # any port of the poked peer's address crosses
        "stranger": False,     # a stranger's address was never admitted
        "per_destination": True,
        "silence": True,       # the 12-second timer expires the mapping
    },
    "rfc-bcp": {
        "cross_port": 9999,    # endpoint-independent filtering
        "stranger": True,      # EIF: any address reaches the mapping
        "per_destination": False,  # EIM: one mapping per inside endpoint
        "silence": False,      # the two-minute floor is not worth waiting out
    },
    "symmetric": {
        "cross_port": 8443,    # address-and-port dependent: the poked port only
        "stranger": False,
        "per_destination": True,
        "silence": False,
    },
}


def cmd_verify_policy():
    enter_own_namespaces()
    cmd_up()
    failures = []
    # profile, distinct-tuples?, crossing front port, stranger crosses?, silence test?
    matrix = (("vm-dslite", True, 9999, False, True),
              ("rfc-bcp", False, 9999, True, False),
              ("symmetric", True, 8443, False, False))
    for profile, want_distinct, front_port, stranger_cross, silence in matrix:
        pathlib.Path("/tmp/carrier-policy-" + profile + ".log").unlink(missing_ok=True)
        policy = start_policy(profile)
        time.sleep(2)
        poke_from_b4(FRONT_PUB, 8443)
        time.sleep(1)
        ports = allocations(profile)
        ext = int(ports[0]) if ports else 0
        ok_alloc = bool(ext)
        print("%s %s: allocation %s" % ("PASS" if ok_alloc else "FAIL",
              profile, ports))
        crossed = cross_from("front", FRONT_PUB, front_port, CARRIER_PUB, ext)
        ok_cross = bool(crossed)
        print("%s %s: the poked peer's arrival crossed" % (
            "PASS" if ok_cross else "FAIL", profile))
        stranger = cross_from("internet", INTERNET_PUB, 9999, CARRIER_PUB, ext)
        ok_stranger = bool(stranger.strip()) == stranger_cross
        print("%s %s: the stranger's arrival %s" % (
            "PASS" if ok_stranger else "FAIL", profile,
            "crossed" if stranger else "was refused"))
        poke_from_b4(INTERNET_PUB, 8443)
        time.sleep(1)
        distinct = len(set(allocations(profile)))
        ok_dest = (distinct >= 2) == want_distinct
        print("%s %s: %d tuple(s) for one source port (want %s)" % (
            "PASS" if ok_dest else "FAIL", profile, distinct,
            "per destination" if want_distinct else "one mapping"))
        ok_silence = True
        if silence:
            idle = int(re.search(r"udp_idle_s = (\d+)", (HERE / "profiles" /
                        (profile + ".conf")).read_text()).group(1))
            time.sleep(idle + 2)
            again = cross_from("front", FRONT_PUB, front_port, CARRIER_PUB, ext)
            ok_silence = not again
            print("%s %s: silence expired the mapping" % (
                "PASS" if ok_silence else "FAIL", profile))
        for label, ok in (("allocation", ok_alloc), ("crossing", ok_cross),
                          ("stranger", ok_stranger),
                          ("per-destination", ok_dest),
                          ("silence", ok_silence)):
            if not ok:
                failures.append("%s %s" % (profile, label))
        kill_policy(policy)
    cmd_down()
    if failures:
        raise SystemExit("verify-policy: failed rows in %s" % (
            ", ".join(failures)))
    print("verify-policy: every profile row green")


def cmd_verify():
    enter_own_namespaces()
    cmd_up()
    listener = os.fork()
    if listener == 0:
        verdict = 1
        with netns("carrier"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 40001))
            sock.settimeout(6)
            try:
                data, peer = sock.recvfrom(128)
                print("verify: the carrier received %r from %s" % (
                    data.decode(errors="replace"), peer[0]), flush=True)
                verdict = 0
            except socket.timeout:
                print("verify: the carrier never received the datagram",
                      flush=True)
        os._exit(verdict)
    time.sleep(0.5)
    with netns("internet"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"hello carrier", (CARRIER_PUB, 40001))
        sock.close()
    _, status = os.waitpid(listener, 0)
    cmd_down()
    sys.exit(os.waitstatus_to_exitcode(status))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["up", "down", "verify",
                                        "verify-policy"])
    args = ap.parse_args()
    {"up": cmd_up, "down": cmd_down, "verify": cmd_verify,
     "verify-policy": cmd_verify_policy}[args.command]()


if __name__ == "__main__":
    main()