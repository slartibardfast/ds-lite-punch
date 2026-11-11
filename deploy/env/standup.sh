#!/usr/bin/env bash
# Stands the carrier environment's five actors up in network namespaces and tears them down; verify also proves a datagram from the internet actor reaches the carrier. Run from the repository root as: bash deploy/env/standup.sh up|down|verify (without root it re-execs itself inside a user namespace).
set -euo pipefail

# The topology (deploy/env): a public bridge lives in the internet actor's
# namespace and carries the carrier's external side, the front and the internet
# peer; the carrier's inside side faces the daemon's WAN (named eth1, because
# the daemon keys its nft rules on that name); a management link carries the
# daemon's push the way the tunnel does in production; the service hangs off the
# daemon's LAN. Each actor is a namespace held open by one sleep process; the
# holder pids are the handle every configuration command enters through.
NS_CARRIER=env-carrier
NS_FRONT=env-front
NS_B4=env-b4
NS_SERVICE=env-service
NS_INTERNET=env-internet
BRIDGE=env-pub0
CARRIER_PUB=10.9.0.1
FRONT_PUB=10.9.0.11
INTERNET_PUB=10.9.0.10
CARRIER_IN=10.9.2.1
B4_WAN=10.9.2.2
MGMT_FRONT=10.9.3.1
MGMT_B4=10.9.3.2
B4_LAN=192.168.77.1
SERVICE_IP=192.168.77.2
PROBE_PORT=40001
declare -A HOLDER=()

if [ "$(id -u)" != 0 ]; then
    # A user namespace maps this account to root and owns every child network
    # namespace, so the whole topology stands up without a root password.
    if [ "${ENV_DEBUG:-0}" = 1 ]; then
        exec unshare -Ur --propagation private bash -x "$0" "$@"
    fi
    exec unshare -Ur --propagation private bash "$0" "$@"
fi

holders_down() {
    local p
    for p in "${HOLDER[@]}"; do
        kill "$p" 2>/dev/null || true
    done
    HOLDER=()
    wait 2>/dev/null || true
}

hold() { # <actor>: open its namespace and remember the holder's pid
    local ns="$1"
    unshare -n sleep infinity & HOLDER["$ns"]=$!
    until nsenter -n -t "${HOLDER[$ns]}" ip link show lo >/dev/null 2>&1; do
        sleep 0.1
    done
}

net() { # <actor> <command...>: run a command inside an actor's namespace
    local ns="$1"
    shift
    nsenter -n -t "${HOLDER[$ns]}" "$@"
}

up() {
    holders_down
    hold "$NS_CARRIER"
    hold "$NS_FRONT"
    hold "$NS_B4"
    hold "$NS_SERVICE"
    hold "$NS_INTERNET"
    # The public bridge lives with the internet peer; the carrier, the front and
    # the peer all attach to it.
    net "$NS_INTERNET" ip link add "$BRIDGE" type bridge
    net "$NS_INTERNET" ip link set "$BRIDGE" up
    attach "$NS_CARRIER" "$CARRIER_PUB/24" pub0
    attach "$NS_FRONT" "$FRONT_PUB/24" pub0
    attach "$NS_INTERNET" "$INTERNET_PUB/24" pub0
    pair "$NS_CARRIER" in0 "$CARRIER_IN/24" "$NS_B4" eth1 "$B4_WAN/24"
    net "$NS_B4" ip route replace default via "$CARRIER_IN"
    pair "$NS_FRONT" mgmt0 "$MGMT_FRONT/30" "$NS_B4" mgmt0 "$MGMT_B4/30"
    pair "$NS_B4" lan0 "$B4_LAN/24" "$NS_SERVICE" eth0 "$SERVICE_IP/24"
    net "$NS_SERVICE" ip route replace default via "$B4_LAN"
}

code_of() { # <actor>: the short wire name, because an ifname stops at fifteen characters
    case "$1" in
        "$NS_CARRIER") echo car ;;
        "$NS_FRONT") echo fro ;;
        "$NS_B4") echo b4 ;;
        "$NS_SERVICE") echo svc ;;
        "$NS_INTERNET") echo int ;;
    esac
}

attach() { # <ns> <ip/cidr> <iface>: a veth end in the namespace, the other end a bridge port
    local ns="$1" ip="$2" iface="$3"
    local code; code=$(code_of "$ns")
    net "$NS_INTERNET" ip link add "e-$code" type veth peer name "e-${code}p"
    net "$NS_INTERNET" ip link set "e-${code}p" master "$BRIDGE"
    net "$NS_INTERNET" ip link set "e-$code" netns "${HOLDER[$ns]}"
    net "$ns" ip link set "e-$code" name "$iface"
    net "$ns" ip addr add "$ip" dev "$iface"
    net "$ns" ip link set "$iface" up
    net "$NS_INTERNET" ip link set "e-${code}p" up
}

pair() { # <ns-a> <iface-a> <ip-a> <ns-b> <iface-b> <ip-b>: a point-to-point veth
    local nsa="$1" ia="$2" ipa="$3" nsb="$4" ib="$5" ipb="$6"
    local ta="tp$RANDOM" tb="tp${RANDOM}p"
    net "$NS_INTERNET" ip link add "$ta" type veth peer name "$tb"
    net "$NS_INTERNET" ip link set "$ta" netns "${HOLDER[$nsa]}"
    net "$NS_INTERNET" ip link set "$tb" netns "${HOLDER[$nsb]}"
    net "$nsa" ip link set "$ta" name "$ia"
    net "$nsb" ip link set "$tb" name "$ib"
    net "$nsa" ip addr add "$ipa" dev "$ia"
    net "$nsb" ip addr add "$ipb" dev "$ib"
    net "$nsa" ip link set "$ia" up
    net "$nsb" ip link set "$ib" up
}

verify() {
    local rc=1
    up
    net "$NS_CARRIER" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", '"$PROBE_PORT"'))
s.settimeout(8)
try:
    data, peer = s.recvfrom(128)
    print("carrier received: %r from %s" % (data.decode(errors="replace"), peer[0]))
except socket.timeout:
    print("carrier received nothing")
' > /tmp/env-carrier-rx.txt 2>&1 &
    local listener=$!
    sleep 1
    net "$NS_INTERNET" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"hello carrier", ("'"$CARRIER_PUB"'", '"$PROBE_PORT"'))
'
    wait "$listener" || true
    if grep -q "hello carrier" /tmp/env-carrier-rx.txt; then
        echo "verify: the datagram from the internet actor reached the carrier"
        cat /tmp/env-carrier-rx.txt
        rc=0
    else
        echo "verify: the carrier never received the datagram"
        cat /tmp/env-carrier-rx.txt
        rc=1
    fi
    holders_down
    return "$rc"
}

case "${1:-}" in
    up) up ;;
    down) holders_down ;;
    verify) verify ;;
    *) echo "usage: bash deploy/env/standup.sh up|down|verify" >&2; exit 2 ;;
esac