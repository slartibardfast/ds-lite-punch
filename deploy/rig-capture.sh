#!/bin/sh
# Capture a slot's traffic on the router, keyed on the port the slot binds: the carrier rewrites the destination to that inner port before the wire, so a filter on the external tuple port matches nothing and reads as if the carrier refused. Run it on the router as: sh rig-capture.sh <udp|tcp> <bind-port> [packets]; it waits for that many packets.
set -eu

proto=${1:-}
port=${2:-}
count=${3:-20}
if [ -z "$proto" ] || [ -z "$port" ]; then
    echo "usage: sh rig-capture.sh <udp|tcp> <bind-port> [packets]" >&2
    exit 2
fi
case "$proto" in
    udp|tcp) ;;
    *) echo "rig-capture: the protocol reads udp or tcp, and this one reads '$proto'" >&2; exit 2 ;;
esac
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "rig-capture: this box carries no tcpdump" >&2
    exit 2
fi

echo "rig-capture: $count packets on $proto port $port, which is the slot's own port"
echo "  the arrival reads   <front>.<peer> > 192.168.0.21.$port   and the carrier rewrote the destination"
echo "  the answer reads    192.168.0.21.$port > <front>.<peer>   from the slot's own socket"
echo "  a reset beside an arrival is the box's own firewall, so read the accept rule's place next"
tcpdump -i any -n -c "$count" "$proto and port $port"