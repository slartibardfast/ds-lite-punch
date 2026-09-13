#!/bin/sh
# Install ds-lite-punch on the ImmortalWrt router (procd init, NOT systemd).
# Run from this directory after scp'ing it to the router. Idempotent.
set -e

BIN=/usr/bin/ds-lite-punch
INIT=/etc/init.d/ds-lite-punch
ENV=/etc/ds-lite-punch.env

[ -x "$BIN" ] || { echo "error: $BIN not present (scp the binary first)"; exit 1; }

cp ds-lite-punch.init "$INIT"
chmod 755 "$INIT"
if [ ! -f "$ENV" ]; then
    cp ds-lite-punch.env "$ENV"
    echo "installed default $ENV — edit BIND/TARGET for your console"
fi

"$INIT" enable
"$INIT" restart
sleep 3
echo "== service status =="
"$INIT" enabled && echo "enabled"
pgrep -fl ds-lite-punch || echo "NOT RUNNING"
echo "== tuple =="
cat /run/ds-lite-punch/tuple 2>/dev/null || echo "no tuple yet"
