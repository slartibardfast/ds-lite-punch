# !/bin/sh Install the front on this host, as root: its root, its relay, its rendered configuration and both units. Safe to run again. It mints nothing, which is mint.sh's job on the line, and it opens no edge.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

root=/etc/front-door
public_port=8443
protected_name=
protected_upstream=
passthru_name=
user=
units_dir=
lease=300
module=/usr/lib/nginx/modules/ngx_stream_module.so
nginx_bin=/usr/sbin/nginx

while [ $# -gt 0 ]; do
    case "$1" in
        --root) root=$2; shift 2 ;;
        --public-port) public_port=$2; shift 2 ;;
        --protected-name) protected_name=$2; shift 2 ;;
        --protected-upstream) protected_upstream=$2; shift 2 ;;
        --passthru-name) passthru_name=$2; shift 2 ;;
        --user) user=$2; shift 2 ;;
        --units-dir) units_dir=$2; shift 2 ;;
        --lease) lease=$2; shift 2 ;;
        --module) module=$2; shift 2 ;;
        --nginx) nginx_bin=$2; shift 2 ;;
        *) echo "install: unknown option $1" >&2; exit 2 ;;
    esac
done

# The systemd path enables units and so needs root; a --units-dir install writes only under its own root and units directory, where the caller's account is enough.
if [ -z "$units_dir" ] && [ "$(id -u)" != "0" ]; then
    echo "install: run it as root" >&2
    exit 1
fi
if [ -z "$protected_name" ] || [ -z "$protected_upstream" ] || [ -z "$passthru_name" ]; then
    echo "install: --protected-name, --protected-upstream and --passthru-name are all required" >&2
    exit 2
fi
if [ ! -s "$root/certs/front.crt" ] || [ ! -s "$root/certs/front.key" ]; then
    echo "install: $root/certs wants front.crt and front.key, which mint.sh signs on the line" >&2
    exit 1
fi

mkdir -p "$root/logs" "$root/certs"
for d in client_body proxy fastcgi uwsgi scgi; do
    mkdir -p "$root/tmp/$d"
done
cp "$HERE/poke-listener.py" "$root/poke-listener.py"
chmod 0755 "$root/poke-listener.py"
: >"$root/upstreams.map"

sh "$HERE/render.sh" --root "$root" --public-port "$public_port" --module "$module" \
    --protected-name "$protected_name" --protected-upstream "$protected_upstream" \
    --user "$user" >"$root/nginx.conf"

units_target=${units_dir:-/etc/systemd/system}
if [ -n "$units_dir" ]; then
    mkdir -p "$units_dir"
fi
sed -e "s|<FRONT_ROOT>|$root|g" -e "s|<NGINX_BIN>|$nginx_bin|g" \
    "$HERE/front-door-nginx.service.in" >"$units_target/front-door-nginx.service"
sed -e "s|<FRONT_ROOT>|$root|g" -e "s|<NGINX_BIN>|$nginx_bin|g" \
    -e "s|<PUBLIC_PORT>|$public_port|g" \
    -e "s|<PASSTHRU_NAME>|$passthru_name|g" -e "s|<LEASE>|$lease|g" \
    "$HERE/front-door-poke.service.in" >"$units_target/front-door-poke.service"

"$nginx_bin" -c "$root/nginx.conf" -t
if [ -n "$units_dir" ]; then
    echo "install: units rendered to $units_dir; no init enables them here, their ExecStart lines are the front's processes"
else
    systemctl daemon-reload
    systemctl enable --now front-door-poke front-door-nginx
fi

cat <<EOF

The front is installed on port $public_port.

What is left, in order:
  1. The edge: ingress, source 0.0.0.0/0, one rule for TCP $public_port and another for UDP $public_port,
     with the source port range left empty. Persist the host firewall rules separately.
  2. The daemon, on the line: --poke <this host>:$public_port, plus --client-identity, --front-anchor,
     --front-endpoint and --front-name.
  3. The protected name's upstream ($protected_upstream) has to serve, or that name answers 502.
EOF
