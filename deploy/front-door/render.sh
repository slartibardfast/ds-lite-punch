#!/bin/sh
# Render the front's nginx configuration from its template, filling the tokens this front's shape sets.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

root=/etc/front-door
public_port=8443
local_tls_listen=127.0.0.1:8446
report_upstream=127.0.0.1:8448
reject_backend=127.0.0.1:9
module=/usr/lib/nginx/modules/ngx_stream_module.so
protected_name=
protected_upstream=

while [ $# -gt 0 ]; do
    case "$1" in
        --root) root=$2; shift 2 ;;
        --public-port) public_port=$2; shift 2 ;;
        --local-tls-listen) local_tls_listen=$2; shift 2 ;;
        --report-upstream) report_upstream=$2; shift 2 ;;
        --reject-backend) reject_backend=$2; shift 2 ;;
        --module) module=$2; shift 2 ;;
        --protected-name) protected_name=$2; shift 2 ;;
        --protected-upstream) protected_upstream=$2; shift 2 ;;
        *) echo "render: unknown option $1" >&2; exit 2 ;;
    esac
done

if [ -z "$protected_name" ] || [ -z "$protected_upstream" ]; then
    echo "render: --protected-name and --protected-upstream are both required" >&2
    exit 2
fi

rendered=$(sed \
    -e "s|<FRONT_MODULE>|$module|g" \
    -e "s|<FRONT_ROOT>|$root|g" \
    -e "s|<CERT_DIR>|$root/certs|g" \
    -e "s|<PUBLIC_LISTEN>|$public_port|g" \
    -e "s|<LOCAL_TLS_LISTEN>|$local_tls_listen|g" \
    -e "s|<PROTECTED_NAME>|$protected_name|g" \
    -e "s|<UPSTREAM_MAP>|$root/upstreams.map|g" \
    -e "s|<PROTECTED_UPSTREAM>|$protected_upstream|g" \
    -e "s|<REPORT_UPSTREAM>|$report_upstream|g" \
    -e "s|<REJECT_BACKEND>|$reject_backend|g" \
    "$HERE/nginx.conf")

case "$rendered" in
    *"<"*)
        echo "render: a token was left unfilled" >&2
        exit 1
        ;;
esac

printf '%s\n' "$rendered"