#!/usr/bin/env bash
# The front door's split, proved on one machine: no carrier, no root, no VPS. A pass-through name must reach the service's own certificate untouched, a protected name must be refused without a client certificate and served with one, and a name nobody published must go nowhere.

set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
NGINX_BIN=${NGINX_BIN:-$(command -v nginx || true)}
FRONT_MODULE=${FRONT_MODULE:-/usr/lib/nginx/modules/ngx_stream_module.so}

# NGINX_BIN and FRONT_MODULE name the nginx binary and the stream module it loads, so this runs against a local extraction or a system install. The variable is not called NGINX: nginx reads that name itself for inherited sockets and warns on any other value.

[ -x "${NGINX_BIN:-}" ] || { echo "set NGINX_BIN to an nginx binary" >&2; exit 2; }
[ -f "${FRONT_MODULE:-}" ] || { echo "set FRONT_MODULE to the stream module object" >&2; exit 2; }

PASS=passthru.example
PROT=protected.example
W=$(mktemp -d)
PIDS=()
cleanup() {
    for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
    "$NGINX_BIN" -c "$W/nginx.conf" -s stop 2>/dev/null || true
    rm -rf "$W"
}
trap cleanup EXIT

# One authority and three leaves: the service behind the pass-through name, the front's own certificate for the protected name, and one client.

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=front-door harness CA" \
    -keyout "$W/ca.key" -out "$W/ca.crt" 2>/dev/null
leaf() {
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$2" \
        -keyout "$W/$1.key" -out "$W/$1.csr" 2>/dev/null
    printf 'subjectAltName=DNS:%s\n' "$2" > "$W/$1.ext"
    openssl x509 -req -in "$W/$1.csr" -CA "$W/ca.crt" -CAkey "$W/ca.key" \
        -CAcreateserial -days 1 -extfile "$W/$1.ext" -out "$W/$1.crt" 2>/dev/null
}
leaf svc "$PASS"
leaf front "$PROT"
leaf client client

# The service behind the pass-through name is a TLS server with its own certificate, which is the thing the front must leave alone; the service behind the protected name is plaintext, because the front terminates there.

openssl s_server -accept 8444 -cert "$W/svc.crt" -key "$W/svc.key" -www -quiet >/dev/null 2>&1 &
PIDS+=($!)
mkdir -p "$W/www" && printf 'the protected service answered\n' > "$W/www/index.html"
(cd "$W/www" && exec python3 -m http.server 8445 --bind 127.0.0.1 >/dev/null 2>&1) &
PIDS+=($!)

# The configuration under test is the shipped one, rendered here with this harness's values.

# The include starts with the name line an operator would have, because the TCP leg cannot be learned on one machine and the harness stands in for it.
mkdir -p "$W/logs" "$W/tmp"
printf '%s 127.0.0.1:8444;\n' "$PASS" > "$W/upstreams.map"
sed -e "s|<FRONT_MODULE>|$FRONT_MODULE|g" -e "s|<FRONT_ROOT>|$W|g" \
    -e "s|<CERT_DIR>|$W|g" -e "s|<PUBLIC_LISTEN>|8443|g" \
    -e "s|<PUBLIC_UDP_LISTEN>|8447|g" \
    -e "s|<LOCAL_TLS_LISTEN>|127.0.0.1:8446|g" \
    -e "s|<PROTECTED_NAME>|$PROT|g" \
    -e "s|<UPSTREAM_MAP>|$W/upstreams.map|g" \
    -e "s|<PROTECTED_UPSTREAM>|127.0.0.1:8445|g" \
    -e "s|<REJECT_BACKEND>|127.0.0.1:9|g" \
    "$HERE/nginx.conf" > "$W/nginx.conf"
"$NGINX_BIN" -c "$W/nginx.conf" -t
"$NGINX_BIN" -c "$W/nginx.conf"
sleep 1

fail=0
note() { printf '%s\n' "$*"; }

# A pass-through name must present the service's certificate, not the front's.

seen=$(echo | openssl s_client -connect 127.0.0.1:8443 -servername "$PASS" \
    -CAfile "$W/ca.crt" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)
case "$seen" in
    *"CN = $PASS"*|*"CN=$PASS"*)
        note "pass-through: reached the service's own certificate, untouched ($seen)" ;;
    *)  note "FAIL pass-through: saw '${seen:-nothing}'"
        fail=1 ;;
esac

# The demand for a client certificate is asserted by its status, since curl reports transport failures alone and a 400 would read as success.

code=$(curl -sS --max-time 5 --cacert "$W/ca.crt" --resolve "$PROT:8443:127.0.0.1" \
        "https://$PROT:8443/" -o /dev/null -w '%{http_code}' 2>"$W/no-client.err" || echo "curl-failed")
case "$code" in
    400)         note "protected: refused without a client certificate (400 from the TLS layer)" ;;
    curl-failed) note "protected: refused without a client certificate (transport refused)" ;;
    *)           note "FAIL protected: a client with no certificate got '$code'"
                 fail=1 ;;
esac

if body=$(curl -sS --max-time 5 --cacert "$W/ca.crt" --cert "$W/client.crt" --key "$W/client.key" \
        --resolve "$PROT:8443:127.0.0.1" "https://$PROT:8443/" 2>"$W/with-client.err"); then
    case "$body" in
        *"the protected service answered"*)
            note "protected: served with a client certificate, and the service answered" ;;
        *)  note "FAIL protected: unexpected body '${body:0:60}'"
            fail=1 ;;
    esac
else
    note "FAIL protected: a client with a certificate was refused: $(tr -d '\n' <"$W/with-client.err" | head -c 100)"
    fail=1
fi

code=$(curl -sS --max-time 5 --resolve "unknown.example:8443:127.0.0.1" \
        "https://unknown.example:8443/" -o /dev/null -w '%{http_code}' 2>/dev/null || echo "curl-failed")
case "$code" in
    000*|curl-failed) note "unknown name: refused at the transport (no connection)" ;;
    *)                note "FAIL unknown name: it answered '$code'"
                      fail=1 ;;
esac

# The front learns the line's tuple from the poke it receives, and the UDP leg follows it.
python3 "$HERE/poke-listener.py" --listen 127.0.0.1:41001 --out "$W/upstreams.map" \
    --name "$PASS" --udp-port 8447 --lease 15 \
    --reload "$NGINX_BIN -c $W/nginx.conf -s reload" >/dev/null 2>&1 &
PIDS+=($!)
python3 - <<'PY' > "$W/udp-leg.txt" 2>&1 &
import socket, time
time.sleep(1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 8455))
s.sendto(b"dslp-poke", ("127.0.0.1", 41001))
s.settimeout(10)
try:
    data, peer = s.recvfrom(2048)
    print("the front forwarded:", data.decode())
except socket.timeout:
    print("the front forwarded nothing")
PY
PIDS+=($!)
sleep 3
python3 - <<'PY'
import socket
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
c.sendto(b"the client spoke", ("127.0.0.1", 8447))
c.close()
t = socket.create_connection(("127.0.0.1", 41001), timeout=3)
t.sendall(b"dslp-poke")
t.close()
PY
sleep 3
learnt_name=$(grep -c "^$PASS 127.0.0.1:" "$W/upstreams.map" || true)
learnt_port=$(grep -c "^8447 127.0.0.1:8455;" "$W/upstreams.map" || true)
if [ "$learnt_name" = 1 ] && [ "$learnt_port" = 1 ] \
    && grep -q 'the front forwarded: the client spoke' "$W/udp-leg.txt"; then
    note "the front follows the poke: the UDP forward went to the tuple it learned"
else
    note "FAIL front learning: $learnt_name name-keyed, $learnt_port port-keyed, and $(tr -d '\n' <"$W/udp-leg.txt")"
    fail=1
fi

# A lease that stops being renewed stops being routed.
sleep 17
if [ -s "$W/upstreams.map" ]; then
    note "FAIL lease: the include still carries $(tr '\n' ' ' <"$W/upstreams.map")"
    fail=1
else
    note "lease: the entry left with the pokes that kept it"
fi

# The authority mints for an identity the store accepts, and for nobody else.
STORE="$W/dp.tsv"
stored_for() {
    python3 -c "
import hashlib, sys
name, salt, pw = sys.argv[1], sys.argv[2], sys.argv[3]
print(hashlib.pbkdf2_hmac('sha256', pw.encode(), (name + salt).encode(), 5000, dklen=32)[:16].hex())
" "$1" "$2" "$3"
}
salt=$(python3 -c "import secrets; print(secrets.token_hex(8))")
printf 'U\talice\t%s\t%s\tBasic|Admin\n' "$salt" "$(stored_for alice "$salt" correct-horse)" > "$STORE"
if printf 'wrong\n' | python3 "$HERE/mint-client.py" --store "$STORE" --name alice --allow "$PASS" \
        --ca-dir "$W/ca" --out-dir "$W/clients" >/dev/null 2>&1; then
    note "FAIL mint: a wrong password was accepted"
    fail=1
else
    note "mint: a wrong password is refused"
fi
printf 'U\tbob\t%s\t%s\tBasic\n' "$salt" "$(stored_for bob "$salt" correct-horse)" > "$STORE"
if printf 'correct-horse\n' | python3 "$HERE/mint-client.py" --store "$STORE" --name bob --allow "$PASS" \
        --ca-dir "$W/ca" --out-dir "$W/clients" >/dev/null 2>&1; then
    note "FAIL mint: an identity without the role was accepted"
    fail=1
else
    note "mint: an identity without the required role is refused"
fi
printf 'U\talice\t%s\t%s\tBasic|Admin\n' "$salt" "$(stored_for alice "$salt" correct-horse)" > "$STORE"
if printf 'correct-horse\n' | python3 "$HERE/mint-client.py" --store "$STORE" --name alice --allow "$PASS" \
        --ca-dir "$W/ca" --out-dir "$W/clients" >/dev/null 2>&1; then
    subject=$(openssl x509 -in "$W/clients/alice.crt" -noout -subject 2>/dev/null)
    case "$subject" in
        *"CN = alice"*"OU = $PASS"*|*"CN=alice"*"OU=$PASS"*)
            note "mint: the certificate carries the identity and what it may reach" ;;
        *)  note "FAIL mint: the subject reads '${subject:-nothing}'"
            fail=1 ;;
    esac
else
    note "FAIL mint: a valid identity was refused"
    fail=1
fi

if [ "$fail" = 0 ]; then
    note "front-door harness: the split by name holds"
else
    note "front-door harness: FAILED"
fi
exit "$fail"