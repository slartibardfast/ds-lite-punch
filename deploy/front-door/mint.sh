#!/bin/sh
# Mint the front's certificates on the line, as root, where call/0040 keeps the authority: it signs the authority, the front's leaf for the names it serves, and the daemon's own identity. Client identities for people are mint-client.py's job.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

dir=/etc/ds-lite-punch-tls
protected_name=
passthru_name=
force=no
ca_days=3650
leaf_days=825

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) dir=$2; shift 2 ;;
        --protected-name) protected_name=$2; shift 2 ;;
        --passthru-name) passthru_name=$2; shift 2 ;;
        --force) force=yes; shift ;;
        *) echo "mint: unknown option $1" >&2; exit 2 ;;
    esac
done

if [ -z "$protected_name" ] || [ -z "$passthru_name" ]; then
    echo "mint: --protected-name and --passthru-name are both required" >&2
    exit 2
fi
if [ "$force" = no ] && [ -s "$dir/ca.key" ]; then
    echo "mint: $dir/ca.key is already there; pass --force to replace the whole set" >&2
    exit 1
fi

mkdir -p "$dir"
cd "$dir"

openssl req -x509 -newkey rsa:2048 -nodes -days "$ca_days" \
    -subj "/CN=ds-lite-punch front authority" -keyout ca.key -out ca.crt

openssl req -newkey rsa:2048 -nodes -subj "/CN=$protected_name" -keyout front.key -out front.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:%s\n' \
    "$protected_name" "$passthru_name" >front.ext
openssl x509 -req -in front.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$leaf_days" -extfile front.ext -out front.crt

openssl req -newkey rsa:2048 -nodes -subj "/CN=ds-lite-punch" -keyout client.key -out client.csr
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' >client.ext
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days "$leaf_days" -extfile client.ext -out client.crt

chmod 0600 ca.key front.key client.key
rm -f front.csr client.csr

cat <<EOF

Minted in $dir: the authority (ca.crt, ca.key), the front's leaf for $protected_name, and the daemon's identity.

The front wants its own leaf and the anchor, never the authority's key:
  install -d /path/to/front/certs
  install -m 0644 $dir/ca.crt /path/to/front/certs/ca.crt
  install -m 0644 $dir/front.crt /path/to/front/certs/front.crt
  install -m 0600 $dir/front.key /path/to/front/certs/front.key

The daemon wants the identity and the anchor, which its own units read:
  CLIENT_IDENTITY=$dir/client.crt:$dir/client.key
  FRONT_ANCHOR=$dir/ca.crt
  FRONT_NAME=$protected_name
EOF