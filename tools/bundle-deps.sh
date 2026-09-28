#!/bin/sh
# Vendors the dependencies and tars them with the source-replacement snippet the host's release stages by name, vendor-config.toml, then prints the digest for .host-software; extract it into the crate root and append that snippet to .cargo/config.toml, and the build runs with the network off.
set -eu
OUT=${1:-deps-vendor.tar.gz}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cargo vendor --versioned-dirs "$WORK/vendor" > "$WORK/vendor-raw.toml"
printf '\n' > "$WORK/vendor-config.toml"
sed -e 's|^directory = .*|directory = "vendor"|' "$WORK/vendor-raw.toml" >> "$WORK/vendor-config.toml"
tar -czf "$OUT" -C "$WORK" vendor vendor-config.toml
printf 'wrote %s\n' "$OUT"
sha256sum "$OUT" | cut -d' ' -f1