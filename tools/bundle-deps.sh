#!/bin/sh
# Vendors the dependencies, tars the sources with a config that points cargo at them, and prints the digest for .host-software; extract it into the crate root and append config.toml to .cargo/config.toml, and the build then runs with the network off.
set -eu
OUT=${1:-deps-vendor.tar.gz}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cargo vendor --versioned-dirs "$WORK/vendor" > "$WORK/vendor-config.toml"
printf '\n' > "$WORK/config.toml"
sed -e 's|^directory = .*|directory = "vendor"|' "$WORK/vendor-config.toml" >> "$WORK/config.toml"
tar -czf "$OUT" -C "$WORK" vendor config.toml
printf 'wrote %s\n' "$OUT"
sha256sum "$OUT" | cut -d' ' -f1