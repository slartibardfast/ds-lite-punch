#!/usr/bin/env bash
# The local gate, in one command: the generated artifacts, the suite, the comment lint and the link check, with no pipeline to mask a failure. Run it from the repository root as: bash tools/check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# The generator reads the version from the manifest, and the lane fails on any diff, so a bump or a flag change belongs in the same commit as its regenerated files.
cargo run --quiet --manifest-path tools/argdoc/Cargo.toml --target x86_64-unknown-linux-gnu
git diff --exit-code -- src/help.txt deploy/man/ds-lite-punch.8

cargo test --release --locked
python3 tools/comment-lint.py
sh tools/link-check.sh

echo "check: the generated artifacts, the suite, the comment lint and the link check all pass"