#!/bin/sh
# Check that every relative link in the authored docs resolves to a file in this
# repository. External links are not fetched, so the check stays offline and
# cannot fail because of a network.
#
# Run from the repository root:
#   sh tools/link-check.sh
set -u

missing=0
for doc in README.md docs/index.md docs/operators/*.md; do
    [ -f "$doc" ] || continue
    dir=$(dirname "$doc")
    for target in $(grep -o ']([^)]*)' "$doc" | sed 's/^](//; s/)$//'); do
        case "$target" in
            http://*|https://*|mailto:*|"") continue ;;
        esac
        path=${target%%#*}
        [ -n "$path" ] || continue
        if [ ! -e "$dir/$path" ]; then
            echo "$doc: broken link: $target"
            missing=1
        fi
    done
done

[ "$missing" -eq 0 ] || exit 1
echo "link check: every relative link in the authored docs resolves"