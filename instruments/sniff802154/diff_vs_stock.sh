#!/usr/bin/env bash
# What the listener overlay changes, against the vendor tree you fetched.
#
#     instruments/sniff802154/diff_vs_stock.sh deps/x-cube-subg2 [--stat]
#
# The listener is the attacker, so nothing about it has to be stock - this is
# here so you can see how much of it is ours before trusting anything it
# measured, and so a vendor bump that moves the example shows up as a diff
# rather than as a silent rebuild.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-}"
STAT="${2:-}"
[ -n "$SRC" ] && [ -d "$SRC/Projects" ] || {
    echo "usage: diff_vs_stock.sh <path to a fetched x-cube-subg2> [--stat]" >&2
    exit 2; }
SRC="$(cd "$SRC" && pwd)"

for pair in "NUCLEO-F401RE f401" "NUCLEO-L152RE l152"; do
    set -- $pair
    board="$1"; ov="$2"
    ex="$SRC/Projects/$board/Examples/CUSTOM_FIFO_RX"
    echo "== $board"
    (cd "$HERE/overlay/$ov" && find . -type f) | while read -r f; do
        if [ "$STAT" = "--stat" ]; then
            printf '   %-44s ' "${f#./}"
            diff --strip-trailing-cr "$ex/$f" "$HERE/overlay/$ov/$f" \
                | grep -c '^[<>]' || true
        else
            diff -u --strip-trailing-cr "$ex/$f" "$HERE/overlay/$ov/$f" || true
        fi
    done
done
