#!/usr/bin/env bash
# Stage the listener application into a fetched x-cube-subg2 tree.
#
#     instruments/sniff802154/stage.sh deps/x-cube-subg2
#
# The listener is ST's own CUSTOM_FIFO_RX example with four files replaced, so
# that is what this ships: the four files, not a copy of ST's project. It
# copies the example to ATK_SNIFF (same depth, because the CubeIDE project
# resolves its linked sources as PARENT-n-PROJECT_LOC) and drops the overlay on
# top, for both boards.
#
# `diff_vs_stock.sh` is the other half: it tells you exactly what the overlay
# changes, against the tree you fetched rather than against a claim.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-}"
[ -n "$SRC" ] && [ -d "$SRC/Projects" ] || {
    echo "usage: stage.sh <path to a fetched x-cube-subg2>" >&2; exit 2; }
SRC="$(cd "$SRC" && pwd)"

stage_one () {   # stage_one <board dir> <overlay dir>
    local board="$1" ov="$2"
    local ex="$SRC/Projects/$board/Examples"
    [ -d "$ex/CUSTOM_FIFO_RX" ] || {
        echo "   $board: no CUSTOM_FIFO_RX example - is this a sparse checkout" >&2
        echo "   that left Projects/$board out? See deps/fetch.sh" >&2
        exit 1; }
    rm -rf "$ex/ATK_SNIFF"
    cp -r "$ex/CUSTOM_FIFO_RX" "$ex/ATK_SNIFF"
    (cd "$HERE/overlay/$ov" && find . -type f) | while read -r f; do
        cp "$HERE/overlay/$ov/$f" "$ex/ATK_SNIFF/$f"
    done
    echo "   $board: ATK_SNIFF staged, $(cd "$HERE/overlay/$ov" && find . -type f | wc -l | tr -d ' ') files replaced"
}

stage_one NUCLEO-F401RE f401
stage_one NUCLEO-L152RE l152
