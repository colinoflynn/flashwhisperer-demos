#!/bin/bash
# Build the victim, then say what the attack needs to know about the image.
#
#   ./build.sh                        # deps/riot, nrf52840dk
#   RIOTBASE=~/riot ./build.sh        # another checkout, pin still asserted
#   BINDIRBASE=~/b ./build.sh         # objects off a synced or /mnt/ volume
#
# The last two lines of output are the point: the image's SHA-256, and Te0's
# runtime address with the row offset that follows from it. A trace count
# without that address is under-specified, and tools/replay.py will not run
# without the geometry beside the vector.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
BOARD="${BOARD:-nrf52840dk}"
RIOTBASE="${RIOTBASE:-$ROOT/deps/riot}"
PIN=f59dcdace51d34218c24339d299ebc3777ec45bc

if [ ! -d "$RIOTBASE/boards/$BOARD" ]; then
    echo "no $RIOTBASE/boards/$BOARD." >&2
    echo "deps/riot is sparse-checked-out; a GNRC build needs more of the" >&2
    echo "tree than the FIDO2 demo does. Run:  ./deps/fetch.sh riot" >&2
    exit 1
fi

HAVE="$(git -C "$RIOTBASE" rev-parse HEAD 2>/dev/null || echo unknown)"
if [ "$HAVE" != "$PIN" ]; then
    echo "WARNING: RIOTBASE is at $HAVE, not $PIN" >&2
    echo "         every address and trace count in this demo is against the pin" >&2
fi

if [ ! -f "$HERE/demo_key.h" ]; then
    echo "note: no demo_key.h, so this builds on RIOT's own published default"
    echo "      key. python gen_key.py for a fresh one."
fi

make -C "$HERE" BOARD="$BOARD" RIOTBASE="$RIOTBASE" \
     ${BINDIRBASE:+BINDIRBASE="$BINDIRBASE"} "$@"

BIN="${BINDIRBASE:-$HERE/bin}/$BOARD/riot_802154_echo"
echo
echo "image      ${BIN}.bin"
echo "sha256     $(sha256sum "${BIN}.bin" | cut -d' ' -f1)"
python3 "$HERE/verify_build.py" "${BIN}.elf"
