#!/usr/bin/env bash
# Build the three-node 802.15.4 rig out of the pinned vendor sources.
#
#     ./deps/fetch.sh x-cube-subg2
#     demos/ota_802154/victim/build_rig.sh --key 000102030405060708090a0b0c0d0e0f
#
# The victim is the node under attack and it has to be auditable, so the only
# thing between ST's sources and the image is `rig.patch`: 62 added lines
# across 4 files with ZERO deletions, every hunk an `#ifndef` guard or a new
# `#ifdef` block. With no -D flags it compiles to upstream behaviour exactly.
# Check that rather than believing it - the script prints the numstat, and the
# deletions column must be 0.
#
# The COORDINATOR is only a traffic source and is freely modified. The SNIFFER
# is the attacker, it is ours, and it lives in instruments/sniff802154.
#
# The vendor tree is PATCHED IN PLACE and put back afterwards, because
# tools/verify.sh rightly fails on a dependency with edits in it. Pass --keep
# if you want to look at the patched tree, and remember to
# `git -C deps/x-cube-subg2 checkout -- . && git -C deps/x-cube-subg2 clean -fd`
# before you trust verify.sh again.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SRC="$ROOT/deps/x-cube-subg2"
SNIFF="$ROOT/instruments/sniff802154"

# The Makefile reaches its sources as $(PKG)/Projects/... and turns them into
# object paths relative to its own directory, so the build directory has to sit
# at a fixed relative depth from the package. build/ is gitignored.
OUTDIR="$ROOT/build/ota_802154"
KEY=""
PANID=0xBEEF
DATARATE=250000
FREQ_DEVIATION=125e3
BANDWIDTH=500.0e3
INTERVAL_MS=20
PAYLOAD=24
KEEP=0
MAC_COORD=0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
MAC_VICTIM=0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02
SNIFFER_BOARD=${SNIFFER_BOARD:-NUCLEO-L152RE}

while [ $# -gt 0 ]; do
  case "$1" in
    --key)      KEY="$2"; shift 2 ;;
    --outdir)   OUTDIR="$2"; shift 2 ;;
    --panid)    PANID="$2"; shift 2 ;;
    --datarate) DATARATE="$2"; shift 2 ;;
    --interval) INTERVAL_MS="$2"; shift 2 ;;
    --payload)  PAYLOAD="$2"; shift 2 ;;
    --keep)     KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$KEY" ] || { echo "ERROR: --key <32 hex chars> is required." >&2; exit 2; }
[ "${#KEY}" -eq 32 ] || { echo "ERROR: --key must be exactly 32 hex chars (16 bytes), got ${#KEY}." >&2; exit 2; }
echo "$KEY" | grep -qiE '^[0-9a-f]{32}$' || { echo "ERROR: --key must be hex." >&2; exit 2; }

# The key becomes a BARE COMMA LIST, never a brace initializer. The shell
# brace-expands {a,b,c} into separate words, which silently turns one -D into
# sixteen and leaves the macro defined as its last byte - and it compiles far
# enough to look plausible. The braces are added inside the header instead.
KEY_LIST=$(echo "$KEY" | sed 's/\(..\)/0x\1,/g; s/,$//')

command -v arm-none-eabi-gcc >/dev/null || { echo "ERROR: arm-none-eabi-gcc not on PATH." >&2; exit 1; }
command -v python3          >/dev/null || { echo "ERROR: python3 not on PATH (cubeproj.py needs it)." >&2; exit 1; }

[ -d "$SRC/.git" ] || { echo "ERROR: $SRC is not fetched. Run ./deps/fetch.sh x-cube-subg2" >&2; exit 1; }
PIN=$(grep -E '^x-cube-subg2[[:space:]]' "$ROOT/deps/PINS" | awk '{print $3}')
GOT=$(git -C "$SRC" rev-parse HEAD)
[ "$GOT" = "$PIN" ] || { echo "ERROR: deps/x-cube-subg2 is at $GOT, deps/PINS says $PIN" >&2; exit 1; }
if [ -n "$(git -C "$SRC" status --porcelain)" ]; then
  echo "ERROR: deps/x-cube-subg2 already has edits in it. Put it back first:" >&2
  echo "       git -C deps/x-cube-subg2 checkout -- . && git -C deps/x-cube-subg2 clean -fd" >&2
  exit 1
fi

cleanup () {
  [ "$KEEP" = 1 ] && return 0
  git -C "$SRC" checkout -- . 2>/dev/null || true
  git -C "$SRC" clean -qfd 2>/dev/null || true
}
trap cleanup EXIT

echo "== vendor sources: x-cube-subg2 @ ${PIN:0:12}, pristine"
echo "== applying rig.patch"
git -C "$SRC" apply --whitespace=nowarn "$HERE/rig.patch"
echo "   victim diff (the deletions column must be 0):"
git -C "$SRC" diff --numstat -- '*S2915A1_UDP_Client*' | sed 's/^/     /'

echo "== staging the listener application"
"$SNIFF/stage.sh" "$SRC"

mkdir -p "$OUTDIR"
cp "$HERE/Makefile" "$HERE/cubeproj.py" "$OUTDIR/"
PKG=$(python3 -c "import os,sys;print(os.path.relpath(sys.argv[1], sys.argv[2]))" \
      "$SRC" "$OUTDIR")

RF="DATARATE=$DATARATE FREQ_DEVIATION=$FREQ_DEVIATION BANDWIDTH=$BANDWIDTH"
LOGS="LOG_CONF_LEVEL_MAC=0 LOG_CONF_LEVEL_RPL=0"

cd "$OUTDIR"
build () {  # build <board> <app> <outdir> <extra defines...>
  local board="$1" app="$2" out="$3"; shift 3
  echo "== building $app -> out/$out"
  rm -rf "out/$out"
  make BOARD="$board" APP="$app" CONFIG=release PKG="$PKG" \
       OUT="out/$out" EXTRA_DEFINES="$*" > "out-$out.log" 2>&1 || {
         echo "   FAILED, see $OUTDIR/out-$out.log" >&2; tail -20 "out-$out.log" >&2; exit 1; }
  # `grep -c` exits 1 when the count is ZERO, which under `set -e` means a
  # perfectly clean build aborts the script. || true, every time.
  { grep -icE ': error|: warning' "out-$out.log" || true; } | sed 's/^/   warnings+errors: /'
  arm-none-eabi-size "out/$out"/*.elf | tail -1 | sed 's/^/   /'
}

build NUCLEO-F401RE S2915A1_UDP_Client victim \
  "$RF $LOGS IEEE802154_CONF_PANID=$PANID RIG_KEY=$KEY_LIST NODE_MAC_FIXED=$MAC_VICTIM"
# CSMA_CONF_MAX_BE and QUEUEBUF_CONF_NUM are TRANSMIT-side settings and belong
# only here. MEASURED: at upstream defaults the rig ran at 10.9 records/s with
# 18.6 % of data frames never acknowledged; with MAX_BE=5 and 16 queuebufs it
# runs at 49.9 records/s with 0.09 %. The victim keeps upstream's values,
# because its soft ACK is a direct NETSTACK_RADIO.send that never goes through
# csma_output - so nothing about the measured path depends on them.
build NUCLEO-F401RE S2915A1_UDP_Server coord \
  "$RF $LOGS IEEE802154_CONF_PANID=$PANID RIG_KEY=$KEY_LIST NODE_MAC_FIXED=$MAC_COORD \
   MAC_GEN=1 MAC_GEN_INTERVAL_MS=$INTERVAL_MS MAC_GEN_PAYLOAD=$PAYLOAD \
   CSMA_CONF_MAX_BE=5 QUEUEBUF_CONF_NUM=16"
# The listener never learns the key. It gets the band and the rate so it can
# hear the link, and the victim's address so it pairs only the target's ACKs.
build "$SNIFFER_BOARD" ATK_SNIFF sniffer \
  "BASE_FREQUENCY=915.0e6 $RF SNIFF_DST=$MAC_VICTIM"

echo
echo "== verifying the flags actually landed in the images"
python3 "$HERE/verify_build.py" "$OUTDIR/out" "$KEY" "$DATARATE"

echo
echo "== S-box row offset, per image. It is NOT a constant: derive it every time"
# Two builds of these same sources have landed on 4 and 12, and a wrong offset
# costs 2.18x in traces without announcing itself. The number goes in the
# vector's json beside the capture it was taken with.
for v in victim coord; do
  printf '   %-8s ' "$v"
  python3 -c "
import glob, sys
from flashleak.placement import row_offset_from_image
elf = glob.glob(sys.argv[1] + '/*.elf')[0]
off, addr, note = row_offset_from_image(elf, part='stm32f4')
print('row offset %s   %s' % (off, note))
" "$OUTDIR/out/$v" 2>/dev/null || echo "(no flashleak here: pip install -e deps/flashwhisperer, or read it in the shell that has it)"
done

cat <<EOF

Done. Images under $OUTDIR/out:
   victim    out/victim/S2915A1_UDP_Client.bin     EUI-64 ...:02
   coord     out/coord/S2915A1_UDP_Server.bin      EUI-64 ...:01
   sniffer   out/sniffer/ATK_SNIFF.bin             LD2 blinks per paired record

Both Contiki nodes come up on power alone: no serial command, no host, no USB
enumeration. The listener's console is 921600 and is the only one to read.
EOF
