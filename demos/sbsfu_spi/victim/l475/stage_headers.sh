#!/bin/bash
# Build the ONE effective header tree the whole firmware compiles against.
#
#   ./stage_headers.sh <build-dir>/inc
#
# WHY THIS EXISTS -- THE SAME BUG, TWICE, ONE LEVEL APART
# --------------------------------------------------------
# A quoted #include searches the INCLUDING FILE'S OWN DIRECTORY first, before
# any -I.  That is not overridable: not by -I order, not by -iquote.
#
# The first time it bit the SAM D21 port, ST's .c files were being compiled
# in ST's own App/ directory, so their `#include "sfu_fwimg_internal.h"`
# found ST's copy instead of the port's.  Staging the .c files into a
# header-free directory fixed that -- for the .c files.
#
# It did not fix the headers.  ST's sfu_fwimg_regions.h lives in ST's App/
# and does `#include "app_sfu.h"`, with ST's app_sfu.h sitting right next to
# it.  So ST's header won again, one level deeper.
#
# Chasing that one level at a time is a losing game.  The fix is to stop
# having two copies of any header visible at once: copy ST's headers into
# one flat directory, then copy this port's over the top, and compile
# against that single tree.  After this there is exactly ONE app_sfu.h
# reachable, and which one it is does not depend on who is including it.
#
# WHAT IT DOES NOT COVER
#   * mbedTLS, Secure Engine, CMSIS, STM32L4xx HAL and BSP headers.  Those
#     are included as "mbedtls/<x>.h" or live in directories this port
#     overrides nothing in, so the own-directory rule cannot pick a wrong
#     copy.  They stay on -I.  THE ONE EXCEPTION is se_intrinsics.h, which
#     this port DOES shadow: it is staged below along with the port's other
#     headers, and the staged tree is searched before $(SE_MW)/Core, so
#     every Secure Engine source picks up the port's copy.
#   * Basename collisions WITHIN ST's own tree.  Flattening would silently
#     drop one, so they are refused -- bar one documented case, below.
set -euo pipefail

dest="${1:?usage: stage_headers.sh <dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
src="${SBSFU_ROOT:-$(cd "$repo_root/.." && pwd)/sbsfu-src}"
stock="$src/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash"

# Order matters for the ONE allowed collision: the first directory listed
# wins it.  See WINS_COLLISION below.
ST_DIRS=(
  "$stock/2_Images_SBSFU/Core/Inc"
  "$stock/2_Images_SBSFU/SBSFU/App"
  "$stock/2_Images_SBSFU/SBSFU/Target"
  "$stock/2_Images_SECoreBin/Inc"
  "$stock/Linker_Common/STM32CubeIDE"
)

# stm32l4xx_hal_conf.h exists TWICE in ST's project, in Core/Inc and in
# SECoreBin/Inc, with different contents: the SE core's copy enables fewer
# HAL modules (no QSPI, no UART, no CORTEX, ...).  ST can ship two because
# ST builds two binaries; this rig links ONE, so one of them has to win.
#
# Core/Inc's wins, and it is the safe direction: a module enable decides
# which HEADERS and prototypes are visible, not which objects are linked, so
# the superset cannot remove anything the SE core needs -- while the SE
# core's copy would hide HAL_QSPI_* from the BSP and HAL_UART_* from the
# trace path.  The Makefile's HAL_SRC is what actually decides the footprint.
declare -A WINS_COLLISION=( ["stm32l4xx_hal_conf.h"]="Core/Inc" )

mkdir -p "$dest"

# 1. ST's headers, flattened, CRLF -> LF.  Refuse on a basename collision
#    that is not the documented one: flattening two different headers with
#    the same name would drop one, and which one survived would depend on
#    directory order.
declare -A seen=()
for d in "${ST_DIRS[@]}"; do
  [ -d "$d" ] || continue
  for f in "$d"/*.h; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    if [ -n "${seen[$b]:-}" ]; then
      if [ -n "${WINS_COLLISION[$b]:-}" ]; then
        # Already staged from the earlier directory, which is the winner.
        # Report it rather than pass over it in silence.
        echo "collision: $b kept from ${WINS_COLLISION[$b]}, ignored $f"
        continue
      fi
      echo "FAIL: two ST headers named $b:" >&2
      echo "        ${seen[$b]}" >&2
      echo "        $f" >&2
      echo "      Add it to WINS_COLLISION with a reason, or keep them apart." >&2
      exit 1
    fi
    seen[$b]="$f"
    tr -d '\r' < "$f" > "$dest/$b"
  done
done
st_count=${#seen[@]}

# 2. This port's headers on top.  Every one of these SHADOWS an ST header or
#    is new; both are reported, because "I added a header" and "I replaced
#    ST's" are different claims.
shadowed=0
added=0
while IFS= read -r f; do
  b="$(basename "$f")"
  if [ -n "${seen[$b]:-}" ]; then
    shadowed=$((shadowed + 1))
  else
    added=$((added + 1))
  fi
  tr -d '\r' < "$f" > "$dest/$b"
done < <(find "$here/B_L475E_IOT01A" -name '*.h' | sort)

echo "staged headers: $st_count from ST, $shadowed replaced by this port, $added new"
