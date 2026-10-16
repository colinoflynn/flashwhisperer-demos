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
#   * mbedTLS, Secure Engine, CMSIS and STM32L1xx HAL headers.  Those are
#     included as "mbedtls/<x>.h" or live in directories this port overrides
#     nothing in, so the own-directory rule cannot pick a wrong copy.  They
#     stay on -I.
#   * Basename collisions WITHIN ST's own tree: flattening would silently
#     drop one.  Checked below rather than assumed.
set -euo pipefail

dest="${1:?usage: stage_headers.sh <dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
src="${SBSFU_ROOT:-$(cd "$repo_root/.." && pwd)/sbsfu-src}"
stock="$src/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash"

ST_DIRS=(
  "$stock/2_Images_SBSFU/Core/Inc"
  "$stock/2_Images_SBSFU/SBSFU/App"
  "$stock/2_Images_SBSFU/SBSFU/Target"
  "$stock/2_Images_SECoreBin/Inc"
  "$stock/Linker_Common/STM32CubeIDE"
)

mkdir -p "$dest"

# 1. ST's headers, flattened, CRLF -> LF.  Refuse on a basename collision:
#    flattening two different headers with the same name would drop one, and
#    which one survived would depend on directory order.
declare -A seen=()
for d in "${ST_DIRS[@]}"; do
  [ -d "$d" ] || continue
  for f in "$d"/*.h; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    # stm32* headers from ST'S PROJECT are not staged, and here that means
    # something different from what it meant on the SAM D21.  That port had
    # no STM32 HAL at all; this one has the real STM32L1xx HAL.  What must
    # not be staged is the L475 project's own stm32l4xx_hal_conf.h -- wrong
    # family entirely -- and ST ships TWO of those, in Core/Inc and in
    # SECoreBin/Inc, with different contents, so flattening would silently
    # keep one.  This port's stm32l1xx_hal_conf.h is staged below as a NEW
    # header, and the HAL's own stm32l1xx_*.h stay on -I where they are.
    case "$b" in
      stm32*) continue ;;
    esac
    if [ -n "${seen[$b]:-}" ]; then
      echo "FAIL: two ST headers named $b:" >&2
      echo "        ${seen[$b]}" >&2
      echo "        $f" >&2
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
done < <(find "$here/NUCLEO_L152RE" -name '*.h' | sort)

echo "staged headers: $st_count from ST, $shadowed replaced by this port, $added new"
