#!/bin/bash
# Show every deviation of this port from stock X-CUBE-SBSFU v2.7.0.
#
#   ./diff_vs_stock.sh              # summary: one line per file
#   ./diff_vs_stock.sh -v           # full unified diffs
#
# The realism claim this demo rests on -- "as close to a real deployment as
# possible, and where it differs, differing the way a user would" -- is only
# worth anything if it is checkable.  This is the check.  It answers, for
# every file under SAMD21_XPRO/ that also exists in ST's tree, exactly what
# changed.
#
# TWO THINGS IT NORMALISES, AND WHY NEITHER IS CHEATING
# ------------------------------------------------------
# 1. LINE ENDINGS.  ST ships CRLF; this repository pins LF in the working
#    tree via .gitattributes, because the firmware is built under WSL and
#    `#!/bin/bash\r` is not an interpreter.  Every copied file was therefore
#    converted on the way in.  Diffing without --strip-trailing-cr reports
#    100% of lines changed and tells you nothing, which is exactly what
#    happened the first time this was checked by hand.
#
# 2. NOTHING ELSE.  No whitespace flags, no comment stripping.  A comment
#    added to ST's source is a change to ST's source and shows up here.
#
# Files with no ST counterpart -- the HAL, the BSP, the SAM D21 sfu_low_level*
# and se_low_level -- are listed as NEW.  Those are the port seam: every board
# in ST's Projects/ tree has its own, and writing them is what porting is.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
src="${SBSFU_ROOT:-$(cd "$repo_root/.." && pwd)/sbsfu-src}"
stock="$src/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash"

verbose=0
[ "${1:-}" = "-v" ] && verbose=1

if [ ! -d "$stock" ]; then
  echo "No SBSFU checkout at $src -- run ./fetch_sbsfu.sh first." >&2
  exit 1
fi

# Where a copied file lives in ST's tree, when the path is not identical.
declare -A REMAP=(
  ["Linker_Common/mapping_export.h"]="Linker_Common/STM32CubeIDE/mapping_export.h"
)

changed=0
new=0
same=0

cd "$here/SAMD21_XPRO"
while IFS= read -r f; do
  rel="${f#./}"
  case "$rel" in
    HAL/*|BSP/*) origin="" ;;
    *) origin="${REMAP[$rel]:-$rel}" ;;
  esac

  if [ -z "$origin" ] || [ ! -f "$stock/$origin" ]; then
    printf '  NEW      %s\n' "$rel"
    new=$((new + 1))
    continue
  fi

  n=$(diff --strip-trailing-cr -u "$stock/$origin" "$rel" 2>/dev/null \
      | grep -cE '^[+-]' || true)
  # a unified diff of a changed file always has the two +++/--- header lines
  n=$((n > 2 ? n - 2 : 0))
  if [ "$n" -eq 0 ]; then
    printf '  same     %s\n' "$rel"
    same=$((same + 1))
  else
    printf '  CHANGED  %s  (%d lines)\n' "$rel" "$n"
    changed=$((changed + 1))
    if [ "$verbose" = 1 ]; then
      diff --strip-trailing-cr -u "$stock/$origin" "$rel" | sed 's/^/      /'
    fi
  fi
done < <(find . -name '*.c' -o -name '*.h' | sort)

echo
echo "unchanged from ST: $same     changed: $changed     new (port seam): $new"

# The section above only covers files that have a copy under SAMD21_XPRO/.
# The stronger half of the realism claim is the files that DO NOT -- ST's
# sources the build compiles straight out of the checkout, which therefore
# cannot have been edited at all.  Listing them is what turns "we did not
# touch ST's code" from an assertion into a report.
echo
echo "ST sources compiled from the checkout (no local copy exists, so no edit is possible):"
cd "$here"
patched_any=0
for f in $(sed -n '/^STOCK_SRC = /,/^$/p' Makefile \
           | sed 's/^STOCK_SRC = //; s/\\$//' | tr -d ' ' | grep '\.c$'); do
  pat=$(ls patches/*"$(basename "$f" .c)"*.patch 2>/dev/null | head -1 || true)
  if [ -n "$pat" ]; then
    n=$(grep -cE '^[+-][^+-]' "$pat" || true)
    printf '  PATCHED  %s  (%s, %d lines)\n' "$f" "$(basename "$pat")" "$n"
    patched_any=$((patched_any + 1))
  else
    printf '  stock    %s\n' "$f"
  fi
done
echo
echo "  ($patched_any of them carry a tracked patch, applied at build time into"
echo "   build/src/ -- the checkout itself is never written to.)"

echo
echo "NOT COVERED BY THIS REPORT:"
echo "  * .ld files.  The linker scripts are this port's own and have no ST"
echo "    counterpart with the same name; Linker_Common/mapping_*.ld are"
echo "    rewritten from ST's, not diffed against them."
echo "  * Middlewares/.  The Secure Engine and mbedTLS compile from the"
echo "    checkout untouched, but nothing here re-verifies that."
echo "  * Whether a CHANGED file's change is SMALL.  The line counts above are"
echo "    a size, not a judgement -- sfu_low_level_security.c reads as 1377"
echo "    changed lines because it is a rewrite, which is what a board port is"
echo "    supposed to do to that file."
echo
echo "stock tree: $stock"
