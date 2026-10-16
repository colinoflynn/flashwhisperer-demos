#!/bin/bash
# Show every deviation of this port from stock X-CUBE-SBSFU v2.7.0.
#
#   ./diff_vs_stock.sh              # summary: one line per file
#   ./diff_vs_stock.sh -v           # full unified diffs
#
# The brief for this rig was "as much as possible default/ST-provided, with
# obvious patches from that codebase".  That is only worth anything if it is
# checkable, and this is the check.  The Makefile and
# NUCLEO_L152RE/2_Images_SECoreBin/Inc/se_intrinsics.h both told the reader
# to run this script for some time before it existed; this is that script.
#
# It is the SAM D21 rig's diff_vs_stock.sh, pointed at this port's own
# directory and extended to cover the Secure Engine sources, which this
# build stages and can patch where the SAM D21 build could not.
#
# TWO THINGS IT NORMALISES, AND WHY NEITHER IS CHEATING
# ------------------------------------------------------
# 1. LINE ENDINGS.  ST ships CRLF; this repository pins LF in the working
#    tree via .gitattributes, because the firmware is built under WSL and
#    `#!/bin/bash\r` is not an interpreter.  Diffing without
#    --strip-trailing-cr reports 100% of lines changed and tells you
#    nothing.
#
# 2. NOTHING ELSE.  No whitespace flags, no comment stripping.  A comment
#    added to ST's source is a change to ST's source and shows up here.
#
# Files with no ST counterpart are listed as NEW.  That is the port seam:
# every board in ST's Projects/ tree has its own copy of these, and writing
# them is what porting is.  The HAL is not listed at all because this port
# keeps no copy of it -- it compiles out of the STM32CubeL1 checkout.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
src="${SBSFU_ROOT:-$(cd "$repo_root/.." && pwd)/sbsfu-src}"
stock="$src/Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash"

verbose=0
[ "${1:-}" = "-v" ] && verbose=1

if [ ! -d "$stock" ]; then
  echo "No SBSFU checkout at $src -- see ./fetch_cubel1.sh and the README." >&2
  exit 1
fi

echo "PORT DIRECTORY -- files this rig keeps its own copy of"
echo

changed=0
new=0
same=0

cd "$here/NUCLEO_L152RE"
while IFS= read -r f; do
  rel="${f#./}"
  case "$rel" in
    BSP/*) origin="" ;;
    *) origin="$rel" ;;
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

# The stronger half of the claim is the files with NO local copy: ST's
# sources the build compiles straight out of the checkout, which therefore
# cannot have been edited at all.  Listing them turns "we did not touch ST's
# code" from an assertion into a report.
cd "$here"
report_list() {
  local label="$1"; shift
  local patched=0
  echo
  echo "$label"
  for f in "$@"; do
    local base pat n shown
    base="$(basename "$f" .c)"
    # The Makefile writes SE paths through a variable; show the path, not
    # the unexpanded $(SE_MW).
    shown="${f##*\)/}"
    pat=$(ls patches/*"$base"*.patch 2>/dev/null | head -1 || true)
    if [ -n "$pat" ]; then
      n=$(grep -cE '^[+-][^+-]' "$pat" || true)
      printf '  PATCHED  %s  (%s, %d lines)\n' "$shown" \
        "$(basename "$pat")" "$n"
      patched=$((patched + 1))
      if [ "$verbose" = 1 ]; then
        sed 's/^/      /' "$pat"
      fi
    else
      printf '  stock    %s\n' "$shown"
    fi
  done
  echo "  ($patched carry a tracked patch, applied at build time into"
  echo "   build/ -- the checkout itself is never written to.)"
}

mk_list() {
  sed -n "/^$1 = /,/^\$/p" Makefile \
    | sed "s/^$1 = //; s/\\\\\$//" | tr -d ' ' | grep '\.c$' || true
}

mapfile -t stock_src < <(mk_list STOCK_SRC)
mapfile -t se_src < <(mk_list SE_SRC)
mapfile -t mbed_src < <(mk_list MBEDTLS_SRC)

report_list "SBSFU application sources, compiled from the checkout:" \
  "${stock_src[@]}"
report_list "Secure Engine sources, compiled from the checkout:" \
  "${se_src[@]}"

echo
echo "mbedTLS: ${#mbed_src[@]} files, all compiled from the checkout, none patched."
echo "  The config header se_mbedtls_config.h IS this port's own and is"
echo "  listed in the port section above."

echo
echo "A STOCK .c IS NOT THE SAME AS A STOCK BUILD OF IT.  The application"
echo "sources above are ST's byte for byte, but they are compiled against"
echo "THIS PORT'S headers -- app_sfu.h and sfu_fwimg_internal.h are both in"
echo "the changed list, and the second is what makes SFU_IMG_CHUNK_SIZE a"
echo "build option.  So \"sfu_fwimg_no_swap.c is stock\" means the loop's"
echo "code is ST's, not that its configuration is."
echo
echo "NOT COVERED BY THIS REPORT:"
echo "  * .ld files.  Linker_Common/mapping_*.ld are rewritten from ST's"
echo "    rather than diffed against them -- the slot layout is this part's."
echo "    mapping_fwimg.ld carries its own note on the resize and how to"
echo "    undo it."
echo "  * The HAL.  ST's STM32L1xx_HAL_Driver compiles out of the"
echo "    STM32CubeL1 checkout; this rig keeps no copy, so there is nothing"
echo "    to diff and nothing that could have been edited."
echo "  * Build-time configuration.  CHUNK, DIRECT_INSTALL, ORACLE and"
echo "    RAMTABLES change behaviour through -D flags, not through edits;"
echo "    the Makefile documents each one where it is defined."
echo "  * se_key.s, which gen_keys.sh generates from ST's demo keys."
echo "  * Whether a CHANGED file's change is SMALL.  The line counts are a"
echo "    size, not a judgement."
echo
echo "stock tree: $stock"
