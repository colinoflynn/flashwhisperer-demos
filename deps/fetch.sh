#!/bin/bash
# Fetch the pinned dependencies, SHALLOW AND SPARSE AND AT THE PIN.
#
#   ./deps/fetch.sh                # everything except the `optional` ones
#   ./deps/fetch.sh flashwhisperer ethtimer
#   ./deps/fetch.sh --tools        # just the two this repo cannot run without
#   ./deps/fetch.sh --size         # report what is on disk, fetch nothing
#
# WHY NOT `git submodule update --init --depth 1`. That clones the default
# BRANCH at depth 1, and several pins here are not in it - an ST Cube package
# pin is a release commit, not a branch tip. The result is a checkout of some
# other version under the right directory name, and for a vendor SDK that
# builds fine and measures something else. This is not hypothetical; it is how
# the crypto-eval repo's first attempt landed on a Mbed-TLS with no aes.c.
#
# WHY NOT `git submodule add` EITHER. It clones whole histories. STM32CubeF4
# and RIOT are enormous, this tree lives in a synced folder, and nothing here
# needs the history.
#
# So each dependency is an empty repository with one remote, a sparse-checkout
# set to the directories something here actually compiles or imports, and a
# single depth-1 fetch of the pinned COMMIT, which GitHub allows. Exact, small,
# and it cannot drift.
#
# WHAT THIS DOES NOT DO
#   * It does not patch anything. Every victim's deviation from its vendor tree
#     lives in that demo's own directory and is applied by that demo's build
#     script, so `diff` against a fresh fetch is the check.
#   * It does not fetch X-CUBE-SBSFU's siblings. The sbsfu sparse list is the
#     UNION of what every SBSFU port needs, because they share one clone and
#     one pin; `git sparse-checkout set` replaces the list, so dropping a line
#     here breaks another port's build.
#   * It does not install a toolchain. arm-none-eabi-gcc, MPLAB X v6.20 and
#     XC32 are yours to install; deps/README.md says which versions.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# Only the directories something here compiles from or imports. Cone mode, so
# these are directory prefixes; everything else stays in the object store and
# off the disk. An empty string means a full checkout.
sparse_for() {
    case "$1" in
      stm32cube-f4)
          # HAL + CMSIS + the two middlewares the victims build, plus the PHY
          # driver the Nucleo's Ethernet needs. Drivers/ whole rather than its
          # three subtrees: a cone sparse-checkout refuses a path that is a
          # SUBMODULE rather than a directory, and the HAL and CMSIS device
          # headers are submodules. Naming the parent sidesteps that.
          echo "Drivers Middlewares/Third_Party/LwIP Middlewares/Third_Party/mbedTLS" ;;
      stm32cube-l1)
          echo "Drivers Projects/NUCLEO-L152RE/Examples/SPI Projects/NUCLEO-L152RE/Templates" ;;
      uoscore-uedhoc)
          echo "src inc externals" ;;
      x-cube-subg2)
          echo "Drivers Middlewares Projects/NUCLEO-F401RE Projects/NUCLEO-L152RE" ;;
      riot)
          echo "" ;;        # RIOT's build reaches all over its own tree
      sbsfu)
          echo "Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash \
                Projects/NUCLEO-L073RZ/Applications/2_Images \
                Middlewares/ST/STM32_Secure_Engine \
                Middlewares/Third_Party/mbedtls \
                Drivers/CMSIS/Core \
                Drivers/STM32L4xx_HAL_Driver \
                Drivers/CMSIS/Device/ST/STM32L4xx \
                Drivers/BSP/B-L475E-IOT01 \
                Drivers/BSP/Components/Common \
                Drivers/BSP/Components/mx25r6435f" ;;
      *)  echo "" ;;
    esac
}

# Submodules OF a dependency that have to be initialised, because the package
# keeps its drivers that way and a sparse checkout leaves empty directories.
subs_for() {
    case "$1" in
      stm32cube-f4) echo "Drivers/CMSIS/Device/ST/STM32F4xx \
                          Drivers/STM32F4xx_HAL_Driver \
                          Drivers/BSP/STM32F4xx-Nucleo \
                          Drivers/BSP/Components/lan8742" ;;
      stm32cube-l1) echo "Drivers/CMSIS/Device/ST/STM32L1xx \
                          Drivers/STM32L1xx_HAL_Driver \
                          Drivers/BSP/STM32L1xx_Nucleo" ;;
      *) echo "" ;;
    esac
}

# The file that states the version, and the string to find in it. A package
# that quietly changed underneath a port produces a build that compiles and is
# not the thing the write-up describes.
assert_for() {
    case "$1" in
      sbsfu)        echo "Release_Notes.html" ;;
      stm32cube-f4) echo "Release_Notes.html" ;;
      stm32cube-l1) echo "Release_Notes.html" ;;
      *)            echo "" ;;
    esac
}

pins() { grep -vE '^[[:space:]]*(#|$)' "$HERE/PINS"; }

want=()
only_tools=0
report=0
for a in "$@"; do
    case "$a" in
      --tools) only_tools=1 ;;
      --size)  report=1 ;;
      -*)      echo "unknown option: $a" >&2; exit 2 ;;
      *)       want+=("$a") ;;
    esac
done

if [ "$report" = 1 ]; then
    while read -r name url pin version kind; do
        dir="$HERE/$name"
        if [ -e "$dir/.git" ]; then
            size=$(du -sh "$dir" 2>/dev/null | cut -f1)
            head=$(git -C "$dir" rev-parse HEAD 2>/dev/null | cut -c1-9)
            printf '  %-15s %-8s %s\n' "$name" "$size" "$head"
        else
            printf '  %-15s %-8s %s\n' "$name" "-" "not fetched"
        fi
    done < <(pins)
    exit 0
fi

fetch_one() {
    local name="$1" url="$2" pin="$3" version="$4"
    local dir="$HERE/$name"
    local sparse subs want_file

    echo "== $name $version  ${pin:0:9}"
    mkdir -p "$dir"
    if [ ! -e "$dir/.git" ]; then
        # core.longpaths is NOT optional on Windows. Several paths inside the
        # ST packages exceed MAX_PATH and the checkout fails HALF DONE, leaving
        # a tree that looks complete. tools/verify.sh is what catches that.
        git -C "$dir" -c core.longpaths=true init -q
        git -C "$dir" remote add origin "$url"
    fi
    git -C "$dir" config core.longpaths true

    sparse="$(sparse_for "$name")"
    if [ -n "$sparse" ]; then
        git -C "$dir" sparse-checkout init --cone
        # shellcheck disable=SC2086
        git -C "$dir" sparse-checkout set $sparse
    fi

    if ! git -C "$dir" cat-file -e "$pin^{commit}" 2>/dev/null; then
        git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$pin"
    fi
    git -C "$dir" checkout -q --detach "$pin"

    subs="$(subs_for "$name")"
    if [ -n "$subs" ]; then
        # shellcheck disable=SC2086
        git -C "$dir" submodule update -q --init --depth 1 -- $subs
    fi

    want_file="$(assert_for "$name")"
    if [ -n "$want_file" ]; then
        if [ ! -f "$dir/$want_file" ]; then
            echo "   FAIL: $want_file is missing - this is not the tree it claims" >&2
            return 1
        fi
        if ! grep -qi "$version" "$dir/$want_file"; then
            echo "   FAIL: $want_file does not mention $version." >&2
            echo "         The upstream's content changed; re-read it before" >&2
            echo "         trusting anything built from this." >&2
            return 1
        fi
    fi
    echo "   ok"
}

rc=0
while read -r name url pin version kind; do
    if [ ${#want[@]} -gt 0 ]; then
        printf '%s\n' "${want[@]}" | grep -qx "$name" || continue
    else
        [ "$kind" = optional ] && continue
        [ "$only_tools" = 1 ] && [ "$kind" != tool ] && continue
    fi
    fetch_one "$name" "$url" "$pin" "$version" || rc=1
done < <(pins)

if [ "$rc" = 0 ]; then
    echo
    echo "Now: pip install -e deps/flashwhisperer -e deps/ethtimer"
    echo "Then: ./tools/verify.sh"
fi
exit $rc
