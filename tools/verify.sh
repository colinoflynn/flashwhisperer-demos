#!/bin/bash
# Is this checkout in a state where numbers mean anything?
#
#   ./tools/verify.sh            # what this checkout needs for what is in it
#   ./tools/verify.sh --all      # every pin, fetched or not
#
# A vendor SDK that has not been fetched is NOT a failure by default: nothing
# can be built without it and the build says so loudly, while `tools/replay.py`
# and demo 00 need none of them. Only the `tool` pins are mandatory. Crying
# wolf about an SDK you have not needed yet is how a checker gets ignored.
#
# Run it before a capture and before believing a result. It is cheap, and the
# failures it catches all look like something else:
#
#   * a clone that exceeded MAX_PATH and ABORTED PART WAY THROUGH, leaving a
#     tree that looks complete. On Windows this is the single most common way
#     to get a repository that builds nothing and blames the toolchain.
#   * a dependency whose HEAD has moved off the pin, which is a different
#     measurement under the same name.
#   * a vendor tree with edits in it, which breaks the one claim these demos
#     rest on: the victim is the vendor's own code.
#   * a vector file that has changed since it was recorded.
#
# WHAT THIS DOES NOT CHECK, because a green checker that is not checking is
# worse than no checker:
#
#   * That a pinned commit is still published upstream. A force push or a
#     deleted mirror would leave a checkout here that nobody else can
#     reproduce; only a fresh clone on another machine finds that.
#   * That a `subtree` dependency is at the commit deps/PINS names. A subtree
#     has no HEAD of its own, so the check does not exist for it at all - see
#     the note at the top of the dependency loop below.
#   * That anything was BUILT, let alone built with the flags a demo needs.
#     Nothing here compiles. `make` in a demo directory is its own check.
#   * That a capture is a capture of what it says. The instrument's own
#     verification does that, by encrypting each captured input under the
#     victim's key and comparing with the captured output. This script never
#     looks at a measurement.
#   * Anything about demos/*/host/. That code is ours and is meant to change;
#     `git status` is its check.
#   * Whether the toolchain is the one the bench used. A codegen difference
#     changes the instruction stream, and the instruction stream is part of
#     what is being measured.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
all=0
for a in "$@"; do
    case "$a" in
      --all) all=1 ;;
      *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

pins() { grep -vE '^[[:space:]]*(#|$)' "$ROOT/deps/PINS"; }

# One file per dependency that MUST exist once it is fetched. This is the
# partial-checkout trap: the directory is there, the .git is there, HEAD is
# right, and the files are missing.
sentinel_for() {
    case "$1" in
      flashwhisperer) echo "flashattack/engine.py" ;;
      ethtimer)       echo "ethtimer/cli.py" ;;
      crypto-eval)    echo "libs/PINS" ;;
      stm32cube-f4)   echo "Drivers/STM32F4xx_HAL_Driver/Inc/stm32f4xx_hal.h" ;;
      stm32cube-l1)   echo "Drivers/STM32L1xx_HAL_Driver/Inc/stm32l1xx_hal.h" ;;
      uoscore-uedhoc) echo "externals/tinycrypt/lib/source/aes_encrypt.c" ;;
      x-cube-subg2)   echo "Projects/NUCLEO-F401RE" ;;
      riot)           echo "tests/sys/fido2_ctap_hid" ;;
      sbsfu)          echo "Middlewares/ST/STM32_Secure_Engine" ;;
      *)              echo "" ;;
    esac
}

echo "== dependencies: fetched, at the pin, and pristine =="
while read -r name url pin version kind; do
    dir="$ROOT/deps/$name"

    # A subtree is IN this repository: upstream's files, committed here, with
    # no .git of their own. So the two checks below do not apply to it and
    # cannot be made to - there is no HEAD to compare against the pin. What
    # can be checked is that the files are here; what cannot is that they are
    # the ones deps/PINS names. That weaker check is the price of vendoring,
    # and it is why these go back to being submodules once the upstream is
    # public. deps/README.md says how.
    if [ "$kind" = subtree ]; then
        s="$(sentinel_for "$name")"
        if [ -n "$s" ] && [ ! -e "$dir/$s" ]; then
            printf '  %-15s MISSING - %s is not here, so this is a partial\n' "$name" "$s"
            echo "                  checkout rather than a vendored subtree."
            fail=1
        else
            printf '  %-15s vendored as a subtree, recorded as %s\n' \
                "$name" "$(echo "$pin" | cut -c1-9)"
            echo "                  (not verifiable here: see deps/README.md)"
        fi
        continue
    fi

    if [ ! -e "$dir/.git" ]; then
        if [ "$kind" = tool ] || [ "$all" = 1 ]; then
            printf '  %-15s NOT FETCHED - run ./deps/fetch.sh %s\n' "$name" "$name"
            fail=1
        elif [ "$kind" = optional ]; then
            printf '  %-15s not fetched (optional)\n' "$name"
        else
            printf '  %-15s not fetched (only needed to BUILD a victim)\n' "$name"
        fi
        continue
    fi

    head=$(git -C "$dir" rev-parse HEAD)
    dirty=$(git -C "$dir" status --porcelain | wc -l | tr -d ' ')
    printf '  %-15s %s  %s modified/untracked\n' "$name" "$(echo "$head" | cut -c1-9)" "$dirty"

    if [ "$head" != "$pin" ]; then
        echo "    FAIL: HEAD is not the pin $pin from deps/PINS."
        echo "          A checkout that has moved is a different measurement."
        fail=1
    fi
    if [ "$dirty" != "0" ]; then
        echo "    FAIL: not pristine. These demos rest on the victim being"
        echo "          the vendor's own code; put your changes in the demo."
        git -C "$dir" status --porcelain | sed 's/^/            /'
        fail=1
    fi

    s="$(sentinel_for "$name")"
    if [ -n "$s" ] && [ ! -e "$dir/$s" ]; then
        echo "    FAIL: $s is missing although HEAD is right."
        echo "          That is a PARTIAL CHECKOUT, usually MAX_PATH on"
        echo "          Windows. Clone somewhere short, with"
        echo "          core.longpaths=true, and fetch again."
        fail=1
    fi

    # The gitlink the parent records has to agree with PINS, or a clone of
    # this repository gets a different version than this checkout has.
    if [ "$kind" != mirror ] && [ "$kind" != subtree ]; then
        link=$(git -C "$ROOT" ls-tree HEAD "deps/$name" | awk '{print $3}')
        if [ -n "$link" ] && [ "$link" != "$pin" ]; then
            echo "    FAIL: the committed gitlink is ${link:0:9}, PINS says ${pin:0:9}."
            fail=1
        fi
    fi
done < <(pins)

echo
echo "== the analysis half has to be importable =="
if python -c "import flashattack, flashsim" 2>/dev/null; then
    echo "  flashwhisperer   ok"
else
    echo "  flashwhisperer   NOT IMPORTABLE"
    echo "    run: pip install -e deps/flashwhisperer"
    fail=1
fi
if python -c "import ethtimer" 2>/dev/null; then
    echo "  ethtimer         ok"
else
    echo "  ethtimer         not importable (only the wired demos need it)"
fi

echo
echo "== vectors =="
if [ -f "$ROOT/captures/MANIFEST.tsv" ]; then
    python "$ROOT/tools/manifest.py" || fail=1
else
    echo "  no captures/MANIFEST.tsv yet"
fi

echo
if [ "$fail" = 0 ]; then
    echo "ok"
else
    echo "NOT ok - see above"
fi
exit $fail
