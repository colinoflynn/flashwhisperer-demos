#!/bin/bash
# Build both user-presence variants SEQUENTIALLY and report their sizes.
#
# Sequentially matters: the rig patches RIOT's own Makefile and restores it, which is not
# concurrency-safe. Two builds launched at once raced over the backup file on 2026-09-28,
# and while RIOT's Makefile survived pristine, the resulting binary's UP setting was
# unknowable. Differing sizes are the evidence that the flag took effect at all.
set -u
RIOT="${1:-../../../riot}"
cd "$(dirname "$0")"
for v in 0 1; do
    [ "$v" = 0 ] && echo "=== user presence ENABLED (shipping default) ===" \
                 || echo "=== user presence DISABLED (campaign victim's setting) ==="
    if make RIOT="$RIOT" DISABLE_UP="$v" >/tmp/dongle.$v.log 2>&1; then
        hex=$(ls "$RIOT"/tests/sys/fido2_ctap_hid/bin/nrf52840dongle/*.hex 2>/dev/null | head -1)
        grep -E "^ +text" -A 1 /tmp/dongle.$v.log | tail -1 | awk '{print "  text "$1" data "$2" bss "$3}'
        [ -n "$hex" ] && cp "$hex" "./fido2ctaphid_up$( [ "$v" = 0 ] && echo on || echo off ).hex" \
            && echo "  saved fido2ctaphid_up$( [ "$v" = 0 ] && echo on || echo off ).hex ($(stat -c%s "$hex") bytes)"
    else
        echo "  BUILD FAILED:"; tail -4 /tmp/dongle.$v.log | sed 's/^/    /'
    fi
done
