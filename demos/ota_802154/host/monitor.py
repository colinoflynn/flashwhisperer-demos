"""Judge a multi-hour capture WHILE it runs, without the key.

A 16-hour capture is a bad thing to analyse only at the end, and the obvious
progress meter - "how many bytes does the vote get right" - needs the answer.
This one does not.

Contiki-NG's SubBytes runs over the state in index order, so every pair of
adjacent rows in a column is two consecutive S-box reads and four pair sets are
attackable. Each covers 8 of the 16 round-10 bytes:

    r0r1 -> 0,1,4,5,8,9,12,13        r1r2 -> 1,2,5,6,9,10,13,14
    r2r3 -> 2,3,6,7,10,11,14,15      r0r3 -> 0,3,4,7,8,11,12,15

Every byte index appears in exactly two of them, which gives two independent
estimates of it. How many of the 16 bytes their two estimates AGREE on is a
self-contained progress meter: under noise the chance agreement per byte is
1/256, so an expected 0.06 bytes of 16. Three or four agreements is already
signal and 16 means the round-10 key is in hand, all without the true key.

Be careful what you read into it, because this is where a long run goes wrong:
agreement is CONSERVATIVE and it was demonstrably throwing away correct answers
at 2.07 M frames, standing at 7 of 16 while 15 of the 16 bytes were already
right in at least one pair set. It is a meter, not a verdict. The verdict is
`host/recover.py` returning a key that verifies.

    python demos/ota_802154/host/monitor.py --log passive.log --line-off 4
"""
from __future__ import annotations

import argparse
import os
import sys
import time

from flashattack import lastround

try:
    from . import frames, logread
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import frames, logread

SETS = ("r0r1", "r1r2", "r2r3", "r0r3")


def agreement(ct, y, *, line_off, line_shift=4):
    """(agreed bytes, the agreed values) across the four pair sets."""
    est = {}
    for name in SETS:
        k10, _margin = lastround.recover_k10(ct, y, name,
                                             line_shift=line_shift,
                                             line_off=line_off)
        for i, v in k10.items():
            est.setdefault(i, []).append(int(v))
    agreed = {}
    for i, vals in est.items():
        if len(vals) >= 2 and len(set(vals)) == 1:
            agreed[i] = vals[0]
    return len(agreed), agreed


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--log", required=True)
    ap.add_argument("--line-off", type=int, required=True,
                    help="read it off the victim's ELF; it is per image")
    ap.add_argument("--highpass", type=int, default=33)
    ap.add_argument("--every", type=float, default=600.0,
                    help="seconds between looks")
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()

    while True:
        rec = logread.read_log(a.log)
        y, keep = logread.condition(rec["gap"], highpass=a.highpass)
        ct = frames.keystream_from_payload(rec["payload"][keep])
        n, agreed = agreement(ct, y, line_off=a.line_off)
        print("  %s  %d frames: %d/16 bytes agree across pair sets "
              "(chance expectation 0.06)"
              % (time.strftime("%H:%M:%S"), len(y), n), flush=True)
        if agreed:
            print("     %s" % " ".join("k10[%d]=%02x" % (i, v)
                                       for i, v in sorted(agreed.items())))
        if a.once:
            return 0
        time.sleep(a.every)


if __name__ == "__main__":
    sys.exit(main())
