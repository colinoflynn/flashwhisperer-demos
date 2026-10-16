#!/usr/bin/env python3
"""Does the bus-side channel still show with a NON-zero credential key?

The first bus-side result (RESULTS.md §5c) leaned on the victim's `cred_key` being
all zeros, which is RIOT's state before any credential is made: with a zero key the
round-1 index is the input byte, so twelve equal nonce bytes share a flash line.
Against a general key a value common to every controlled byte CANCELS out of every
pairwise line difference, and the same probe measures nothing. So the result needs
this check before it can be quoted as anything but a special case.

The check: write a known random key with `set_cred_key.py set --random`, then run
three arms, interleaved probe for probe and matched on seed, differing only in what
is written into the twelve chosen nonce bytes:

    true    byte i = v ^ key[i + 1]   -> index (v ^ k) ^ k = v for all twelve,
                                        i.e. all twelve lookups on ONE line
    wrong   byte i = v ^ decoy[i]     -> a vector that is not the key; lookups scatter
    random  pseudorandom bytes        -> the natural footprint

`key[i + 1]`, not `key[i]`: CCM builds counter blocks as flags(1) || nonce(13) ||
counter(2), so nonce byte i is AES input byte i + 1.

Prediction, written before running: `true` is fastest by roughly what §5c measured,
and `wrong` sits with `random`. If `true` does not separate, the §5c result is about
a zero key and nothing more.
"""

from __future__ import annotations

import argparse
import random
import statistics as st
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "hardware"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import boards  # noqa: E402

from nfill_sweep import TICKS_PER_US, tblock  # noqa: E402
from usbhost_capture import HOST_BOARD, VICTIM_BOARD, Host, reset_boards  # noqa: E402


def load_offsets(h: Host, off: bytes | None) -> None:
    """Load the twelve per-byte fill offsets, or clear them."""
    if off is None:
        h.cmd("U 99 0", 0.25, cap=64)
        return
    for i, v in enumerate(off):
        h.cmd(f"U {i} {v}", 0.06, cap=64)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True,
                    help="the 16-byte key now in the victim's flash, as hex")
    ap.add_argument("--decoy", default=None,
                    help="12-byte wrong vector as hex (default: a fixed random vector)")
    ap.add_argument("--fill", type=int, default=0)
    ap.add_argument("--entries", type=int, default=8)
    ap.add_argument("--idlen", type=int, default=164)
    ap.add_argument("--block", type=int, default=8)
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--seed0", type=int, default=7000)
    ap.add_argument("--budget", type=float, default=1500.0)
    ap.add_argument("--out", default=None)
    ap.add_argument("--decoys", type=int, default=0,
                    help="extra random decoy arms: selectivity controls, and a null "
                         "for the keystream-driven term (see the note below)")
    ap.add_argument("--no-flash", action="store_true")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    if len(key) != 16:
        raise SystemExit("--key must be 16 bytes")
    true_off = key[1:13]                       # nonce byte i is AES input byte i+1
    # A decoy has to SCATTER, and the obvious construction does not. Offsetting
    # every byte of the key by one constant c gives indices (v ^ k ^ c) ^ k = v ^ c
    # -- still twelve lookups on ONE line, merely a different line. The first run
    # used c = 0x5A and the arm collapsed just like the true vector: a correct
    # confirmation of the XOR-cancellation argument, and a useless control. The
    # default is therefore a random vector, which is what makes this arm a test of
    # SELECTIVITY rather than of amplification.
    rng = random.Random(0xC0FFEE)
    decoy = bytes.fromhex(args.decoy) if args.decoy else \
        bytes(rng.randrange(256) for _ in range(12))
    if len(decoy) != 12:
        raise SystemExit("--decoy must be 12 bytes")

    arms = [("true", true_off, args.fill),
            ("wrong", decoy, args.fill),
            ("random", None, 300)]             # fill > 255 = leave the nonce random

    # Extra decoy arms do double duty. As controls they test SELECTIVITY: a vector
    # that is not the key must not collapse. As a null they bound the one term this
    # experiment cannot hold fixed -- every fill value produces a different CTR
    # keystream, so a different plaintext reaches the 9 CBC-MAC blocks, and that
    # footprint is class-dependent noise. Several arms whose round-1 footprint is
    # equally scattered measure how large it is, which is what decides whether
    # differences between two COLLAPSED classes mean anything.
    for j in range(args.decoys):
        arms.append((f"decoy{j + 1}",
                     bytes(rng.randrange(256) for _ in range(12)), args.fill))

    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    if not args.no_flash:
        boards.flash(HOST_BOARD, str(ROOT / "instruments/ctaphost/fw.bin"))
        time.sleep(0.5)
    reset_boards()
    h = Host(boards.BOARDS[HOST_BOARD]["port"])
    h.bring_up()
    h.cmd("D 0 8 4000", 0.4, cap=80)
    h.cmd("A 0", 0.3, cap=64)                  # escalating recovery: the fast modes
    h.cmd("J 0", 0.3, cap=64)                  # and deliberate jitter both measured worse
    h.cmd("L 0 0 0", 0.3, cap=64)              # pair mode off
    h.cmd(f"G 1 {args.idlen}", 2.0)            # set idlen
    print(f"true offsets  {true_off.hex()}\nwrong offsets {decoy.hex()}", flush=True)

    rows: list[tuple[int, int, int, int, int]] = []   # arm, rep, k, ticks, polls
    errs = 0
    t0 = time.time()
    for rep in range(args.reps):
        if time.time() - t0 > args.budget:
            break
        seed = args.seed0 + rep
        for ai, (name, off, fill) in enumerate(arms):
            load_offsets(h, off)
            h.cmd(f"N {fill}", 0.25, cap=64)
            # Budget sized to the block, and a re-INIT when a block yields NOTHING.
            # Without both, one unrecoverable wedge turns every later block into a
            # full-budget stall: a run of six arms sat on rep 5 for half an hour
            # before its own budget stopped it, having collected nothing after the
            # wedge. `sweep()` in nfill_sweep.py already does this; this loop did not.
            got, e = tblock(h, seed, args.entries, args.block,
                            budget=6.0 + 0.5 * args.block)
            errs += e
            if not got:
                h.cmd("I", 2.0)
            for k, r in enumerate(got):
                rows.append((ai, rep, k, r[0], r[1]))
        if (rep + 1) % 5 == 0:
            el = time.time() - t0
            print(f"  rep {rep + 1}/{args.reps}: {len(rows)} probes, {errs} faults, "
                  f"{len(rows) / max(el, 1e-9):.1f} probe/s", flush=True)

    a = np.array(rows, dtype=np.int64)
    if a.size == 0:
        print("no rows")
        return 1
    us = a[:, 3] / TICKS_PER_US
    print(f"\n{'arm':>8} {'n':>5} {'mean us':>10} {'sem':>7} {'sd':>7} {'polls':>7}")
    for ai, (name, _, _) in enumerate(arms):
        m = a[:, 0] == ai
        if not m.any():
            continue
        x = us[m]
        print(f"{name:>8} {len(x):>5} {x.mean():>10.1f} "
              f"{x.std(ddof=1) / len(x) ** 0.5:>7.2f} {x.std(ddof=1):>7.1f} "
              f"{a[m, 4].mean():>7.2f}")

    ref = {(int(r[1]), int(r[2])): i for i, r in enumerate(a) if r[0] == 0}
    print(f"\npaired against arm 'true' (same seed, so only the nonce differs)")
    print(f"{'arm':>8} {'pairs':>6} {'mean d us':>11} {'sem':>7} {'t':>7}")
    for ai, (name, _, _) in enumerate(arms):
        if ai == 0:
            continue
        d = np.asarray([us[i] - us[ref[(int(r[1]), int(r[2]))]]
                        for i, r in enumerate(a)
                        if r[0] == ai and (int(r[1]), int(r[2])) in ref])
        if len(d) < 2:
            continue
        sem = d.std(ddof=1) / len(d) ** 0.5
        print(f"{name:>8} {len(d):>6} {d.mean():>11.2f} {sem:>7.2f} "
              f"{d.mean() / sem if sem else float('nan'):>7.2f}")

    # The statistic that survives the quantisation. The reply time here is bimodal
    # -- a probe lands on the fast poll count or three steps later, nothing in
    # between -- so the RATE of fast completions is the measurement, and the mean in
    # microseconds is just that rate times the step. A proportion is also immune to
    # where inside a step a class happens to sit, which is what made the per-class
    # means in RESULTS.md §5c untrustworthy below one step.
    floor = int(a[:, 4].min())
    print(f"\nfast completions (<= {floor} polls) -- the quantisation-proof statistic")
    print(f"{'arm':>8} {'fast':>6} {'n':>5} {'rate':>7} {'z vs true':>10}  poll counts")
    import math
    from collections import Counter
    base = None
    for ai, (name, _, _) in enumerate(arms):
        p = a[a[:, 0] == ai, 4]
        if len(p) == 0:
            continue
        k, n = int((p <= floor).sum()), len(p)
        if base is None:
            base = (k, n)
        pp = (k + base[0]) / (n + base[1])
        se = math.sqrt(pp * (1 - pp) * (1 / n + 1 / base[1])) if 0 < pp < 1 else 0.0
        z = (k / n - base[0] / base[1]) / se if se else float("nan")
        print(f"{name:>8} {k:>6} {n:>5} {k / n:>7.3f} {z:>10.2f}  "
              f"{dict(sorted(Counter(int(x) for x in p).items()))}")

    if args.out:
        np.savez_compressed(args.out, rows=a, key=np.frombuffer(key, dtype=np.uint8),
                            true_off=np.frombuffer(true_off, dtype=np.uint8),
                            decoy=np.frombuffer(decoy, dtype=np.uint8),
                            arms=np.asarray([n for n, _, _ in arms]),
                            entries=np.int64(args.entries), fill=np.int64(args.fill),
                            cols=np.asarray(["arm", "rep", "k", "ticks", "polls"]))
        print(f"\nwrote {args.out}  ({a.shape[0]} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
