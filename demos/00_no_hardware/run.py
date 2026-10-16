"""Recover every demo's key from the shipped vectors. No board, no network.

    python demos/00_no_hardware/run.py              # everything
    python demos/00_no_hardware/run.py --fast       # skip the slow ones
    python demos/00_no_hardware/run.py --demo oscore_coap

This is the demo to run first, and the one that runs in CI. It replays each
demo's captures from `demos/*/vectors/`, recovers the key, and checks the
answer against what that vector's `.json` says should happen - including the
controls, which must NOT yield a key.

Exit status is 0 only if every vector did what it says. A vector that recovers
when its json says it should not is as much a failure as one that does not
recover: it would mean the analysis is finding something in a control.
"""
from __future__ import annotations

import argparse
import glob
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import replay as replay_driver            # noqa: E402


def vectors(demo=None):
    pat = os.path.join(ROOT, "demos", demo or "*", "vectors", "*.json")
    for side in sorted(glob.glob(pat)):
        npz = os.path.splitext(side)[0] + ".npz"
        if os.path.exists(npz):
            yield npz, json.load(io.open(side, encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--demo", default=None, help="just this demos/ directory")
    ap.add_argument("--fast", action="store_true",
                    help="skip vectors whose json marks them slow")
    a = ap.parse_args()

    found = list(vectors(a.demo))
    if not found:
        print("no vectors found - is this a partial checkout?")
        return 1

    rows, bad = [], 0
    for npz, geom in found:
        if a.fast and geom.get("slow"):
            print("== skipped (slow): %s" % os.path.relpath(npz, ROOT))
            continue
        ok, summary = replay_driver.run(npz, controls=True)
        print()
        rows.append((ok, summary))
        bad += 0 if ok else 1

    print("== summary")
    for ok, s in rows:
        print("   %-14s %-28s %-9s %-9s %4.0fs  %s"
              % (s["demo"], s["vector"],
                 "key" if s["recovered"] else "no key",
                 "expected" if s["expected"] else "control",
                 s["seconds"], "ok" if ok else "FAILED"))
    if bad:
        print("\n%d of %d vectors did not do what they say." % (bad, len(rows)))
        return 1
    print("\nall %d vectors as expected" % len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
