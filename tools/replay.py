"""Replay one captured vector and recover the key. No hardware, no network.

    python tools/replay.py demos/oscore_coap/vectors/f429_standard_600k.npz
    python tools/replay.py <vector.npz> --n 100000 --controls
    python tools/replay.py <vector.npz> --line-off 0     # see what wrong costs

Every vector has a `.json` beside it holding the victim, the TABLE GEOMETRY and
what the attack is expected to do. The geometry is not decoration: the row a
lookup hits is `(index + line_off) >> line_shift`, `line_off` is a property of
the victim's image, and getting it wrong costs between two and ten times the
traces. The original tree scored this demo's own capture at `line_off=0` for
months, which turned a verified key at 150 000 traces into three correct bytes.
So this driver refuses to guess it.

Each demo supplies `host/replay.py` with `load()` and `attack()`; this file
knows nothing about any protocol and is the same for all of them.

WHAT THIS DOES NOT CHECK
  * That the vector is a faithful compression of the capture it came from.
    The packer checks that when the vector is made, by regenerating every
    block and comparing byte for byte, and it refuses to write one that does
    not. Nothing here re-does it.
  * That the firmware in images/ is the firmware the vector came off. Both the
    victim's table address and the recorded geometry would have to be re-read
    from the ELF for that.
  * Anything about silicon. A replay is arithmetic on numbers that were
    measured once, somewhere else.
"""
from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Run as `python tools/replay.py`, which puts tools/ on sys.path and not the
# repository root, and imported as `tools.replay` by demo 00. Both have to
# reach `tools.stats` and `demos.<demo>.host.replay`.
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import stats                        # noqa: E402


def load_geometry(vector_path):
    side = os.path.splitext(vector_path)[0] + ".json"
    if not os.path.exists(side):
        raise SystemExit("no geometry beside %s - a trace count without the "
                         "table's address is under-specified, so this refuses "
                         "to run. Expected %s"
                         % (os.path.basename(vector_path), os.path.basename(side)))
    return json.load(io.open(side, encoding="utf-8"))


def demo_adapter(vector_path):
    """(demo name, its host/replay module), imported as a package module.

    `demos.<demo>.host.replay`, and not by file path with the host directory
    on sys.path, which is how this was written first. Four demos each have a
    module called `make_vector`, a bare `import make_vector` finds whichever
    one was imported first, and the second demo then reads the first demo's
    vector format. That failed as a missing array name three frames deep
    rather than as an import error, which is the whole reason these are
    packages.
    """
    demo_dir = os.path.dirname(os.path.dirname(os.path.abspath(vector_path)))
    demo = os.path.basename(demo_dir)
    if not os.path.exists(os.path.join(demo_dir, "host", "replay.py")):
        raise SystemExit("%s has no host/replay.py" % demo)
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    return demo, importlib.import_module("demos.%s.host.replay" % demo)


def run(vector_path, *, n=None, line_off=None, controls=False, quiet=False,
        vote_only=False):
    """(ok, summary). ok is whether the vector did what its json says."""
    geom = load_geometry(vector_path)
    name, adapter = demo_adapter(vector_path)
    if n:
        geom["attack"]["n"] = n
    if line_off is not None:
        geom["geometry"]["line_off"] = line_off

    say = (lambda *a: None) if quiet else (lambda *a: print(*a))
    g, atk = geom["geometry"], geom["attack"]
    truth = bytes.fromhex(geom["truth"]["master_key"])

    say("== %s :: %s" % (name, os.path.basename(vector_path)))
    say("   %s" % geom["what"])
    say("   victim      %s, %s" % (geom["victim"]["part"], geom["victim"]["stack"]))
    say("   table       %s at %s" % (geom["victim"]["table"], geom["victim"]["table_addr"]))
    say("   geometry    line_off=%d line_shift=%d  (row of a lookup is (x+%d)>>%d)"
        % (g["line_off"], g["line_shift"], g["line_off"], g["line_shift"]))

    data = adapter.load(vector_path, geom)
    i = data["info"]
    say("   oracle      %s: %d kept, %s modes, spread %.1f"
        % (i["column"], i["kept"], i["modes"], i["spread"] or float("nan")))

    if controls:
        # tools/stats.py scores LAST-round collisions on an AES output block.
        # A demo whose reduction is something else - the bootloader one attacks
        # round 1 of a decryption, where the index is linear in the key and
        # identifies differences rather than bytes - says so by defining its
        # own `controls`, and gets to print whatever its reduction can support.
        # Silently running the last-round statistic on those traces would
        # return a clean null and read as "no channel", which is the failure
        # this repository has paid for more than once.
        if hasattr(adapter, "controls"):
            say("   controls    %s" % adapter.controls(data, geom, truth))
        elif data.get("known_blocks") is None:
            say("   controls    none for this reduction; the demo README says why")
        else:
            z, zs, zw = stats.controls(data["known_blocks"], data["timing"], truth,
                                       line_off=g["line_off"],
                                       line_shift=g["line_shift"])
            say("   pooled z    %+.2f   (the effect over the 120 pairs, given the key)" % z)
            say("   shuffled    %+.2f   (control: timing permuted)" % zs)
            say("   wrong key   %+.2f   (control: labels from a key that is not it)" % zw)

    t0 = time.time()
    master, notes = adapter.attack(data, geom, vote_only=vote_only, truth=truth)
    dt = time.time() - t0

    for note in notes:
        say("   note        %s" % note)
    say("   recovered   %s" % (master.hex() if master else "nothing"))
    say("   truth       %s" % truth.hex())

    got = master == truth
    want = bool(atk.get("expect_recovery", True))
    kind = "key" if got else "no key"

    # A demo whose replayable half is not a key says so with `expect_kind`, and
    # the driver then asks the adapter. The FIDO2 ladder is the case: it pins
    # the key to 2^44 and the search that closes it is twelve minutes of Rust,
    # so a replay checks the measurement and says RELATIONS. Without this the
    # only way to express that would be `expect_recovery: false`, which is how
    # this repository marks a CONTROL - a vector that must stay silent - and
    # the two mean opposite things.
    if atk.get("expect_kind") == "relations":
        ok, line = adapter.check(data, geom)
        kind = "relations"
        say("   relations   %s" % line)
    else:
        ok = (got == want)

    say("   %s  %s in %.0fs"
        % (kind.upper() if kind == "relations" else ("EXACT" if got else "no key"),
           "as expected" if ok else "NOT WHAT THE VECTOR SAYS", dt))
    if not ok:
        say("   expected    %s" % atk.get("expect_note", ""))
    return ok, {"demo": name, "vector": os.path.basename(vector_path),
                "recovered": got, "expected": want, "kind": kind,
                "seconds": dt}


def ladder(vector_path, counts, *, line_off=None):
    """The trace table: what the vote alone resolves at each count.

    Vote only, so this measures one thing. Escalating from a 14/16 vote with a
    brute force is real and it is cheap, but it comes out of the attacker's CPU
    rather than off the wire, and a ladder that includes it is measuring two
    things at once.
    """
    geom = load_geometry(vector_path)
    name, adapter = demo_adapter(vector_path)
    if line_off is not None:
        geom["geometry"]["line_off"] = line_off
    truth = bytes.fromhex(geom["truth"]["master_key"])
    print("== %s ladder, line_off=%d, vote only"
          % (name, geom["geometry"]["line_off"]))
    for n in counts:
        geom["attack"]["n"] = n
        data = adapter.load(vector_path, geom)
        master, notes = adapter.attack(data, geom, vote_only=True, truth=truth)
        hit = [x for x in notes if "round-key bytes" in x]
        print("   %7d  %-44s %s"
              % (n, hit[0] if hit else "?", "EXACT" if master == truth else ""))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("vector", help="a demos/*/vectors/*.npz")
    ap.add_argument("--ladder", default=None,
                    help="comma-separated trace counts; prints the vote table "
                         "and nothing else")
    ap.add_argument("--vote-only", action="store_true",
                    help="stop after the vote, with no brute-force escalation")
    ap.add_argument("--n", type=int, default=None,
                    help="use only the first N conditioned traces")
    ap.add_argument("--line-off", type=int, default=None,
                    help="override the recorded row offset. For showing what a "
                         "wrong one costs, not for making a result")
    ap.add_argument("--controls", action="store_true",
                    help="also print the labelled statistic and its two controls")
    a = ap.parse_args()
    if a.ladder:
        ladder(a.vector, [int(x) for x in a.ladder.split(",")],
               line_off=a.line_off)
        return 0
    ok, _ = run(a.vector, n=a.n, line_off=a.line_off, controls=a.controls,
                vote_only=a.vote_only)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
