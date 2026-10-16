"""flashattack.sweep: does the grid walker report what the attack found?

The sweep itself is bookkeeping, so these are mostly cheap structural
tests. The one that earns its keep is `test_bytes_correct_accepts_numpy`:
the engine returns numpy integers, `np.int64` is not a Python `int`, and
an `isinstance(c, int)` guard in the extraction silently reported 0/16
for a recovery that had actually got 14 of them. A byte count that fails
LOW turns a real channel into a published null, so it is tested
directly.

WHAT THIS DOES NOT COVER:
  * Whether the underlying recovery is correct - that is
    tests/test_flashattack.py and the captured-trace replays.
  * Real timing data. The one end-to-end check here replays a tracked
    vector and is marked slow.
  * `margin_ratio` against real margins; only its arithmetic.
"""
from __future__ import annotations

import os
import pathlib

import numpy as np
import pytest

from flashattack import Capture, aesref
from flashattack.sweep import (Geometry, Ladder, Trial, controls_clean,
                               default_geometries, ladder, margin_ratio,
                               _bytes_correct)

_VEC = pathlib.Path(__file__).resolve().parent / "vectors"


class _Rep:
    def __init__(self, round_keys):
        self.round_keys = round_keys


def test_bytes_correct_accepts_numpy():
    """np.int64 is not a Python int. The engine returns one."""
    assert _bytes_correct(_Rep([{"correct": np.int64(14)}])) == 14
    assert _bytes_correct(_Rep([{"correct": 16}])) == 16
    assert _bytes_correct(_Rep([{"correct": None}])) == 0
    assert _bytes_correct(_Rep([])) == 0
    # several round keys (192/256): the best of them
    assert _bytes_correct(_Rep([{"correct": np.int64(3)},
                                {"correct": np.int64(11)}])) == 11


def test_bytes_correct_accepts_objects_too():
    class RK:
        correct = np.int64(9)
    assert _bytes_correct(_Rep([RK()])) == 9


def test_bytes_correct_ignores_bool():
    """True is an int in Python. A report that said `correct=True` must
    not be read as one correct byte."""
    assert _bytes_correct(_Rep([{"correct": True}])) == 0


def test_default_geometries_covers_both_models_and_adjacencies():
    g = default_geometries(line_shifts=[3, 1])
    labels = {x.label for x in g}
    # 2 shifts x (1 wide + 2 narrow adjacencies)
    assert len(g) == 6
    assert "ls=3 off=0 120" in labels
    assert "ls=3 off=0 24/state" in labels
    assert "ls=3 off=0 24/ct" in labels
    # the wide model has no adjacency axis - it must not be duplicated
    assert sum(1 for x in g if x.pairs == "all" and x.line_shift == 3) == 1


def test_default_geometries_drops_impossible_offsets():
    """An offset at or beyond the row width is not a row offset."""
    g = default_geometries(line_shifts=[1], line_offs=[0, 1, 2, 8])
    assert sorted({x.line_off for x in g}) == [0, 1]


def test_ladder_ranking_prefers_exact_then_bytes_then_small_n():
    g = Geometry(3)
    lad = Ladder(label="x", trials=[
        Trial(50000, g, 14, False, False, None, [], 1.0),
        Trial(10000, g, 16, True, True, "aa", [], 1.0),
        Trial(20000, g, 16, True, True, "aa", [], 1.0),
    ])
    assert lad.best.n == 10000           # exact, and the cheapest exact
    assert lad.exact_at == 10000
    assert lad.scored == 16
    assert "EXACT MASTER KEY at n=10000" in lad.summary_line()


def test_ladder_summary_when_nothing_is_exact():
    lad = Ladder(label="x", trials=[
        Trial(20000, Geometry(3), 6, False, False, None, [], 1.0)])
    assert lad.exact_at is None
    assert "6/16 best" in lad.summary_line()


def test_controls_clean_flags_a_control_that_scored():
    g = Geometry(3)
    good = Ladder("twin", [Trial(20000, g, 1, False, False, None, [], 1.0)])
    bad = Ladder("twin2", [Trial(20000, g, 9, False, False, None, [], 1.0)])
    real = Ladder("victim", [Trial(5000, g, 16, True, True, "aa", [], 1.0)])

    ok, off = controls_clean({"twin": good, "victim": real}, ["twin"])
    assert ok and not off

    ok, off = controls_clean({"twin2": bad, "victim": real}, ["twin2"])
    assert not ok and off[0][0] == "twin2"

    # a control that recovers the KEY is the loudest possible failure
    ex = Ladder("twin3", [Trial(20000, g, 16, True, True, "aa", [], 1.0)])
    ok, off = controls_clean({"twin3": ex}, ["twin3"])
    assert not ok


def test_controls_clean_ignores_non_controls():
    g = Geometry(3)
    real = Ladder("victim", [Trial(5000, g, 16, True, True, "aa", [], 1.0)])
    ok, off = controls_clean({"victim": real}, ["some-other-label"])
    assert ok and not off


def test_margin_ratio_discriminates_noise_from_signal():
    # noise: margin falls as 1/sqrt(4) = 1/2 when n quadruples
    assert margin_ratio(0.082, 0.041, 4.0) == pytest.approx(1.0, abs=0.02)
    # real: margin does not move
    assert margin_ratio(0.748, 0.738, 4.0) == pytest.approx(0.5, abs=0.02)


@pytest.mark.slow
def test_ladder_recovers_a_tracked_vector():
    """End to end on a committed capture: the sweep must find a geometry
    that gets the key WITHOUT being told which one, which is the whole
    reason this module exists.

    The vectors store timing only; the blocks are regenerated from the
    recorded seed, the same way tests/test_vectors.py does it.
    """
    from flashattack import modes, transport

    p = _VEC / "sbox_tinyaes_ecb-enc_128.npz"
    if not p.is_file():
        pytest.skip("vector not present")
    d = np.load(str(p))
    key = bytes.fromhex(str(d["key_hex"]))
    material = transport.gen_pts(int(d["seed"]), int(d["n"]))
    ct, direction = modes.known_output(str(d["mode"]), material, key)
    assert direction == "enc"

    cap = Capture(timing=d["timing"].astype(float), mode="ecb-enc",
                  ciphertext=np.asarray(ct, dtype=np.uint8), label="tinyaes")
    # Deliberately given BOTH a right and a wrong row width, and not told
    # which is which.
    # The full vector: this capture is known to need most of it, and the
    # point here is the SWEEP picking a geometry, not a trace-count floor.
    # Only the wide model, to keep a slow test to a couple of minutes.
    lad = ladder(cap, n_values=[int(d["n"])],
                 geometries=default_geometries(line_shifts=[4, 1],
                                               models=("all",)),
                 key_for_truth=key, stop_on_exact=True)
    assert lad.best is not None
    assert lad.best.bytes_correct >= 8, lad.summary_line()
    # and the sweep must have preferred the correct row width
    assert lad.best.geometry.line_shift == 4, lad.summary_line()
