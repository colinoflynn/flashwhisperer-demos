"""The consolidated scorer: geometry, both margin conventions, coverage, search.

These cover the module that replaced two implementations of one scoring rule
(`flashattack/engine.py`'s and `hardware/atk_lastround.py`'s). The property
that matters most is the one in `test_line_off_zero_is_the_historical_partition`:
`line_off = 0` must reproduce exactly what the engine did when it could not
express an offset at all, or every archived number in `research/targets/` moves.

WHAT THESE TESTS DO NOT COVER, which is most of what can go wrong:

  * that a geometry is the RIGHT one for a target. That is read off the image
    (`flashleak.row_offset_from_image`) or swept, and what it is worth is
    measured on captures with a known key in
    `results/stm32f4/rescore_rowoffset.py` - 2x to 10x in traces, which is a
    row of `research/FINDINGS_LEDGER.md` section D. Nothing here would notice a
    wrong offset; it would just recover less.
  * that an adjacency convention is right. A wrong one returns a clean null,
    and no unit test on random data can tell a null from a correct null.
  * whether a recovery is real. `search.best_first` will happily enumerate
    candidates from surfaces with no channel in them; the guard is a shuffled
    or wrong-key control on a real capture, which lives with the campaigns.
"""
from __future__ import annotations

import os as _os, sys as _sys
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))

import numpy as np
import pytest

from flashattack import aesref, engine, lastround, round2, search  # noqa: E402


def _blocks(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    return (rng.integers(0, 256, size=(n, 16), dtype=np.uint8),
            rng.normal(100.0, 3.0, n))        # NOT centred, deliberately


@pytest.mark.parametrize("line_shift", [1, 2, 3, 4, 5])
def test_line_off_zero_is_the_historical_partition(line_shift):
    """At offset 0 the bin count must be `1 << (8 - shift)`, as `engine` assumed.

    The two expressions agree for every shift, and this is the check that keeps
    the archived numbers reproducible rather than merely close.
    """
    assert lastround.nlines(line_shift, 0) == 1 << (8 - line_shift)


@pytest.mark.parametrize("off", [1, 4, 8, 12, 15])
def test_a_misaligned_table_spans_one_more_row(off):
    assert lastround.nlines(4, off) == 17


@pytest.mark.parametrize("geom", [(4, 0), (4, 12), (3, 5), (2, 3), (5, 0), (1, 1)])
def test_fast_path_equals_the_reference_surface(geom):
    """The equality the fast path is only allowed to exist because of."""
    shift, off = geom
    assert lastround.selftest(line_shift=shift, line_off=off, n=3000)


def test_uncentred_timing_gives_the_same_answer():
    """Adding a constant to the timing shifts every cell equally, so neither
    the argmin nor either margin moves. That is what makes a trace ladder
    cheap, and an API that centres internally loses it."""
    blocks, y = _blocks()
    a = lastround.score_surface(blocks[:, 3], blocks[:, 7], y, lastround.SINV,
                                line_off=12)
    b = lastround.score_surface(blocks[:, 3], blocks[:, 7], y - y.mean(),
                                lastround.SINV, line_off=12)
    for conv in ("z", "cycles"):
        ra, rb = lastround.best(a, conv), lastround.best(b, conv)
        assert ra[:2] == rb[:2]
        assert abs(ra[2] - rb[2]) < 1e-9


def test_the_two_margin_conventions_are_both_available_and_differ():
    """`z` is what the vote weights with; `cycles` is what the archived margins
    in the ledger were measured in. Converting between them after the fact is
    not possible, which is why both are kept."""
    blocks, y = _blocks()
    S = lastround.score_surface(blocks[:, 1], blocks[:, 6], y, lastround.SINV)
    z = lastround.best(S, "z")
    cyc = lastround.best(S, "cycles")
    assert z[:2] == cyc[:2]                 # same winner
    assert abs(z[2] - cyc[2]) > 1e-6        # different number
    with pytest.raises(ValueError):
        lastround.best(S, "median")


def test_coverage_sets():
    assert len(lastround.pairs_all()) == 120
    intra = lastround.pairs_intra_column()
    assert len(intra) == 24 and set(intra) <= set(lastround.pairs_all())
    # One row pairing is four pairs, one per column.
    assert len(lastround.pairs_intra_column("r1r2")) == 4
    # The adjacency convention changes WHICH pairs, not how many.
    other = lastround.pairs_intra_column(ct_adjacent=True)
    assert len(other) == 24 and set(other) != set(intra)
    assert lastround.coverage("all") == lastround.pairs_all()
    assert lastround.coverage([(0, 1), (2, 3)]) == [(0, 1), (2, 3)]
    with pytest.raises(ValueError):
        lastround.coverage("every-other-one")


def test_engine_recover_accepts_a_geometry_and_a_coverage():
    """Not a recovery test - 2000 random traces carry no channel. It checks the
    parameters reach the scorer and the surfaces come back when asked."""
    blocks, y = _blocks(n=2000, seed=3)
    surfaces = {}
    res = engine.recover(blocks, y, line_shift=4, line_off=12,
                         pairs="r1r2", surfaces=surfaces)
    assert len(res.roundkey) == 16
    assert set(surfaces) == set(lastround.pairs_intra_column("r1r2"))
    assert all(s.shape == (256, 256) for s in surfaces.values())


def test_round2_state_matches_the_packages_own_aes():
    """The round-2 index computation, against `aesref`'s round structure --
    two independent routes to the same state."""
    blocks, _ = _blocks(n=64, seed=7)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rk = aesref.key_expansion(key)
    k0 = np.frombuffer(bytes(rk[0]), np.uint8)
    k1 = np.frombuffer(bytes(rk[1]), np.uint8)
    want = aesref._mix(aesref.SBOX[blocks ^ k0[None, :]][:, aesref._SHIFT_ROWS],
                       False) ^ k1[None, :]
    assert np.array_equal(round2.round2_state(blocks, k0, k1), want)


def test_round2_decrypt_state_is_one_invcipher_round():
    """`round2_state_dec` is the bootloader direction, and it must be exactly
    the state after ONE round of `aesref`'s InvCipher - checked against that
    loop rather than against itself."""
    blocks, _ = _blocks(n=64, seed=8)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    rk = aesref.key_expansion(key)
    rk10 = np.frombuffer(bytes(rk[10]), np.uint8)
    rk9 = np.frombuffer(bytes(rk[9]), np.uint8)
    # aesref.decrypt_blocks_rk's loop body, for r = 9:
    st = blocks ^ rk10
    st = aesref.SINV[st[:, aesref._ISR]] ^ rk9
    want = aesref._mix(st, True)
    assert np.array_equal(round2.round2_state_dec(blocks, rk10, rk9), want)
    # and the two row permutations really are inverses
    assert np.array_equal(round2.inv_shift_rows(round2.shift_rows(blocks)), blocks)
    assert np.array_equal(round2.shift_rows(blocks),
                          blocks[:, aesref._SHIFT_ROWS])


def test_search_walk_is_in_ascending_total_cost():
    rng = np.random.default_rng(4)
    lists = [[(float(c), (2 * i, int(rng.integers(256)), 2 * i + 1, int(rng.integers(256))))
              for c in np.sort(rng.random(12))] for i in range(4)]
    seen = list(search.best_first(lists, 200))
    assert len(seen) == 200
    # the first candidate is every list's own best
    assert seen[0] == tuple(l[0][1] for l in lists)
    # and the walk never revisits
    assert len(set(seen)) == len(seen)


def test_search_verified_walk_reports_the_candidate_count():
    rng = np.random.default_rng(6)
    lists = [[(float(c), ("p", i, int(c * 1000))) for c in np.sort(rng.random(10))]
             for i in range(3)]
    target = list(search.best_first(lists, 50))[25]
    pops, found = search.best_first_verified(lists, lambda p: p == target, 10_000)
    assert found == target and pops == 26          # 1-based count of tries
    pops, found = search.best_first_verified(lists, lambda p: False, 40)
    assert found is None and pops == 40


def test_residual_bits_is_log2_of_the_product_of_ranks():
    assert search.residual_bits([1, 1, 1]) == 0.0
    assert abs(search.residual_bits([2, 4, 8]) - 6.0) < 1e-12
    # an unreachable rank of 0 must not take the log of zero
    assert search.residual_bits([0, 1]) == 0.0


def test_standardise_pushes_unreachable_cells_to_the_back():
    S = np.zeros((4, 4))
    S[0, 0] = np.inf
    out = search.standardise(S)
    assert np.isfinite(out).all() and out[0, 0] == 50.0
