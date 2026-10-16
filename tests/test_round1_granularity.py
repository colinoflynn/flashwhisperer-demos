"""How finely does a round-1 collision resolve a lookup index?

This sets the ceiling on the known-plaintext-only (and chosen-ciphertext-only)
attack, because those routes learn key-byte *differences* at whatever granularity
the channel resolves, and nothing else. The arithmetic is unforgiving:

    residual = 16 * line_shift  +  (8 - line_shift)
             = 2^68 at 16-byte granularity, 2^38 at 4-byte granularity

and 2^68 is a keyspace reduction while 2^38, against one known (P, C) pair, is a
break. So the exponent is the whole result and it is worth a regression test.

Measured on tests/vectors/sbox_tinyaes_ecb-enc_128.npz (F429, ART on, 250 k
blocks): the channel resolves 4 bytes, not the 16-byte cache line - there is
sub-line structure, consistent with 32-bit flash data reads inside a 128-bit
line. See flashattack/EXPERIMENTAL.md.
"""

import os as _os, sys as _sys
# The five packages live under flashwhisperer/ (REORG_PLAN D2).  Walk up to the
# .git marker rather than assume a depth: importers of these packages sit at the
# repository root, in hardware/, results/<campaign>/, demo/<stack>/ and
# research/<area>/ - four different depths.  `.git` is a FILE in a worktree, so
# test existence, not isdir.
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))
import os

import numpy as np
import pytest

from flashattack import engine, transport

VEC = os.path.join(os.path.dirname(__file__), "vectors",
                   "sbox_tinyaes_ecb-enc_128.npz")
KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _load():
    if not os.path.exists(VEC):
        pytest.skip("capture vector not present")
    d = np.load(VEC)
    return transport.gen_pts(int(d["seed"]), int(d["n"])), d["timing"].astype(float)


def _correct_at(shift):
    blocks, timing = _load()
    rel = engine.recover_round1_keyspace(blocks, timing, line_shift=shift)["reldiff"]
    return sum(1 for j in range(16)
               if rel[j] is not None
               and rel[j] == ((KEY[j] >> shift) ^ (KEY[0] >> shift)))


@pytest.mark.slow
def test_resolves_four_byte_granularity():
    """All fifteen 6-bit differences, exactly. This is the 2^38 claim."""
    assert _correct_at(2) == 16


@pytest.mark.slow
def test_finer_than_four_bytes_does_not_resolve():
    """The counterpart that makes the above meaningful: the channel is not simply
    reporting whatever granularity it is asked for. At 2-byte granularity it is
    already unreliable and at 1-byte it fails."""
    assert _correct_at(1) < 16
    assert _correct_at(0) < 8


@pytest.mark.slow
def test_coarser_granularity_still_works():
    """Coarser information is implied by finer, so the line-level answer must
    also come out - this is the 2^68 reading the docs used to quote."""
    assert _correct_at(4) == 16


@pytest.mark.slow
def test_the_reduction_contains_the_true_key_and_is_not_vacuous():
    blocks, timing = _load()
    rel = engine.recover_round1_keyspace(blocks, timing, line_shift=2)["reldiff"]
    assert all(rel[j] == ((KEY[j] >> 2) ^ (KEY[0] >> 2)) for j in range(16))
    # A random key should satisfy 16 six-bit constraints with probability 2^-90,
    # i.e. never. If this passed often the constraints would mean nothing.
    rng = np.random.default_rng(0)
    k = rng.integers(0, 256, size=(20000, 16), dtype=np.uint8).astype(int)
    hit = np.ones(len(k), bool)
    for j in range(16):
        hit &= ((k[:, j] >> 2) ^ (k[:, 0] >> 2)) == rel[j]
    assert hit.sum() == 0


def test_residual_arithmetic():
    """2^38 vs 2^68 is 16 x (4 - 2) bits of low-order key material."""
    def residual(shift):
        return 16 * shift + (8 - shift)
    assert residual(4) == 68
    assert residual(2) == 38
    assert residual(4) - residual(2) == 30
