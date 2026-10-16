"""The one last-round collision scorer: geometry, surface, fast path, selftest.

This module exists because there were two of these and they disagreed about
whether a shipped library gives up its key. `engine.col_attack_scored` scanned
all 120 output-byte pairs but could not express where the table sits inside a
flash row; `hardware/atk_lastround.py` could express that and scored only the
24 intra-column pairs. A campaign inherited the blind spot of whichever one it
imported, and on the L152RE library captures that decided whether two shipped
library configurations gave up their key at all: `results/sstimer_jitter/scan120.py`
re-scored them and `results/sstimer_lib/README.md` records the retraction.

So the scoring rule lives here once, with BOTH capabilities, and the two old
entry points are thin wrappers over it:

    engine.col_attack_scored(...)         -> score_surface + best(margin="z")
    hardware/atk_lastround.score_matrix   -> score_surface  (margin="cycles")

THE TWO GEOMETRY PARAMETERS, because mixing them up costs a run each:

  `line_shift`  entries per flash row, as a shift. 4 = a 1-byte S-box in a
                16-byte row (16 entries); 2 = 4-byte T-table entries in a
                16-byte row; 3 = a byte S-box in an 8-byte row (F1/F3/G4);
                5 = a byte S-box in a 32-byte row (TC234). Scoring an 8-byte
                row at 4 merges two real rows and tests a collision that does
                not exist.
  `line_off`    where the table starts inside its row, **in table ENTRIES**,
                not in bytes. A byte S-box at `0x...cc` is `0xc` = 12 entries
                in. A 4-byte T-table 12 bytes into its row is **3** entries in.
                The unit is the same as the index being shifted, which is the
                only way the two stay consistent.

`line_off != 0` is not a correction factor, it is a different partition: a
256-byte table 12 bytes into a 16-byte row spans SEVENTEEN lines, with
boundaries at index 4, 20, 36 ... rather than 0, 16, 32. Getting it wrong cost
a factor of 2.2 in traces on the measured case in `hardware/line_offset.py`,
and `hardware/atk_lastround.py` records it silently cutting an on-chip recovery
from 8/8 to 4/8.

WHAT THIS MODULE DOES NOT COVER, so the next reader does not assume it:

  * It scores ONE pair of known output bytes at a time. Which pairs to score,
    how to combine them into a key, and what to do with the residual search are
    `engine`'s business, not this module's.
  * `selftest()` compares the fast path against the reference surface at one
    geometry on random data. It does NOT check that the geometry is the right
    one for a given image (that is `geometry.row_offset_from_image`), nor that
    the adjacency convention is right (`engine`'s `pairs=`), and a wrong
    adjacency returns a clean null rather than a degraded one.
  * The round-1 difference attack in `engine.recover_round1_*` cannot take a
    `line_off` at all: it works because `topbits(p ^ k) == topbits(p) ^
    topbits(k)`, and adding an offset before the shift breaks that identity for
    every index next to a row boundary. Row-aligned tables only, which is why
    that parameter is absent there rather than defaulted.
"""
from __future__ import annotations

import numpy as np

from . import aesref

SBOX = aesref.SBOX.astype(np.int64)
SINV = aesref.SINV.astype(np.int64)

# Round-10 state index -> ciphertext index. ShiftRows is its own inverse only
# for row 0, so this is needed whenever the last round emits in STATE order.
PINV = np.argsort(aesref._SHIFT_ROWS)

_BASE = np.arange(256)
_TAG_CACHE: dict = {}
_FOLD_CACHE: dict = {}


def nlines(line_shift=4, line_off=0, table_len=256):
    """How many flash rows the table spans at this geometry.

    `((table_len - 1 + line_off) >> line_shift) + 1`, which is 16 for an
    aligned byte S-box in a 16-byte row and **17** as soon as `line_off` is
    non-zero. Sizing this 16 regardless raised IndexError the first time an
    offset was used, and the exception was itself the confirmation that a
    misaligned table straddles an extra line.
    """
    return ((table_len - 1 + int(line_off)) >> int(line_shift)) + 1


def line_tags(tbl, line_shift=4, line_off=0):
    """TAG[g, x] = (tbl[x ^ g] + line_off) >> line_shift: the row each lookup hits.

    Cached per (table, geometry). The cache holds a reference to `tbl` as well
    as its address, so an array cannot be freed and a later one land at the
    same address with different contents - which an address-keyed cache
    permits and which would be silent.
    """
    tbl = np.asarray(tbl, np.int64)
    key = (tbl.ctypes.data, tbl.shape, int(line_shift), int(line_off))
    hit = _TAG_CACHE.get(key)
    if hit is None:
        tag = ((tbl[_BASE[None, :] ^ _BASE[:, None]] + int(line_off))
               >> int(line_shift)).astype(np.intp)
        _TAG_CACHE[key] = hit = (tag, tbl)       # keep tbl alive; see docstring
    return hit[0]


def score_surface(ba, bb, y, tbl, *, line_shift=4, line_off=0):
    """The (256, 256) surface a last-round collision attack minimises.

    `ba`, `bb` are the two known output bytes per trace; `y` the per-trace
    timing; `tbl` the predictor table - SINV for direction "enc" (the attacker
    knows the cipher's output) or SBOX for "dec".

    Cell (ga, gb) is the MEAN TIME over the traces whose two lookups are
    predicted to fall in the same flash row under that key-byte pair. The true
    pair collides more often than any wrong one, so it scores lowest.

    `y` NEED NOT BE CENTRED. Subtracting a constant from `y` shifts every cell
    by that same constant, so neither the argmin nor either margin in `best()`
    moves. That is what makes `accumulate()`'s trace ladder cheap, and it is
    why nothing here centres on the caller's behalf.

    Cells with no traces are `inf`, not `nan`: `np.isfinite` excludes both and
    `argmin`/`nanargmin` both behave, so either convention works downstream,
    and `inf` additionally makes a plain `argmin` safe.
    """
    ba = np.asarray(ba, np.int64)
    bb = np.asarray(bb, np.int64)
    Ssum, Scnt = accumulate(ba, bb, y)
    nl = nlines(line_shift, line_off)
    TAG = line_tags(tbl, line_shift, line_off)
    scores = np.full((256, 256), np.inf)
    for ga in range(256):
        Rs = np.zeros((nl, 256))
        Rc = np.zeros((nl, 256))
        np.add.at(Rs, TAG[ga], Ssum)             # fold rows into row bins
        np.add.at(Rc, TAG[ga], Scnt)
        num = Rs[TAG, _BASE[None, :]].sum(axis=1)    # every gb at once
        den = Rc[TAG, _BASE[None, :]].sum(axis=1)
        with np.errstate(invalid="ignore", divide="ignore"):
            scores[ga] = np.where(den > 0, num / den, np.inf)
    return scores


def accumulate(ba, bb, y, Ssum=None, Scnt=None):
    """Fold traces into the (256, 256) tables `score_from_tables()` consumes.

    Pass the raw measurement and accumulate rung by rung: a trace ladder then
    costs one scoring per rung instead of re-reducing every earlier trace. See
    `score_surface` on why no centring is needed for that to be exact.
    """
    if Ssum is None:
        Ssum, Scnt = np.zeros((256, 256)), np.zeros((256, 256))
    idx = (np.asarray(ba, np.int64), np.asarray(bb, np.int64))
    np.add.at(Ssum, idx, np.asarray(y, float))
    np.add.at(Scnt, idx, 1.0)
    return Ssum, Scnt


def _fold(tbl, line_shift, line_off):
    """One-hot (guess, row, byte value) folding matrix, cached per geometry."""
    tbl = np.asarray(tbl, np.int64)
    key = (tbl.ctypes.data, tbl.shape, int(line_shift), int(line_off))
    hit = _FOLD_CACHE.get(key)
    if hit is None:
        nl = nlines(line_shift, line_off)
        TAG = line_tags(tbl, line_shift, line_off)
        A = np.zeros((256, nl, 256))
        A[_BASE[:, None], TAG, _BASE[None, :]] = 1.0
        _FOLD_CACHE[key] = hit = (A, nl, tbl)
    return hit[0], hit[1]


def score_from_tables(Ssum, Scnt, tbl, *, line_shift=4, line_off=0):
    """`score_surface()`'s surface from pre-accumulated tables, via two matmuls.

    A SECOND IMPLEMENTATION IS ALLOWED HERE, and only here, because
    `selftest()` checks it against the reference at the geometry in use. A fast
    path nobody compares to the reference is a second attack; one with an
    equality test is an optimisation.

    Cost note: the folding matrix is `(256, nlines, 256)` float64, so it is
    ~9 MB at `line_shift = 4` and ~67 MB at `line_shift = 1`, cached per
    geometry. Scoring many pairs at one geometry amortises it; sweeping
    geometries at `line_shift = 1` does not.
    """
    A, nl = _fold(tbl, line_shift, line_off)
    Af = A.reshape(256 * nl, 256)
    Rs = (Af @ np.asarray(Ssum, float)).reshape(256, nl * 256)
    Rc = (Af @ np.asarray(Scnt, float)).reshape(256, nl * 256)
    B = A.reshape(256, nl * 256).T
    T, C = Rs @ B, Rc @ B
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.where(C > 0, T / np.maximum(C, 1e-30), np.inf)


def best(scores, margin="z"):
    """(ga, gb, margin) from a surface. Two margin conventions, both archived.

    `margin="z"`      (mean of the finite cells - winner) / their std. Scale
                      free, so it can weight a vote across pairs with different
                      timing units. This is what `engine.recover` votes with
                      and what every `flashattack` number was measured in.
    `margin="cycles"` median of the finite cells - winner, in the timing's own
                      units. This is `hardware/atk_lastround.col_attack`'s, and
                      what the archived per-pair-set margins in
                      `research/targets/` and the ledger were measured in --
                      including the 1/sqrt(n) scaling test that decides whether
                      a partial recovery is structural.

    They are not interchangeable and neither is a scaled version of the other:
    median against mean differs on a skewed surface, and only one is divided by
    a spread. Converting an archived number between them is not possible after
    the fact, which is why both are kept rather than unified.
    """
    scores = np.asarray(scores, float)
    ia, ib = np.unravel_index(np.argmin(scores), scores.shape)
    fin = scores[np.isfinite(scores)]
    if margin == "cycles":
        mg = float(np.median(fin) - scores[ia, ib])
    elif margin == "z":
        mg = float((fin.mean() - scores[ia, ib]) / (fin.std() + 1e-12))
    else:
        raise ValueError(f"margin must be 'z' or 'cycles', not {margin!r}")
    return int(ia), int(ib), mg


def selftest(*, line_shift=4, line_off=12, tbl=None, n=4000, rng=None,
             pair=(3, 7)):
    """Assert the fast path and the reference surface agree to the last bit.

    Run it at the GEOMETRY about to be used, not only at the default: the
    folding matrix is built per `(line_shift, line_off)` and a geometry bug
    does not show at `line_off = 0`.

    What it does NOT check: that the geometry matches the target image, that
    the adjacency convention is right, or anything about recovery. It is an
    equality test between two implementations of one formula on random data.
    """
    rng = np.random.default_rng(0) if rng is None else rng
    tbl = SINV if tbl is None else tbl
    blocks = rng.integers(0, 256, size=(n, 16), dtype=np.uint8)
    y = rng.normal(0, 1, n)
    ja, jb = pair
    ref = score_surface(blocks[:, ja], blocks[:, jb], y, tbl,
                        line_shift=line_shift, line_off=line_off)
    fast = score_from_tables(*accumulate(blocks[:, ja], blocks[:, jb], y), tbl,
                             line_shift=line_shift, line_off=line_off)
    fin = np.isfinite(ref)
    assert np.array_equal(fin, np.isfinite(fast)), "finite masks differ"
    assert np.allclose(ref[fin], fast[fin], rtol=0, atol=1e-9), "surfaces differ"
    for conv in ("z", "cycles"):
        a, b = best(ref, conv), best(fast, conv)
        assert a[:2] == b[:2] and abs(a[2] - b[2]) < 1e-9, (conv, a, b)
    return True


# ---------------------------------------------------------------------------
# Which pairs to score. Coverage is a PARAMETER, not a property of the scorer:
# the 120-pair sweep is the right default and the intra-column set is what
# every archived `atk_lastround` trace count was measured with, so both have to
# stay expressible or those numbers stop being reproducible.
#
# A wider vote is not automatically better. On the sstimer byte-S-box control
# the 120-pair vote reached 13/16 on the UART arm where the intra-column model
# reached 12/16 and finished the key with a 33-candidate search: when the leak
# really is concentrated in one adjacent-read pair set, 104 noise pairs cost
# more than the extra coverage buys. `engine.leaking_offsets` is how to choose
# between them without the key.
# ---------------------------------------------------------------------------

#: All six pairings of the four state rows of a column. It is six and not the
#: obvious four because whichever two reads the compiler emits back-to-back are
#: the ones a depth-1 row buffer can serve, and on the K21 the recovering
#: pairing moved with code residence, optimisation level and core clock.
ROW_PAIRINGS = {
    "r0r1": (0, 1), "r1r2": (1, 2), "r2r3": (2, 3),
    "r0r3": (0, 3), "r0r2": (0, 2), "r1r3": (1, 3),
}


def pairs_all():
    """The 120 unordered pairs of output-byte positions: layout-agnostic."""
    return [(a, b) for a in range(16) for b in range(a + 1, 16)]


def pairs_intra_column(rows=None, *, ct_adjacent=False):
    """The pairs of output bytes that are two reads of ONE state column.

    `rows` picks the row pairings, defaulting to all six of `ROW_PAIRINGS`;
    pass one name, one `(ra, rb)` tuple, or a list of either.

    `ct_adjacent` is the adjacency convention and it is a property of the
    victim's last round, not of the part:

      False  SubBytes runs over the state and ShiftRows follows, so consecutive
             reads are state indices `4c+r` and reach the ciphertext through
             `PINV`. This is the byte-S-box build.
      True   the last round folds ShiftRows into the read - every T-table
             build in this repository does - so the four consecutive reads
             producing output column c emit ciphertext bytes `4c+0..4c+3`, and
             `PINV` must not be applied.

    Getting it wrong does not degrade gracefully: it tests an adjacency the
    access stream does not have and returns a clean null. That has cost two
    parts a wrong answer (the TC234 read as the most resistant cell on its part
    when it is the cheapest; the MPC5606B's T-table builds read as 0/16 at
    20 000 traces when they fall at 2 500 and 750).
    """
    if rows is None:
        sel = list(ROW_PAIRINGS.values())
    else:
        if isinstance(rows, str) or (isinstance(rows, tuple) and len(rows) == 2
                                     and all(isinstance(v, int) for v in rows)):
            rows = [rows]
        sel = [ROW_PAIRINGS[r] if isinstance(r, str) else tuple(r) for r in rows]
    out = []
    for ra, rb in sel:
        for c in range(4):
            if ct_adjacent:
                ja, jb = 4 * c + ra, 4 * c + rb
            else:
                ja, jb = int(PINV[4 * c + ra]), int(PINV[4 * c + rb])
            out.append((min(ja, jb), max(ja, jb)))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def coverage(spec="all", *, ct_adjacent=False):
    """Resolve a coverage spec to a list of (ja, jb) output-byte pairs.

    `"all"` -> the 120; `"intra-column"` -> the 24 of `pairs_intra_column`; a
    pairing name such as `"r1r2"` -> that pairing's 4 pairs; or pass an
    explicit iterable of `(ja, jb)` and it is returned as given.
    """
    if spec is None or spec == "all":
        return pairs_all()
    if isinstance(spec, str):
        if spec in ("intra-column", "intra_column", "column"):
            return pairs_intra_column(ct_adjacent=ct_adjacent)
        if spec in ROW_PAIRINGS:
            return pairs_intra_column(spec, ct_adjacent=ct_adjacent)
        raise ValueError(f"unknown coverage {spec!r}")
    return [(int(a), int(b)) for a, b in spec]


# ---------------------------------------------------------------------------
# Pair-set recovery, moved in from hardware/atk_lastround.py on 2026-10-12.
#
# It lived in the shim because "the archived trace counts were measured through
# it", which was a good reason to keep ONE implementation and a bad reason for
# that one to sit outside the package: a script that reproduces a published
# figure has to import the package, not a directory the package layering has no
# edge to. The shim now delegates here, and flashwhisperer/tests asserts the
# surfaces and margins are bit-identical rather than taking it on trust.
# ---------------------------------------------------------------------------

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def recover_k10(ct, cyc, rows, line_shift=4, line_off=0, ct_adjacent=False):
    """Recover 8 round-10 key bytes from one pair set.

    Returns `(k10, margin)`: a {ct index -> byte} map for the eight positions
    this pair set covers, and the mean margin in the TIMING'S OWN UNITS
    (median minus winner), which is the convention every archived margin in
    `research/targets/` and the findings ledger was measured in. `engine`
    votes in `margin="z"` and the two are not interchangeable - in particular
    the 1/sqrt(n) scaling test that decides whether a partial recovery is
    structural is a statement about THIS margin.

    `ct_adjacent` picks which adjacency the collision test assumes, and it is a
    property of the cipher's last round rather than of the part:

      False   SubBytes runs over a state column and ShiftRows follows, so
              consecutive S-box reads are state indices 4c+r and reach the
              ciphertext through PINV. The byte S-box build.
      True    the last round FOLDS ShiftRows into the read - every T-table
              build in this repository does - so the four consecutive reads
              producing output column c emit ciphertext bytes 4c+0..4c+3 in
              that order and PINV must not be applied.

    GETTING THIS WRONG DOES NOT DEGRADE GRACEFULLY: it tests an adjacency the
    access stream does not have and returns a clean null. It has cost two parts
    a wrong answer - the TC234 read as 7/16 in 26 624 traces when it is the
    cheapest cell on the part at 3 072, and the MPC5606B's T-table builds read
    as 0/16 at 20 000 when they fall at 2 500 and 750.
    """
    import numpy as _np
    if isinstance(rows, str):
        rows = ROW_PAIRINGS[rows]
    y = cyc - cyc.mean()
    k10, margins = {}, []
    for c in range(4):
        if ct_adjacent:
            ja, jb = 4 * c + rows[0], 4 * c + rows[1]
        else:
            ja, jb = int(PINV[4 * c + rows[0]]), int(PINV[4 * c + rows[1]])
        surf = score_surface(ct[:, ja], ct[:, jb], y, SINV,
                             line_shift=line_shift, line_off=line_off)
        ga, gb, mg = best(surf, margin="cycles")
        k10[ja], k10[jb] = ga, gb
        margins.append(mg)
    return k10, float(_np.mean(margins))


def invert_ks(k10):
    """Round-10 subkey -> master key. `k10` must hold all sixteen bytes."""
    rk = [int(k10[i]) for i in range(16)]
    for rnd in range(10, 0, -1):
        prev = [0] * 16
        for i in range(4, 16):
            prev[i] = rk[i] ^ rk[i - 4]
        t = [prev[13], prev[14], prev[15], prev[12]]
        t = [int(SBOX[b]) for b in t]
        t[0] ^= RCON[rnd - 1]
        for i in range(4):
            prev[i] = rk[i] ^ t[i]
        rk = prev
    return bytes(rk)
