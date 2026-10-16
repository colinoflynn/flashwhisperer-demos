"""Round-2 collision primitives: the state the second round indexes, and its dip.

The round-2 attack is what finishes a key from ONE side of the cipher - no
known plaintext/ciphertext pair, no verification oracle, and in the decrypt
direction no plaintext ever observed, which is the bootloader threat model.
[`ROUND2.md`](ROUND2.md) is its write-up and sits beside this file; what was
missing until now is that **the code it documents lived outside the package**,
in `research/round2/`, as a private copy per script: five definitions of
`xtime`, two of `round2_state`, and the column decomposition written out again
in `results/stm32f4/matrix_f4.py`.

Why round 2 at all? Round-1 line collisions depend on
`topbits(P ^ k0) == topbits(P) ^ topbits(k0)`. XOR has no carries, so the LOW
`line_shift` bits of every key byte are invisible to round 1 - that is exactly
the residual `recover_round1_keyspace` reports, 2^38 for a 4-byte granularity.
Round 2's index passes through MixColumns, which mixes those low bits into the
top bits of the next round's index, so a round-2 collision score CAN separate
them. `research/round2/round2_gonogo.py` is the measurement that it does, with
round 1's own flat response across the four low-bit candidates as the built-in
control.

WHAT IS HERE, and what is deliberately not:

  * the state computations, the GF(2^8) helpers, the pooled and per-column dip
    statistics, and the column decomposition - the parts every script shared
    and each had its own copy of;
  * NOT the solvers. `round2_fullsolve.py`, `round2_network.py`,
    `round2_parallel.py`, `round2_rank.py` and `round2_finish.py` are campaign
    drivers with their own victims, conditioning choices and archived logs.
    They now import these primitives instead of redefining them, and their
    search strategies stay where their results are.

ONE SIDE EFFECT THIS REMOVES. `round2_column.py` and `round2_nuisance.py`
imported `round2_state` from `round2_gonogo.py`, which runs its whole analysis
at module level - so importing the function re-ran the go/no-go measurement.
Nothing was wrong with the numbers; it just cost minutes per import, silently.

WHAT THIS MODULE DOES NOT COVER. The statistics here take a tag array and a
timing array and nothing else: they assume the traces are already conditioned
(see `oracle` for a network capture) and that `y` has had no per-trace
weighting applied. They also assume a row-ALIGNED table, like
`engine.recover_round1_*` and for the same reason - the XOR identity the
bucketing relies on breaks when an offset is added before the shift, so a
non-zero row offset needs the pair-wise scorer in `lastround`, not these.
"""
from __future__ import annotations

import numpy as np

from . import aesref

SBOX = aesref.SBOX.astype(np.uint8)
SINV = aesref.SINV.astype(np.uint8)

#: Which four state bytes each round-2 COLUMN depends on, as positions in the
#: round-1 input. ShiftRows runs before MixColumns, so a column of round 2 is
#: fed by one byte from each column of round 1 - the diagonal. This is what
#: makes a per-column search 2^8 rather than 2^32: round 2's state byte 4c+r
#: depends on exactly one unknown low-bit group per row.
COLUMN_BYTES = [[4 * c, 4 * ((c + 1) % 4) + 1, 4 * ((c + 2) % 4) + 2,
                 4 * ((c + 3) % 4) + 3] for c in range(4)]


def xtime(a):
    """Multiply a uint8 array by x in GF(2^8) - the AES `xtime`."""
    a = np.asarray(a, np.uint8)
    return ((a << 1) ^ (((a >> 7) & 1) * 0x1B)).astype(np.uint8)


#: The name the research scripts use.
xt = xtime


def gmul(a, c):
    """Multiply a uint8 array by the constant `c` in GF(2^8), by doubling."""
    out = np.zeros_like(np.asarray(a, np.uint8))
    x = np.asarray(a, np.uint8).copy()
    while c:
        if c & 1:
            out = out ^ x
        x = xtime(x)
        c >>= 1
    return out


def shift_rows(st):
    """state[4c+r] <- state[4((c+r) mod 4)+r]: rows rotate LEFT by r."""
    st = np.asarray(st)
    out = np.empty_like(st)
    for c in range(4):
        for r in range(4):
            out[:, 4 * c + r] = st[:, 4 * ((c + r) % 4) + r]
    return out


def inv_shift_rows(st):
    """state[4c+r] <- state[4((c-r) mod 4)+r]: rows rotate RIGHT by r."""
    st = np.asarray(st)
    out = np.empty_like(st)
    for c in range(4):
        for r in range(4):
            out[:, 4 * c + r] = st[:, 4 * ((c - r) % 4) + r]
    return out


def round2_state(P, k0, k1):
    """S-box indices of round 2 = MixColumns(ShiftRows(SubBytes(P^k0))) ^ k1.

    `k1` enters only as an additive 6-bit nuisance per relation, so a search
    that scores *differences* between two bytes of the same column can pass
    zeros here - which is what `column_score` does.
    """
    P = np.asarray(P, np.uint8)
    k0 = np.asarray(k0, np.uint8)
    k1 = np.asarray(k1, np.uint8)
    sr = shift_rows(SBOX[P ^ k0[None, :]])
    mc = np.empty_like(sr)
    for c in range(4):
        a = [sr[:, 4 * c + r] for r in range(4)]
        for r in range(4):
            mc[:, 4 * c + r] = (xtime(a[r]) ^ (xtime(a[(r + 1) % 4]) ^ a[(r + 1) % 4])
                                ^ a[(r + 2) % 4] ^ a[(r + 3) % 4])
    return mc ^ k1[None, :]


def round2_state_dec(C, rk10, rk9):
    """The decrypt analogue: x2 = InvMixColumns(SINV[InvShiftRows(C ^ rk10)] ^ rk9).

    This is the direction that matches the bootloader: the attacker supplies or
    observes the ciphertext, times the decryption, and never sees a plaintext.
    """
    C = np.asarray(C, np.uint8)
    rk10 = np.asarray(rk10, np.uint8)
    rk9 = np.asarray(rk9, np.uint8)
    u = SINV[inv_shift_rows(C ^ rk10[None, :])] ^ rk9[None, :]
    x2 = np.empty_like(u)
    for c in range(4):
        a = [u[:, 4 * c + r] for r in range(4)]
        for r in range(4):
            x2[:, 4 * c + r] = (gmul(a[r], 0x0E) ^ gmul(a[(r + 1) % 4], 0x0B)
                                ^ gmul(a[(r + 2) % 4], 0x0D) ^ gmul(a[(r + 3) % 4], 0x09))
    return x2


def pooled_dip(tag, y, min_count=200):
    """(mean dip, per-pair dips) over all 120 pairs of a tag array.

    Each pair contributes (mean time when the two lookups share a row) minus
    (mean time when they do not). More negative means the hypothesis predicts
    collisions that really are faster, so the most negative candidate wins.

    Pairs with fewer than `min_count` traces on either side are dropped rather
    than included noisily, which matters at small trace counts and at coarse
    granularities where one bucket can be nearly empty.
    """
    tag = np.asarray(tag)
    y = np.asarray(y, float)
    n = len(y)
    out = []
    for a in range(16):
        for b in range(a + 1, 16):
            m = tag[:, a] == tag[:, b]
            nc = int(m.sum())
            if nc < min_count or nc > n - min_count:
                continue
            out.append(y[m].mean() - y[~m].mean())
    arr = np.asarray(out, float)
    return (float(arr.mean()) if arr.size else float("nan")), arr


def column_score(x2, y, c, *, line_shift=2, min_count=100):
    """Best-of-targets dip pooled over one round-2 column's six same-row pairs.

    Scoring the DIFFERENCE of two bytes of the same column removes `k1`
    entirely: it enters both bytes additively, so its contribution to the
    difference is a constant 6-bit target rather than an unknown to search. The
    minimum over targets is taken per pair, which is why `k1` can be passed as
    zeros to `round2_state`.

    Lower (more negative) is better, as with `pooled_dip`.
    """
    x2 = np.asarray(x2, np.uint8)
    y = np.asarray(y, float)
    n = len(y)
    ysum = float(y.sum())
    nbins = 1 << (8 - line_shift)
    tot = 0.0
    for r in range(4):
        for r2 in range(r + 1, 4):
            v = ((x2[:, 4 * c + r] ^ x2[:, 4 * c + r2]) >> line_shift).astype(np.int64)
            s = np.bincount(v, weights=y, minlength=nbins)
            cnt = np.bincount(v, minlength=nbins).astype(float)
            ok = cnt > min_count
            if not ok.any():
                continue
            tot += float((s[ok] / cnt[ok] - (ysum - s[ok]) / (n - cnt[ok])).min())
    return tot / 6.0
