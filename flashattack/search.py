"""From a partial recovery to a key: ranked candidates and a best-first walk.

A recovery that returns "5 of 16 bytes" reads like a failure and often is not.
On the Harmony SNMPv3 3 M-exchange pool the true pair ranked in the top 694 of
65 536 on all twelve column pairs, median rank 27: the information was there
and the argmin threw it away. **The gap between a partial vote and the key is a
search, not more traces**, and the unit a recovery should be quoted in is
therefore **(traces, candidate keys)** rather than a byte count.

This module is the shared part of that search. It was written independently
four times - `results/harmony_snmpv3/enumerate_key.py`,
`results/sstimer_jitter/enumerability.py`,
`results/mpc5606b/enumerability.py` (same idea, same metric name, arrived at in
a parallel session) and `research/round2/round2_finish.py` - plus the
packaged-but-unused `bruteforce.search_pairs`.

HOW IT RELATES TO `bruteforce`. That module runs **many keys over one block**:
exhaustive search over chosen byte positions, with a known plaintext/ciphertext
pair deciding. This one orders the candidates a *scoring surface* suggests, so
the exhaustive search is only ever a fallback. They compose: `candidate_lists`
and `best_first` propose, `bruteforce` or an explicit verify disposes.

TWO THINGS THAT ARE EASY TO GET WRONG, both measured:

  * **Sum overlapping surfaces; do not filter them for agreement.** Where three
    pair sets touch the same four key bytes, each byte is constrained twice.
    Summing the three standardised surfaces put the true quartet at rank 2313,
    2, 1, 2 for the four columns - 2^13.2 for the whole key. An earlier version
    ranked by ONE list and kept the quartets the others agreed with: 51 000 per
    column and nothing found in 4 M tries. Agreement is a weaker use of the
    same data than addition.
  * **Standardise before summing.** The pair sets have different numbers of
    traces surviving the collision test, so their surfaces have different
    scales, and summing them raw lets the noisiest one dominate.

WHAT THIS MODULE DOES NOT COVER. It does not know what a surface means, so it
cannot tell a real ranking from a noise one: a `best_first` walk over surfaces
with no channel in them enumerates 2^k rubbish just as happily. The guard is
the negative control - run the same walk on a shuffled or wrong-key surface
and check it finds nothing - not anything here. And the overlap trick needs
the victim's READ ORDER, which is a property of the compiled image: the
specialised quartet enumeration for one such order stays in
`results/harmony_snmpv3/enumerate_key.py`, where the image it was read from is
recorded.
"""
from __future__ import annotations

import heapq

import numpy as np


def standardise(S):
    """Shift a surface by its median and scale by its spread, so it can be summed.

    Unreachable cells (`inf`/`nan`: no traces fell there) become a large
    positive constant rather than being dropped, so a candidate that depends on
    one is pushed to the back of the queue instead of silently scoring well.
    """
    S = np.asarray(S, float)
    f = S[np.isfinite(S)]
    out = (S - np.median(f)) / (f.std() or 1.0)
    out[~np.isfinite(S)] = 50.0
    return out


def rank_of(S, ia, ib):
    """1-based rank of cell (ia, ib) with the surface sorted ascending.

    Ties count AGAINST the attacker: a cell equal to the true one is assumed to
    be tried first. `inf` cells are unreachable rather than merely bad and
    cannot outrank anything finite, so a true cell that is itself unreachable
    ranks last.
    """
    S = np.asarray(S, float)
    v = S[ia, ib]
    if not np.isfinite(v):
        return int(S.size)
    return int(np.count_nonzero(S <= v))


def residual_bits(ranks):
    """log2 of the product of per-group ranks: the search left after the scores.

    This is the statistic that distinguishes "half-converged" from "structural"
    where a byte count cannot: a rank can improve a thousandfold without one
    byte reaching rank 1. Both `enumerability.py` scripts report it under this
    name, which is why it is spelled the same here.
    """
    r = np.asarray(list(ranks), float)
    return float(np.sum(np.log2(np.maximum(r, 1.0))))


def candidate_lists(surfaces, depth, *, cost="score"):
    """The `depth` best cells of each surface, ascending, as (cost, payload) lists.

    `surfaces` is an iterable of `(ja, jb, S)`. Each payload is
    `(ja, ka, jb, kb)` - the two key-byte positions and their candidate values
    - which is what a verifier needs to assemble a round key.

    `cost="score"`  the surface's own value, standardised by its spread and
                    taken relative to its best cell. Comparable across pair
                    sets, which is what lets `best_first` interleave them.
    `cost="rank"`   log2(1 + rank). Scale-free by construction, so it ignores
                    how confident a surface is and treats all pair sets alike.
                    The two orderings differ, and which is better is a property
                    of the capture: `results/mpc5606b/enumerability.py` carries
                    both for that reason.
    `cost="raw"`    the surface value as it stands, unshifted and unscaled.
                    NOT comparable across pair sets - a surface with a larger
                    absolute mean dominates the walk regardless of its
                    confidence - and kept only because
                    `results/sstimer_jitter/enumerability.py`'s archived
                    residual-bit numbers were measured with it. Reproducing an
                    archived count needs it; a new attack wants "score".
    """
    out = []
    for ja, jb, S in surfaces:
        S = np.asarray(S, float)
        flat = np.where(np.isfinite(S), S, np.inf).ravel()
        finite = int(np.count_nonzero(np.isfinite(flat)))
        d = max(min(depth, finite), 1)
        sel = np.argpartition(flat, d - 1)[:d]
        sel = sel[np.argsort(flat[sel], kind="stable")]
        if cost == "rank":
            costs = np.log2(1.0 + np.arange(len(sel)))
        elif cost == "score":
            sd = S[np.isfinite(S)].std() or 1.0
            costs = (flat[sel] - flat[sel[0]]) / sd
        elif cost == "raw":
            costs = flat[sel]
        else:
            raise ValueError(
                f"cost must be 'score', 'rank' or 'raw', not {cost!r}")
        out.append([(float(c), (ja, int(s // 256), jb, int(s % 256)))
                    for c, s in zip(costs, sel)])
    return out


def best_first(lists, limit):
    """Walk the product of per-group candidate lists in ascending total cost.

    `lists` is one ascending `[(cost, payload), ...]` per group. Yields payload
    tuples in increasing total, which is the order an attacker with a
    verification oracle tries them in - so the index at which the true one
    appears IS the attack's candidate count, and the heap only ever holds the
    frontier, so the cost is the budget rather than the product.

    Materialising the product instead is what makes a "not found" inconclusive:
    at M = 8 over eight groups it is 16.7 M tuples, which exhausted a 4 M cap
    and reported nothing, while the truth's rank in the TOTAL-COST order was a
    few thousand.
    """
    k = len(lists)
    if not k or any(len(l) == 0 for l in lists):
        return
    start = (float(sum(l[0][0] for l in lists)), (0,) * k)
    heap, seen, n = [start], {(0,) * k}, 0
    while heap and n < limit:
        cost, idx = heapq.heappop(heap)
        yield tuple(lists[i][idx[i]][1] for i in range(k))
        n += 1
        for i in range(k):
            if idx[i] + 1 < len(lists[i]):
                nxt = list(idx)
                nxt[i] += 1
                t = tuple(nxt)
                if t not in seen:
                    seen.add(t)
                    heapq.heappush(heap, (cost - lists[i][idx[i]][0]
                                          + lists[i][t[i]][0], t))


def best_first_indices(vals, limit):
    """`best_first` over plain ascending cost arrays, yielding (index tuple, total).

    The form `results/harmony_snmpv3/enumerate_key.py` uses, where the payload
    is a quartet table indexed by position rather than a tuple carried along.
    """
    k = len(vals)
    if not k or any(len(v) == 0 for v in vals):
        return
    start = (float(sum(v[0] for v in vals)), (0,) * k)
    heap, seen, n = [start], {(0,) * k}, 0
    while heap and n < limit:
        tot, idx = heapq.heappop(heap)
        yield idx, tot
        n += 1
        for c in range(k):
            nxt = list(idx)
            nxt[c] += 1
            if nxt[c] >= len(vals[c]):
                continue
            t = tuple(nxt)
            if t in seen:
                continue
            seen.add(t)
            heapq.heappush(heap, (tot - vals[c][idx[c]] + vals[c][nxt[c]], t))

def best_first_verified(lists, verify, max_pops=10**6):
    """Walk the product and stop at the first candidate that VERIFIES.

    Returns `(pops, payload)` - the number of candidates tried and the one
    that worked, or `(pops, None)` if the budget ran out. `pops` is the
    attack's candidate count, which is the second half of the
    **(traces, candidate keys)** pair a recovery should be quoted as; a byte
    count alone cannot distinguish a near-miss from a recovery.

    `verify(payload_tuple)` does the assembling and the checking, because what
    a payload means is the caller's: a round key here, a delta vector there.
    It must use only what the attacker has - a captured plaintext/ciphertext
    pair off the wire, not the key from the capture file - or the pop count is
    a rank estimate dressed up as a recovery.
    """
    pops = 0
    for payload in best_first(lists, max_pops):
        pops += 1
        if verify(payload):
            return pops, payload
    return pops, None
