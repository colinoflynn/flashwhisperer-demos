"""Recover the link key from a listener capture. Two endgames, both verified.

The attack is the ordinary last-round collision attack - which flash row each
S-box read of the final round lands in - and CCM* makes it unusually cheap to
finish, because the frame carries the cipher's INPUT in the clear as well as
handing over its OUTPUT. Any candidate key is settled by one AES block with
nothing secret, so the scoring only has to put the truth in a small set.

TWO ENDGAMES, and the difference between them is the whole story of this demo.

`recover()` scores all 120 output-byte pairs, standardises each surface and
sums what each one says about each byte on its own. Every byte is then
constrained by the fifteen pairs it appears in rather than by one, and on the
blind capture that lands all sixteen round-10 bytes at rank 1 by about 2.3 M
frames - the key comes straight out of the vote and one AES block confirms it.

`cover_search()` is the older one, and the one the campaign's published numbers
were measured with: pick a disjoint cover of eight byte PAIRS, take the top
cells of each joint 256x256 surface, and walk the product best-first. It is
stronger per edge and much weaker overall, because a passive capture produces a
lopsided cover - seven edges solved and one at rank 435 - and total-score order
grinds through every tuple that trades a worse cheap candidate for a better
expensive one. Pinning the weak edge (`pin=True`) searches that structure
instead and is what first recovered a key from the air: 59.1 M verifications.
It is kept because it is the fallback when the marginal evidence is flat, and
because a reader comparing numbers needs the search that produced them.

Which edge is weak, which bytes are weak, and which offset to use are all
decided WITHOUT the key. `truth` only ever labels a note.

WHAT THIS DOES NOT DO
  * It does not sweep the row offset. Pass the one the victim's ELF gives.
    Sweeping costs four scorings and verification cannot pick a wrong answer,
    so it is a fine thing to do - it just belongs in the caller.
  * It does not know the adjacency of the victim's last round. Contiki-NG's
    `aes-128.c` runs SubBytes over the state in index order and ShiftRows
    after, which is the `ct_adjacent=False` convention, and that is baked into
    the 120-pair sweep only in the sense that the sweep does not care.
  * A large statistic is not a key. `tools/stats.py` prints the labelled
    effect and its controls; this prints a key or nothing.
"""
from __future__ import annotations

import itertools

import numpy as np

from flashattack import bruteforce, lastround, search

LINE_SHIFT = 4          # a 1-byte S-box in a 16-byte flash row


def verify_batch(rk10, known):
    """(master keys, hit mask) for many candidate round-10 keys, one block each.

    `known` is the (AES input, AES output) pair the capture gave us. Decrypting
    the output under each candidate and comparing against the input is the same
    test as encrypting, and it is the direction `flashattack.bruteforce`
    already vectorises.
    """
    rk10 = np.asarray(rk10, np.uint8).reshape(-1, 16)
    master = bruteforce.invert_key_schedules(rk10)
    rks = bruteforce.expand_keys(master)
    want = np.frombuffer(bytes(known[0]), np.uint8)
    got = bruteforce.decrypt_block(rks, np.frombuffer(bytes(known[1]), np.uint8))
    return master, (got == want[None, :]).all(axis=1)


def surfaces(ct, y, *, line_off, line_shift=LINE_SHIFT, pairs="all", log=None):
    """{(ja, jb): score surface} over a coverage spec. Scoring is most of the time."""
    out = {}
    y = np.asarray(y, float)
    y = y - y.mean()
    for a, b in lastround.coverage(pairs):
        out[(a, b)] = lastround.score_surface(ct[:, a], ct[:, b], y,
                                              lastround.SINV,
                                              line_shift=line_shift,
                                              line_off=line_off)
        if log:
            ga, gb, mg = lastround.best(out[(a, b)], margin="z")
            log("  pair (%2d,%2d) -> (%3d,%3d) margin %.2f" % (a, b, ga, gb, mg))
    return out


def byte_evidence(surfs):
    """Per-byte scores, summed over every pair a byte appears in. (16, 256).

    Each surface is standardised first, because the pairs have different
    numbers of traces surviving the collision test and summing them raw lets
    the noisiest one dominate. What is summed is the surface's MINIMUM along
    the other byte: for the true value of this byte the row contains the true
    cell, which is the lowest cell on the surface, and for a wrong value the
    row is 256 draws of noise. Lower is better throughout, because a row
    collision saves a flash access and makes the frame faster.

    The mean along the other byte is the obvious alternative and it is much
    worse here, measured: 3 of 16 bytes at rank 1 against 16 of 16 on the same
    capture. Averaging dilutes one good cell into 255 bad ones.
    """
    M = np.zeros((16, 256))
    for (a, b), S in surfs.items():
        Z = search.standardise(S)
        M[a] += Z.min(axis=1)
        M[b] += Z.min(axis=0)
    return M


def candidate_lists(M, depth=256):
    """Per byte: candidate values ascending, and their cost above the best."""
    order = np.argsort(M, axis=1)[:, :depth]
    cost = np.take_along_axis(M, order, axis=1)
    return order, cost - cost[:, :1]


def recover(ct, y, known, *, line_off, line_shift=LINE_SHIFT, pairs="all",
            weak=6, depth=64, wrong=3, truth=None, log=None,
            vote_only=False):
    """(master key or None, notes, info). The marginal endgame."""
    notes = []
    surfs = surfaces(ct, y, line_off=line_off, line_shift=line_shift,
                     pairs=pairs, log=log)
    M = byte_evidence(surfs)
    order, cost = candidate_lists(M, depth=depth)
    rk10 = order[:, 0].astype(np.uint8)
    margin = cost[:, 1]                       # cost of the runner-up, per byte

    if truth is not None:
        rk = np.array(bruteforce.expand_keys(
            np.frombuffer(bytes(truth), np.uint8)[None, :])[0, 10], np.uint8)
        ranks = [1 + int((M[i] < M[i, rk[i]]).sum()) for i in range(16)]
        notes.append("vote got %d/16 round-key bytes (validation only)"
                     % int((rk10 == rk).sum()))
        notes.append("true-byte ranks %s, %.1f residual bits (validation only)"
                     % (ranks, search.residual_bits(ranks)))

    master, hit = verify_batch(rk10[None, :], known)
    if hit[0]:
        notes.append("verified straight from the vote, 1 candidate key")
        return bytes(master[0]), notes, {"M": M, "surfaces": surfs, "candidates": 1}

    if vote_only:
        notes.append("vote only: no escalation attempted")
        return None, notes, {"M": M, "surfaces": surfs, "candidates": 1}

    # Escalate: the vote is wrong on a few bytes, so take the least confident
    # `weak` positions and try every combination of up to `wrong` of them over
    # their top `depth` candidates. One wrong byte, then two, then three, which
    # is the same shape `flashattack.bruteforce` uses for a known pair and for
    # the same reason - each candidate costs one AES block.
    #
    # The alternative, a best-first walk over all sixteen lists in total-cost
    # order, is what a key-enumeration paper would do and it was tried first.
    # It is worse here on both counts. The truth sits FAR deeper than the
    # product of its ranks - 4 800 by the ranks and past 131 072 pops in the
    # cost order on the stock capture - because the walk spends its budget
    # trading a cheap worse candidate for an expensive better one, which is the
    # same lower-bound trap the cover search below fell into. And the heap
    # keeps every index tuple it has queued, 16 per pop, which is gigabytes at
    # a budget worth having.
    pos = [int(p) for p in np.argsort(margin)[:weak]]
    cands = {p: [int(v) for v in order[p, 1:depth]] for p in pos}
    tried = 1
    for r in range(1, min(wrong, len(pos)) + 1):
        for sub in itertools.combinations(pos, r):
            mk = bruteforce.search_positions(
                bytes(rk10), list(sub), None,
                values=[cands[p] for p in sub], known=known)
            tried += int(np.prod([len(cands[p]) for p in sub]))
            if mk is not None:
                notes.append("verified after about %d candidate keys: the vote "
                             "was wrong on bytes %s"
                             % (tried, [int(s) for s in sub]))
                return bytes(mk), notes, {"M": M, "surfaces": surfs,
                                          "candidates": tried}
        if log:
            log("  no key with %d wrong bytes (%d candidates so far)"
                % (r, tried))

    notes.append("no key in about %d candidates over the %d least confident "
                 "bytes; the vote was not good enough and the answer is more "
                 "frames" % (tried, len(pos)))
    return None, notes, {"M": M, "surfaces": surfs, "candidates": tried}


# ---------------------------------------------------------------------------
# The older endgame: joint pair surfaces, a disjoint cover, best-first or
# pinned. This is what the over-the-air numbers in the README were first
# measured with, and it is the fallback when byte_evidence comes out flat.
# ---------------------------------------------------------------------------

def _edges(surfs, depth):
    """Every scored pair as an edge, with a key-free confidence."""
    out = []
    for (a, b), S in surfs.items():
        Z = search.standardise(S)
        flat = np.where(np.isfinite(Z), Z, np.inf).ravel()
        sel = np.argsort(flat, kind="stable")[:depth]
        cands = [(int(s // 256), int(s % 256), float(flat[s])) for s in sel]
        # How far the winner sits below the runner-up, scaled by its own depth.
        # No key involved, which is what lets the cover be chosen honestly.
        conf = abs(cands[0][2]) + (cands[1][2] - cands[0][2]) * 10.0
        out.append({"a": a, "b": b, "cands": cands, "conf": conf})
    return out


def covers(edges, want=12):
    """Sets of eight disjoint edges spanning all sixteen byte positions.

    Any perfect matching is a legal cover, which is the point: pairing two
    WHOLE pair sets left one joint attack with the truth outside its top 64 and
    that one attack alone blocked recovery, where mixing columns across sets
    gave a cover whose worst true rank was 16.
    """
    order = sorted(range(len(edges)), key=lambda i: -edges[i]["conf"])
    out = []

    def rec(pos, used, chosen):
        if len(out) >= want:
            return
        if len(chosen) == 8:
            out.append(list(chosen))
            return
        for k in range(pos, len(order)):
            e = edges[order[k]]
            if e["a"] in used or e["b"] in used:
                continue
            chosen.append(order[k])
            rec(k + 1, used | {e["a"], e["b"]}, chosen)
            chosen.pop()
            if len(out) >= want:
                return

    rec(0, frozenset(), [])
    return out


def cover_search(surfs, known, *, depth=32, budget=400000, n_covers=12,
                 pin=False, pin_deep=512, pin_shallow=30000, log=None):
    """(master or None, notes). The cover endgame, uniform or pinned.

    The candidate counts it reports are rounded up to the verification batch,
    which is 4096 keys, because that is where the AES stops being the expensive
    part. A walk that finds the key on its first pop says 4096.
    """
    notes = []
    edges = _edges(surfs, max(depth, pin_deep if pin else depth))
    sets = covers(edges, want=n_covers)
    notes.append("%d covers over %d scored pairs" % (len(sets), len(edges)))
    for ci, cover in enumerate(sets):
        groups = [edges[i] for i in cover]
        if pin:
            # Least confident edge first. On the recovery that worked the true
            # weak edge was the FOURTH in this order, not the first, which is
            # the argument against capping the number of edges tried.
            for ei in sorted(range(8), key=lambda i: groups[i]["conf"]):
                got, pops = _pinned(groups, ei, known, pin_deep, pin_shallow)
                if got:
                    notes.append("cover %d, pinned edge (%d,%d), %d candidates"
                                 % (ci + 1, groups[ei]["a"], groups[ei]["b"], pops))
                    return got, notes
                if log:
                    log("  cover %d pinned (%d,%d): no key in %d"
                        % (ci + 1, groups[ei]["a"], groups[ei]["b"], pops))
        else:
            got, pops = _walk(groups, known, budget, depth)
            if got:
                notes.append("cover %d, uniform walk, %d candidates"
                             % (ci + 1, pops))
                return got, notes
            if log:
                log("  cover %d: no key in %d candidates" % (ci + 1, pops))
    notes.append("no verified key at these settings")
    return None, notes


def _verify_rows(groups, idxs, known, fixed, pops):
    """Assemble one batch of index tuples into round keys and check them."""
    cand = np.zeros((len(idxs), 16), np.uint8)
    for row, idx in enumerate(idxs):
        for j, g in enumerate(groups):
            ga, gb, _ = g["cands"][idx[j]]
            cand[row, g["a"]], cand[row, g["b"]] = ga, gb
        if fixed is not None:
            g, (ga, gb) = fixed
            cand[row, g["a"]], cand[row, g["b"]] = ga, gb
    master, hit = verify_batch(cand, known)
    pops += len(idxs)
    if hit.any():
        return bytes(master[int(np.flatnonzero(hit)[0])]), pops
    return None, pops


def _walk(groups, known, budget, depth, fixed=None):
    """Best-first over the product of these edges' candidate lists."""
    vals = [[c[2] - g["cands"][0][2] for c in g["cands"][:depth]]
            for g in groups]
    pops, batch, idxs = 0, 4096, []
    for idx, _t in search.best_first_indices(vals, budget):
        idxs.append(idx)
        if len(idxs) == batch:
            got, pops = _verify_rows(groups, idxs, known, fixed, pops)
            idxs = []
            if got:
                return got, pops
    if idxs:
        got, pops = _verify_rows(groups, idxs, known, fixed, pops)
        if got:
            return got, pops
    return None, pops


def _pinned(groups, ei, known, deep, shallow):
    """Pin one edge to each of its `deep` candidates; walk the other seven."""
    rest = [g for j, g in enumerate(groups) if j != ei]
    pops = 0
    for pin_idx in range(min(deep, len(groups[ei]["cands"]))):
        pa, pb, _ = groups[ei]["cands"][pin_idx]
        got, used = _walk(rest, known, shallow, len(rest[0]["cands"]),
                          fixed=(groups[ei], (pa, pb)))
        pops += used
        if got:
            return got, pops
    return None, pops
