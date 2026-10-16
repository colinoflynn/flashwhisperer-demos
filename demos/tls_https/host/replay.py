"""Replay adapter: a packed TLS vector in, the attack's two arrays out.

The one thing this does that the other adapters do not is STACK. Each exchange
gives one timing and fifteen AES blocks, and all fifteen were encrypted inside
that one measured turnaround, so each block is its own trace carrying its
exchange's time. The collision patterns of different blocks are independent -
the inputs are effectively random - so each block contributes its own evidence
while the other fourteen look like noise to it.

So `n` in the vector's json counts EXCHANGES, and the trace count the attack
sees is fifteen times that. Both numbers are printed, because quoting the wrong
one makes this demo look fifteen times cheaper or fifteen times dearer than it
is.

Conditioning is `mode` here, not the `fast` the SNMPv3 vector asks for: on this
capture keeping every mode and subtracting each one's own mean beats keeping
only the fast mode by a factor of about three and a half.
"""
from __future__ import annotations

import numpy as np

from flashattack import oracle as oracle_mod

from tools import knownpair

from . import make_vector


def load(path, geom):
    atk = geom["attack"]
    outs, t, meta = make_vector.load_vector(path)
    y, keep, info = oracle_mod.condition(t, method=atk.get("conditioning", "mode"))
    outs, y = outs[keep], y[keep]

    nex = atk.get("n")
    if nex:
        outs, y = outs[:nex], y[:nex]

    nblk = meta["blocks"]
    stacked = np.concatenate([outs[:, i, :] for i in range(nblk)])
    timing = np.tile(y, nblk)

    return {
        "known_blocks": stacked,
        "timing": timing,
        "known": meta["known"],
        "info": {
            "label": meta["label"],
            "column": "dt_hw",
            "kept": len(timing),
            "modes": info.get("n_modes"),
            "spread": info.get("std"),
            "exchanges": len(y),
            "blocks_per_exchange": nblk,
        },
    }


def attack(data, geom, log=None, vote_only=False, truth=None):
    g, atk = geom["geometry"], geom["attack"]
    master, notes, _res = knownpair.recover(
        data["known_blocks"], data["timing"],
        known=data["known"],
        line_off=g["line_off"], line_shift=g["line_shift"],
        pair_offsets=atk.get("pair_offsets") or None,
        truth=truth, vote_only=vote_only, log=log)
    notes.insert(0, "%d exchanges x %d blocks = %d traces"
                 % (data["info"]["exchanges"], data["info"]["blocks_per_exchange"],
                    len(data["timing"])))
    return master, notes
