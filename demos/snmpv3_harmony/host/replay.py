"""Replay adapter: a packed PIC32MZ cipher-probe vector in, two arrays out.

Nearly the same as the SNMPv3 demo's adapter next door, because it is the same
protocol and the same reduction. What differs is the oracle - the cipher's own
CP0 cycles rather than a network turnaround - so there is no multimodal network
noise to condition away and the vector asks for `raw`.

The pair sets are the other difference, and they are the reason this demo
exists in the shape it does. XC32 does not emit wolfCrypt's last-round reads in
source order: in this image the order is ct[0] -> ct[3] -> ct[1] -> ct[2], so
the output-byte pairs that can share a flash row are (0,3), (1,3) and (1,2),
and the pairs the source suggests cannot collide at all. Scoring all 120 pairs
includes the right ones; scoring the "obvious" ones gets zero of twenty-four.
Derive that per image, from the shift amounts in the disassembly, never from
the source.
"""
from __future__ import annotations

from flashattack import oracle as oracle_mod

from tools import knownpair

from . import make_vector


def load(path, geom):
    atk = geom["attack"]
    out, t, meta = make_vector.load_vector(path)
    y, keep, info = oracle_mod.condition(t, method=atk.get("conditioning", "raw"))
    out, y = out[keep], y[keep]

    n = atk.get("n")
    if n:
        out, y = out[:n], y[:n]

    return {
        "known_blocks": out,
        "timing": y,
        "known": meta["known"],
        "info": {
            "label": meta["label"],
            "column": meta["unit"] or "cp0",
            "kept": len(y),
            "modes": info.get("n_modes"),
            "spread": info.get("std"),
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
    return master, notes
