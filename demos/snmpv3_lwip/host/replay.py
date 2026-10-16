"""Replay adapter: a packed SNMPv3 vector in, the attack's two arrays out.

`tools/replay.py` is the driver and knows nothing about any protocol. This is
the SNMPv3 half of the seam.

One thing here is not like the other demos. This capture is NOT STATIONARY:
its first stretch runs about 8 microseconds faster than the rest, so a single
mode fit that straddles the step spans both regimes and the signal dies. The
conditioning the vector asks for (`fast`) keeps the fast mode and subtracts its
mean, which survives the step; `tools/replay.py --controls` prints how many
traces that kept. If you re-capture and the step is gone, say so in the json
rather than leaving a conditioning choice in place for a reason that no longer
holds.
"""
from __future__ import annotations

from flashattack import oracle as oracle_mod

from tools import knownpair

from . import make_vector


def load(path, geom):
    atk = geom["attack"]
    out, t, meta = make_vector.load_vector(path)
    y, keep, info = oracle_mod.condition(t, method=atk.get("conditioning", "fast"))
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
            "column": "dt_hw",
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
