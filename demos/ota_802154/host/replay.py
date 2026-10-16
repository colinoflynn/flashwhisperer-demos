"""Replay adapter: a packed listener capture in, the attack's two arrays out.

`tools/replay.py` is the driver and knows nothing about any protocol. This is
the 802.15.4 half of the seam, and there is one of these per demo:

    load(path, geom)   -> {known_blocks, timing, info}
    attack(data, geom) -> (master_key or None, notes)

What makes `load` more than `np.load` is that the vector does not store the AES
output at all. Every block the listener saw is `AES(K, A_1)` for a counter
block built out of fields the frame carries in the clear, so given the key and
the frame counters the whole sequence regenerates exactly - which is how 2.6
million frames fit in a few megabytes. `host/make_vector.py` refuses to write a
vector whose blocks do not come back byte for byte.
"""
from __future__ import annotations

import numpy as np

from . import logread
from . import make_vector
from . import recover as recover_mod


def load(path, geom):
    """The attacker's two arrays, conditioned the way the vector specifies."""
    atk = geom["attack"]
    ct, gap, label, hz = make_vector.load_vector(path)
    y, keep = logread.condition(gap, trim=atk.get("trim", 6.0),
                                highpass=atk.get("highpass", 0), verbose=False)
    ct = ct[keep]

    n = atk.get("n")
    if n:
        ct, y = ct[:n], y[:n]

    return {
        "known_blocks": ct,
        "timing": y,
        "known": make_vector.known_pair(path),
        "info": {
            "label": label,
            "column": "turnaround",
            "kept": len(y),
            "modes": ("high-pass %d" % atk["highpass"]) if atk.get("highpass")
                     else "raw",
            "spread": float(1.4826 * np.median(np.abs(y - np.median(y)))),
            "listener_hz": hz,
        },
    }


def attack(data, geom, log=None, vote_only=False, truth=None):
    """(master key or None, notes). The recovery never reads the true key.

    `truth`, when given, only adds notes saying how many round-key bytes the
    vote got and where the true bytes ranked. That is validation, and it is
    what the README's trace ladder is made of.
    """
    g = geom["geometry"]
    atk = geom["attack"]
    master, notes, _info = recover_mod.recover(
        data["known_blocks"], data["timing"], data["known"],
        line_off=g["line_off"], line_shift=g["line_shift"],
        pairs=atk.get("pairs", "all"),
        weak=atk.get("weak", 6), depth=atk.get("depth", 64),
        wrong=atk.get("wrong", 3),
        vote_only=vote_only, truth=truth, log=log)
    return master, list(notes)
