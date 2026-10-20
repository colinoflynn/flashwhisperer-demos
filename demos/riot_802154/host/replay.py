"""Replay adapter: a packed capture in, the attack's two arrays out.

`tools/replay.py` is the driver and knows nothing about any protocol. This is
the 802.15.4 half of the seam:

    load(path, geom)   -> {known_blocks, timing, known, info}
    attack(data, geom) -> (master key or None, notes)

What makes `load` more than `np.load` is that the vector stores no AES output.
Every block is `AES_K(A_i)` for a counter block built out of public frame
fields, so the key in the json's `truth` regenerates the sequence exactly --
and `make_vector.pack` refused to write a vector whose blocks did not come
back byte for byte, so what comes out here is what came off the air.

It is also more than `np.load` for a second reason, and it is the one that
decides whether this demo works: the conditioning. `recover.condition` removes
the CSMA slot's residual offset and the ACK's common mode, which on this
capture is the difference between 3 of 16 round-key bytes and all sixteen. A
replay that loaded the raw interval would reproduce the campaign's null rather
than its key.
"""

from __future__ import annotations

import numpy as np

from . import make_vector
from . import recover as recover_mod


def _rows(path, geom):
    key = bytes.fromhex(geom["truth"]["master_key"])
    blocks = [int(b) for b in geom["attack"].get("blocks", [1, 2, 3, 4])]
    rows = make_vector.load_rows(path, key, blocks)
    n = geom["attack"].get("n")
    return (rows[:n] if n else rows), rows[n:] if n else [], blocks


def load(path, geom):
    """The attacker's two arrays, conditioned the way the vector specifies."""
    rows, holdout, blocks = _rows(path, geom)
    mode = geom["attack"].get("mode", "full")
    timing = recover_mod.condition(rows, mode)
    known, y = recover_mod.stack(rows, blocks, timing)
    return {
        "known_blocks": known,
        "timing": y,
        "known": None,
        "rows": rows,
        "holdout": holdout,
        "blocks": blocks,
        "info": {
            "label": geom["vector"],
            "column": "reply turnaround, %s-conditioned" % mode,
            "kept": len(y),
            "modes": "%d replies x %d CTR blocks" % (len(rows), len(blocks)),
            "spread": float(1.4826 * np.median(np.abs(y - np.median(y)))),
        },
    }


def attack(data, geom, log=None, vote_only=False, truth=None):
    """(master key or None, notes). The recovery never reads the true key.

    `truth`, when the driver passes it, only adds notes about how many
    round-key bytes the vote got. That is validation, and it is what the
    README's trace table is made of.
    """
    g, atk = geom["geometry"], geom["attack"]
    return recover_mod.recover(
        data["rows"], data["blocks"], g["line_off"],
        mode=atk.get("mode", "full"),
        depth=atk.get("depth", 8),
        budget=atk.get("budget", 1 << 20),
        pairs=atk.get("pairs", "all"),
        holdout=data["holdout"] or None,
        truth=truth, vote_only=vote_only)
