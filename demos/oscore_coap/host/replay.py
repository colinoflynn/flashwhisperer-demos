"""Replay adapter: a packed OSCORE vector in, the attack's two arrays out.

`tools/replay.py` is the driver and knows nothing about any protocol. This is
the OSCORE half of the seam, and there is one of these per demo:

    load(path, geom)   -> {known_blocks, timing, keystreams, info}
    attack(data, geom) -> (master_key or None, notes)

What makes OSCORE's `load` more than `np.load` is that the vector does not
store the keystream. Every block the attacker read off the wire is
`E(K, A_i(PIV))` for consecutive Partial IVs, so given the key, the Common IV
and the first PIV, the whole sequence regenerates exactly - which is how 600 000
exchanges fit in under two megabytes. `host/make_vector.py` refuses to write a
vector whose keystreams do not reproduce byte for byte.
"""
from __future__ import annotations



from flashattack import oracle as oracle_mod

from . import make_vector
from . import recover as recover_mod


def load(path, geom):
    """The attacker's two arrays, conditioned the way the demo specifies."""
    atk = geom["attack"]
    ks, cols, label = make_vector.load_vector(path)
    column = atk.get("column", "dt_hw")
    y, keep, info = oracle_mod.condition(cols[column].astype(float),
                                         method=atk.get("conditioning", "mode"))
    ks, y = ks[keep], y[keep]

    n = atk.get("n")
    if n:
        ks, y = ks[:n], y[:n]

    return {
        "known_blocks": ks,          # the keystream IS the AES output block
        "timing": y,
        "keystreams": ks,            # and it is also what verification uses
        "info": {
            "label": label,
            "column": column,
            "kept": len(y),
            "modes": info.get("n_modes"),
            "spread": info.get("std"),
        },
    }


def attack(data, geom, log=None, vote_only=False, truth=None):
    """(master key or None, notes). The recovery never reads the true key.

    `truth`, when given, only adds a line to the notes saying how many
    round-key bytes the vote got right. That is validation, not part of the
    attack, and it is the number the README's trace ladder is made of.
    """
    g = geom["geometry"]
    atk = geom["attack"]
    master, res, notes = recover_mod.recover_and_verify(
        data["known_blocks"], data["timing"], data["keystreams"],
        line_off=g["line_off"],
        pair_offsets=atk.get("pair_offsets") or None,
        vote_only=vote_only, log=log)
    notes = list(notes)
    if truth is not None:
        hit, _ = recover_mod.score_against(res, truth)
        notes.append("vote got %d/16 round-key bytes (validation only)" % hit)
    notes.append("vote confidence floor %.2f" % min(res.confidence))
    return master, notes
