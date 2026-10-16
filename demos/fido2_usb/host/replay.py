"""Replay adapter for the FIDO2 demo: the ladder's relations, re-derived.

This demo's recovery has two halves and only the first one is cheap.

The measurement half is a ladder of thirteen stages. Each stage sweeps 64 delta
classes over forged credential blobs, times the authenticator's reply from a
bare-metal USB host, and takes the class with the lowest mean poll count; that
argmin is six bits of a relation between two key bytes. That half is what the
vector holds, and re-deriving it from the rows is what `check()` below does.

The search half is 2^44 and lives in [`../search`](../search), a CPU searcher
at about 3 Gcandidate/s with VAES - an hour and a half on ten cores, or twelve
minutes on faster silicon. It is not run here and not run in CI, because a
twelve-minute Rust build-and-search is not a regression test. `tools/replay.py`
therefore reports this vector as RELATIONS rather than as a key, and the json
says `expect_kind: relations` so nothing mistakes that for a control.

What the demo claims, and where each part is checked:

  the dips are real            `check()` here, and host/stage_stats.py for the
                               shuffle null, the frame-phase spread and the
                               split-half replication
  the relations compose into
  a 2^44 constraint file       host/constraints_from_campaign.py, whose own
                               docstring carries the caveat that matters: the
                               anchor format needs a CONNECTED relation graph,
                               and its diff6 values assume a 16-byte-aligned
                               table while this victim's is at pad 4
  the key falls out of it      ../search, and the recovered key is in the json
                               as truth so a replay can say whether the
                               published answer and these rows agree
"""
from __future__ import annotations

import numpy as np


def _stages(path):
    d = np.load(path, allow_pickle=False)
    rows, lens, off = d["rows"], d["row_lens"], 0
    out = []
    for i, name in enumerate(d["stage"]):
        a = rows[off:off + lens[i]]
        off += int(lens[i])
        out.append({
            "stage": str(name),
            "rows": a,
            "deltas": np.asarray(d["deltas"][i]),
            "offset": int(d["offset"][i]),
            "p": int(d["p"][i]),
            "q": int(d["q"][i]),
            "sigma": float(d["margin_sigma"][i]),
            "kind": str(d["kind"][i]),
        })
    return out, str(d["label"])


def _argmin(stage, labels=None):
    polls = stage["rows"][:, 1].astype(float)
    lab = stage["rows"][:, 0].astype(int) if labels is None else labels
    means = {int(dd): polls[lab == dd].mean()
             for dd in stage["deltas"] if (lab == dd).sum() > 2}
    return min(means, key=means.get) if means else None


def load(path, geom):
    stages, label = _stages(path)
    n = sum(len(s["rows"]) for s in stages)
    return {
        "path": path,
        "stages": stages,
        "known_blocks": None,
        "timing": stages[0]["rows"][:, 1].astype(float),
        "info": {
            "label": label,
            "column": "USB reply poll count, per forged credential blob",
            "kept": n,
            "modes": "%d stages" % len(stages),
            "spread": float(np.std(np.concatenate(
                [s["rows"][:, 1].astype(float) for s in stages]))),
        },
    }


def check(data, geom):
    """(ok, one line). Does each stage's dip sit where the record says?"""
    stages = data["stages"]
    rng = np.random.default_rng(geom["attack"].get("shuffle_seed", 7))
    hit = sum(_argmin(s) == s["offset"] for s in stages)
    shuffled = sum(_argmin(s, rng.permutation(s["rows"][:, 0].astype(int)))
                   == s["offset"] for s in stages)
    weak = min(s["sigma"] for s in stages)
    ok = (hit == len(stages)) and shuffled == 0
    return ok, ("%d/%d stages reproduce their recorded class, %d/%d with the "
                "labels shuffled, weakest margin %.2f sigma"
                % (hit, len(stages), shuffled, len(stages), weak))


def attack(data, geom, log=None, vote_only=False, truth=None):
    """No key here, by design: see the module docstring and ../search."""
    ok, line = check(data, geom)
    notes = [line,
             "the 2**44 search that turns these relations into the key is "
             "../search, and is not run by a replay"]
    for s in data["stages"]:
        notes.append("  %-12s k[%2d] against k[%2d]  class %3d  %4.2f sigma  %s"
                     % (s["stage"], s["p"], s["q"], s["offset"], s["sigma"], s["kind"]))
    return None, notes


def controls(data, geom, truth):
    ok, line = check(data, geom)
    return line
