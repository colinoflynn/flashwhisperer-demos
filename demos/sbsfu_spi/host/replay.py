"""Replay adapter for the bootloader demo: a capture in, the key or nothing out.

This one is shaped differently from the other demos' adapters, for two reasons
that are the demo rather than the plumbing.

The attack is on round ONE of a DECRYPTION. SBSFU decrypts, mbedTLS's inverse
cipher XORs the ciphertext with the last round key and indexes the inverse
T-table with the result directly, so the index is `c ^ k` with no S-box in the
way. What that identifies is key-byte DIFFERENCES, not bytes, and the key
itself comes out of a small offline search closed against the genuine image's
own plaintext. So `tools/stats.py`'s last-round statistic does not apply here
and this file does not pretend otherwise: `controls()` below returns the
difference-recovery count instead, and the structural control is a second
vector rather than a statistic.

And the scorer is `host/attack_self.py`, which is the campaign's own, ported
whole. The adapter runs it as a subprocess and reads its verdict, rather than
re-implementing its wiring in-process: that way the thing being checked is the
documented command, and a demo that passes here is a demo you can reproduce by
typing what the README says.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(DEMO))


def load(path, geom):
    """No arrays: this adapter hands `attack()` the paths it needs.

    The capture is already what the attack reads - one interval per chunk and
    the ciphertext that chunk carried - so there is nothing to distil and no
    conditioning to choose. `tools/replay.py` prints what is here instead of a
    trace count, because an interval is not a trace: at this chunk size one
    interval sums 32 block decryptions.
    """
    import numpy as np

    d = np.load(path, allow_pickle=False)
    n = int(d["cycles"].shape[0])
    chunk = int(d["chunk"])
    blocks = n * (chunk // 16)
    return {
        "path": path,
        "known_blocks": None,
        "timing": d["cycles"].astype(float),
        "info": {
            "label": str(d["variant"]),
            # The observer is a property of the CAPTURE, not of this
            # demo: the L475 has a self-timed arm and a bus-side one,
            # and they are the same schema scored by the same code.
            # A vector that does not say is the self-timed one, which
            # is what every vector here was before the bus arm.
            "column": ("%s, %.3f ns per tick"
                       % (str(d["observer"]), 1e9 / int(d["tick_hz"]))
                       if "observer" in d.files
                       else "DWT->CYCCNT across one chunk, 12.5 ns"),
            "kept": n,
            "modes": "n/a",
            "spread": float(d["cycles"].std()),
            "intervals": n,
            "blocks": blocks,
        },
    }


def _scorer_argv(data, geom, extra=()):
    g, atk = geom["geometry"], geom["attack"]
    v = os.path.join(DEMO, "vectors")
    return [sys.executable, "-u", os.path.join(HERE, "attack_self.py"),
            data["path"],
            "--geometry", g.get("scorer_geometry", "latch"),
            "--round", atk.get("round", "first"),
            "--genuine", os.path.join(v, "fw.sfb"),
            "--plain", os.path.join(v, "fw.plain"),
            "--meta", os.path.join(v, "fw.meta")] + list(extra)


def attack(data, geom, log=None, vote_only=False, truth=None):
    """(master key or None, notes), by running the demo's own scorer."""
    argv = _scorer_argv(data, geom, () if vote_only else ("--finish",))
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(ROOT, "deps", "flashwhisperer"), env.get("PYTHONPATH", "")])
    out = subprocess.run(argv, capture_output=True, text=True, env=env).stdout

    notes = ["%d intervals, %d AES blocks (one interval sums %d decryptions)"
             % (data["info"]["intervals"], data["info"]["blocks"],
                data["info"]["blocks"] // max(data["info"]["intervals"], 1))]
    for line in out.splitlines():
        s = line.strip()
        if re.match(r"^\d+ intervals \(", s) or "masked bytes consistent" in s:
            notes.append(s)
        elif s.startswith("residual search:"):
            notes.append(s)

    m = re.search(r"^\s*KEY ([0-9a-f]{32}) after (\d+) candidates", out, re.M)
    if not m:
        if "is past what this script searches" in out:
            notes.append("the residual was past what the scorer searches, so "
                         "no key was attempted")
        notes.append("no key")
        return None, notes
    notes.append("found after %s candidates in the %s residual"
                 % (m.group(2), "2**23" if "2**23" in out else "stated"))
    return bytes.fromhex(m.group(1)), notes


def controls(data, geom, truth):
    """What this reduction can say in place of a last-round statistic.

    Round 1 identifies differences, so the readable number is how many of the
    120 byte pairs the scorer resolved and how many of the 16 masked bytes came
    out consistent. The twin vector is the structural control and it is a
    separate entry in demos/*/vectors/, scored the same way.
    """
    argv = _scorer_argv(data, geom)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(ROOT, "deps", "flashwhisperer"), env.get("PYTHONPATH", "")])
    out = subprocess.run(argv, capture_output=True, text=True, env=env).stdout
    lines = [l.strip() for l in out.splitlines() if "masked bytes consistent" in l]
    return lines[-1] if lines else "the scorer printed no pair summary"
