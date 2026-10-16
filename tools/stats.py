"""The labelled statistic, and the controls that make it mean something.

This is a diagnostic, not an attack: it needs the key, so an attacker cannot
run it. It is here because a null and a broken analysis look identical from a
failed recovery, and this is what separates them.

Every demo in this repository reads the cipher's last round, so one
implementation serves all of them: tag each trace by which flash ROW each
last-round S-box lookup fell in, then ask whether traces where two lookups
shared a row are faster than traces where they did not.

    tag = (SINV[ct ^ k10] + line_off) >> line_shift

The geometry matters here exactly as much as it does in the recovery. The
OSCORE capture reads -28 at `line_off=0` and -46 at the 12 its own image has,
with nothing else changed.

Three things to check, and all three have to hold before a number here is worth
anything:

  the effect     large and NEGATIVE. A row collision saves a flash access, so
                 it makes the trace faster. A two-sided "signal" means
                 something else is being measured.
  shuffled       permute the timing: the effect has to vanish. This is what
                 rules out the analysis finding structure in the ciphertext.
  wrong key      label with a key that is not the victim's: also has to
                 vanish.

WHAT THIS DOES NOT DO. It does not recover anything, and a large z is not a
channel - a pooled z of -21.81 that yields 0 of 16 key bytes has happened on
this bench. Run the recovery.
"""
from __future__ import annotations

import numpy as np


def pooled_z(known_blocks, timing, key, *, line_off=0, line_shift=4):
    """(pooled z, per-pair z array) over the 120 output-byte pairs."""
    from flashattack import aesref

    rk10 = np.array(aesref.key_expansion(list(key))[10], np.int64)
    ct = np.asarray(known_blocks, np.int64)
    tag = (aesref.SINV.astype(np.int64)[ct ^ rk10[None, :]]
           + line_off) >> line_shift

    y = np.asarray(timing, float)
    n, sd = len(y), y.std()
    zs = []
    for a in range(16):
        for b in range(a + 1, 16):
            same = tag[:, a] == tag[:, b]
            nc = int(same.sum())
            if nc < 50 or nc > n - 50:
                continue
            d = y[same].mean() - y[~same].mean()
            zs.append(d / (sd * np.sqrt(1.0 / nc + 1.0 / (n - nc))))
    z = np.array(zs)
    return float(z.mean() * np.sqrt(z.size)), z


def controls(known_blocks, timing, key, *, line_off=0, line_shift=4, seed=0):
    """(effect, shuffled, wrong key) as three pooled z values."""
    z, _ = pooled_z(known_blocks, timing, key,
                    line_off=line_off, line_shift=line_shift)
    shuffled = np.random.default_rng(seed).permutation(np.asarray(timing))
    zs, _ = pooled_z(known_blocks, shuffled, key,
                     line_off=line_off, line_shift=line_shift)
    zw, _ = pooled_z(known_blocks, timing, bytes(range(16)),
                     line_off=line_off, line_shift=line_shift)
    return z, zs, zw
