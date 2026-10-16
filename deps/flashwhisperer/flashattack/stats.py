"""Jitter-robust timing preprocessing.

Real oracles are noisy and non-Gaussian (USB scheduling, OS preemption, thermal
drift). These helpers clean a timing vector before the attack. They operate on a
Capture's `.timing` (or a raw array) and return a new array; `preprocess` chains
them and `apply` returns a new Capture.
"""
from __future__ import annotations
import numpy as np


def trim_outliers(timing, lo=0.0, hi=0.999):
    """Clip to the [lo, hi] quantile range (positive-going OS/USB spikes mostly
    live in the top tail)."""
    t = np.asarray(timing, float)
    a, b = np.quantile(t, lo), np.quantile(t, hi)
    return np.clip(t, a, b)


def detrend(timing, window=None):
    """Remove slow capture-time drift (temperature, clock wander) that does not
    average out as sqrt(N). Subtracts a moving-median baseline over trace index."""
    t = np.asarray(timing, float)
    n = len(t)
    if window is None:
        window = max(101, (n // 50) | 1)          # odd, ~2% of the capture
    if window >= n:
        return t - np.median(t)
    # fast moving median via strided percentile is O(n*w); use a coarse baseline:
    k = window
    pad = k // 2
    tp = np.pad(t, pad, mode="edge")
    # coarse: median of blocks, then interpolate (cheap, adequate for drift)
    nb = max(4, n // k)
    edges = np.linspace(0, n, nb + 1).astype(int)
    centers = (edges[:-1] + edges[1:]) / 2
    meds = np.array([np.median(t[edges[i]:edges[i + 1]]) for i in range(nb)])
    baseline = np.interp(np.arange(n), centers, meds)
    return t - baseline + np.median(t)


def min_filter(timing, groups):
    """Given repeated measurements (an integer group id per trace), return the
    per-group minimum time (kills positive-going jitter - the Brumley-Boneh
    remote-timing trick). Returns (group_ids_sorted, min_time)."""
    t = np.asarray(timing, float); g = np.asarray(groups)
    order = np.argsort(g, kind="stable")
    gs, ts = g[order], t[order]
    uniq, start = np.unique(gs, return_index=True)
    mins = np.minimum.reduceat(ts, start)
    return uniq, mins


def preprocess(timing, *, detrend_drift=True, trim=(0.0, 0.999)):
    t = np.asarray(timing, float)
    if trim is not None:
        t = trim_outliers(t, *trim)
    if detrend_drift:
        t = detrend(t)
    return t


def apply(capture, **kw):
    """Return a copy of `capture` with preprocessed timing."""
    import copy
    c = copy.copy(capture)
    c.timing = preprocess(capture.timing, **kw)
    return c
