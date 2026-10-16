"""Quick leakage assessment - a fast go/no-go before committing to full recovery.

Three tools:
  * constant_time_check(timing) - is the timing data-independent (std ~ 0)? The
    decisive test for constant-time / bitsliced code.
  * exploitability(capture)     - KEY-FREE. Runs the collision scan on a small
    sample of byte-pairs; the best margin measures the *exploitable* collision
    signal (note: a first-order/Bernstein test is flat here, so we test the pair
    collisions that the attack actually uses) and estimates traces-to-break.
  * tvla_fixed_random(fixed, random) - the gold-standard non-specific TVLA
    Welch t-test, if a fixed-vs-random capture is available (|t|>4.5 => leaks).
"""
from __future__ import annotations
import numpy as np
from . import engine


def constant_time_check(timing, floor=0.5):
    t = np.asarray(timing, float)
    std = float(t.std()); uniq = int(np.unique(np.round(t)).size)
    constant = std <= floor
    return {"std": std, "distinct_values": uniq, "constant_time": constant,
            "verdict": ("constant-time: no data-dependent timing (immune to this channel)"
                        if constant else "data-dependent timing present")}


def exploitability(capture, sample_pairs=10, target_margin=6.0, seed=0):
    """Key-free strength estimate. Returns the strongest collision margin over a
    random sample of byte-pairs and an extrapolated trace count for full recovery
    (margin ~ sqrt(N))."""
    known, direction = capture.engine_input()
    tbl = engine.SINV if direction == "enc" else engine.SBOX
    y = capture.timing - capture.timing.mean()
    rng = np.random.default_rng(seed)
    allpairs = [(a, b) for a in range(16) for b in range(a + 1, 16)]
    idx = rng.choice(len(allpairs), size=min(sample_pairs, len(allpairs)), replace=False)
    margins = []
    for k in idx:
        a, b = allpairs[k]
        _, _, mg = engine.col_attack_scored(known[:, a], known[:, b], y, tbl, capture.line_shift_last)
        margins.append(mg)
    mmax = float(max(margins))
    n = capture.n
    if mmax >= target_margin:
        est = n
        verdict = f"exploitable: margin {mmax:.1f} at {n} traces (>= {target_margin})"
    elif mmax < 1.5:
        est = None
        verdict = f"no collision signal detected (max margin {mmax:.1f}); likely not exploitable / constant-time"
    else:
        est = int(n * (target_margin / mmax) ** 2)
        verdict = f"weak signal (margin {mmax:.1f}); ~{est:,} traces estimated for full recovery"
    return {"max_margin": mmax, "sampled_pairs": len(margins),
            "n_traces": n, "traces_to_break_est": est, "verdict": verdict}


def tvla_fixed_random(fixed_timing, random_timing, threshold=4.5):
    """Welch's t-test between a fixed-input group and a random-input group (the
    standard non-specific TVLA). |t| > threshold => data-dependent leakage."""
    a = np.asarray(fixed_timing, float); b = np.asarray(random_timing, float)
    va, vb = a.var(ddof=1), b.var(ddof=1)
    t = (a.mean() - b.mean()) / np.sqrt(va / a.size + vb / b.size + 1e-30)
    leaks = abs(t) > threshold
    return {"t": float(t), "threshold": threshold, "leaks": bool(leaks),
            "verdict": f"{'LEAKS' if leaks else 'no leakage'} (|t|={abs(t):.1f}, thr {threshold})"}


def assess(capture):
    """One-call quick check: constant-time + exploitability."""
    ct = constant_time_check(capture.timing)
    if ct["constant_time"]:
        return {"constant_time": ct, "exploitability": None,
                "summary": ct["verdict"]}
    ex = exploitability(capture)
    return {"constant_time": ct, "exploitability": ex, "summary": ex["verdict"]}
