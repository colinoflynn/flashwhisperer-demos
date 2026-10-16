"""Feasibility / trace-count estimation and amplification advice.

From a pilot capture, estimate how many traces a full recovery needs and (for a
noisy external oracle like ACK latency) how much in-device amplification K to use.

The recovery margin grows ~ sqrt(N) in the white-noise regime, so from the pilot's
weakest per-byte confidence we extrapolate N for a target confidence. This is a
heuristic guide, not a guarantee (correlated jitter - see the bootloader result --
breaks the sqrt law; that is exactly the case where amplification, not more N, is
the fix).
"""
from __future__ import annotations
import math
import numpy as np
from . import engine


def estimate(known_blocks, timing, *, direction="enc", target_conf=3.0):
    res = engine.recover(known_blocks, timing, direction=direction)
    n = len(timing)
    conf = res.confidence
    weakest_pos = int(np.argmin(conf)); weakest = conf[weakest_pos]
    if weakest >= target_conf:
        n_needed = n
        verdict = f"pilot already sufficient (weakest byte conf {weakest:.2f} >= {target_conf})"
    else:
        n_needed = int(math.ceil(n * (target_conf / max(weakest, 1e-6)) ** 2))
        verdict = (f"weakest byte {weakest_pos} conf {weakest:.2f}; ~{n_needed:,} traces "
                   f"estimated for conf {target_conf} (sqrt-N; correlated jitter may need more, "
                   f"or use amplification)")
    return {
        "n_pilot": n, "per_byte_confidence": conf, "weakest_pos": weakest_pos,
        "weakest_conf": weakest, "n_needed_est": n_needed, "verdict": verdict,
        "assembled_roundkey": res.roundkey.hex(),
    }


def recommend_amplification(per_op_signal_cyc, jitter_cyc, want_ratio=1.0, k_max=255):
    """K so that K*signal ~ want_ratio*jitter (bring the amplified collision signal
    up to the jitter level). Returns (K, note)."""
    if per_op_signal_cyc <= 0:
        return 1, "no signal estimate"
    K = int(math.ceil(want_ratio * jitter_cyc / per_op_signal_cyc))
    K = max(1, min(K, k_max))
    return K, (f"K={K} makes amplified signal ~{K*per_op_signal_cyc:.0f} cyc "
               f"vs jitter ~{jitter_cyc:.0f} cyc (ratio target {want_ratio})")


def signal_from_calibration(oncore_cyc, K):
    """Rough per-decrypt collision-signal magnitude from a calibration capture:
    the std of the (data-dependent) on-chip time divided by K."""
    return float(np.std(oncore_cyc)) / max(K, 1)
