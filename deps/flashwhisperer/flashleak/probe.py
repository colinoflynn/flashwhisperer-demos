"""Key-free statistical tests for a black-box crypto target.

Every test here answers a question you can ask without knowing the key, the mode,
or even whether the thing is AES. They are ordered by how much they assume:

  timing_summary     nothing at all - is the clock even moving?
  data_dependence    the observed bytes pair with the timings - does the data
                     change the time? Model-free, permutation-calibrated.
  pair_input_test    the observed block is the cipher's INPUT, and lookups are
                     indexed by (block ^ key). Cheap.
  pair_output_test   the observed block is the cipher's OUTPUT of a final round
                     with no MixColumns. Expensive (2^16 per pair) but it is the
                     one that leads to a full key.

The last two are the same collision physics seen from the two sides of the
cipher, and which one fires tells you which side you are looking at. See
`hypotheses.py`.

**Calibration.** Where a test is cheap enough, the null is established by
shuffling the timings against the blocks and recomputing - no distributional
assumption, and it adapts automatically to trace count and bucket count. The
expensive output-side test cannot afford many shuffles, so it carries an analytic
floor (a peak over 65536 cells reads about 4.2 sigma on pure noise) and
`floor_check()` verifies that floor empirically on a few pairs.

Only numpy is required; the AES tables and the 2^16 pair search are imported
from `flashattack` and are the only external pieces to bring if you lift this
package out of the repo.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

try:                                            # the only coupling to the repo
    from flashattack.aesref import SBOX as _SBOX, SINV as _SINV
    from flashattack.engine import col_attack_scored as _col_attack_scored
except ImportError:                             # pragma: no cover
    raise SystemExit("flashleak needs flashattack.aesref and flashattack.engine "
                     "(two 256-byte tables and the pair search)")

SBOX = np.asarray(_SBOX, np.int64)
SINV = np.asarray(_SINV, np.int64)
IDENTITY = np.arange(256, dtype=np.int64)

#: A peak over 65536 cells reads about this on pure noise. Measured, and
#: re-checkable with `floor_check()`.
OUTPUT_NOISE_FLOOR = 4.2


@dataclass
class TestResult:
    """One statistic plus what the null looks like for it."""
    name: str
    statistic: float
    null_mean: float = 0.0
    null_sd: float = 1.0
    n_used: int = 0
    detail: dict = field(default_factory=dict)

    @property
    def z(self) -> float:
        """How far above the null, in null standard deviations."""
        return (self.statistic - self.null_mean) / max(self.null_sd, 1e-12)

    @property
    def fired(self) -> bool:
        return self.z >= 5.0


def _as_blocks(blocks) -> np.ndarray:
    b = np.asarray(blocks)
    if b.ndim != 2 or b.shape[1] != 16:
        raise ValueError(f"blocks must be (n, 16); got {b.shape}")
    return b.astype(np.int64)


def timing_summary(timing) -> dict:
    """Is the clock moving at all, and by how much?

    `quantum` is the smallest non-zero gap between distinct observed values --
    the resolution actually delivered, which is often coarser than the units
    suggest. A target whose timing takes two values in a quarter of a million
    measurements is constant-time for practical purposes no matter what its
    sigma rounds to.
    """
    t = np.asarray(timing, float)
    t = t[np.isfinite(t)]
    u = np.unique(t)
    gaps = np.diff(u)
    return {
        "n": int(t.size),
        "distinct": int(u.size),
        "sigma": float(t.std()),
        "median": float(np.median(t)) if t.size else float("nan"),
        "iqr": float(np.subtract(*np.percentile(t, [75, 25]))) if t.size else float("nan"),
        "quantum": float(gaps.min()) if gaps.size else 0.0,
        "constant_time": bool(u.size <= 2),
    }


def _validate_modes(t, edges, min_share=0.05, sep=4.0):
    """Keep only the splits that a real transport mode would produce.

    An edge survives when both the clusters it separates hold at least
    `min_share` of the traces and their medians are at least `sep`
    within-cluster sigmas apart. Dropping an edge merges two clusters and
    changes both statistics, so the weakest offender goes first and the
    rest are re-checked, rather than filtering them all in one pass.
    """
    edges = sorted(float(e) for e in edges)
    while edges:
        lab = np.searchsorted(np.array(edges), t)
        groups = [t[lab == m] for m in range(len(edges) + 1)]
        worst, worst_score = None, None
        for i, e in enumerate(edges):
            lo, hi = groups[i], groups[i + 1]
            if lo.size == 0 or hi.size == 0:
                worst, worst_score = i, -1.0
                break
            share = min(lo.size, hi.size) / max(t.size, 1)
            # Robust within-cluster spread. An on-chip cycle count is discrete
            # enough that a cluster can hold ONE value and have a MAD of zero,
            # which would divide into an infinite separation and wave every
            # edge through - exactly the captures this has to get right. Fall
            # back to the pooled spread, so separation is always measured
            # against a scale the data actually has.
            spread = max(_mad(lo), _mad(hi)) or _mad(t) or float(np.std(t))
            if spread <= 0:                      # constant: nothing to split
                worst, worst_score = i, -1.0
                break
            gap = abs(float(np.median(hi)) - float(np.median(lo))) / spread
            # Normalised so the two tests are comparable and the genuinely
            # weakest edge is the one that goes.
            score = min(share / min_share, gap / sep)
            if score >= 1.0:
                continue
            if worst_score is None or score < worst_score:
                worst, worst_score = i, score
        if worst is None:
            break
        edges.pop(worst)
    return edges


def _mad(x):
    """Median absolute deviation, scaled to a Gaussian sigma."""
    if x.size == 0:
        return 0.0
    return float(np.median(np.abs(x - np.median(x))) * 1.4826)


def condition(blocks, timing, outlier_sigma=6.0, sep=4.0, min_mode_share=0.05):
    """Strip the nuisance structure that would otherwise hide everything.

    Raw timings off a real target are rarely a single tight cluster. Two things
    wreck every statistic below, and a black-box assessor has no reason to know
    about either:

    * **Outliers.** An interrupt, a retransmit, a garbage-collection pause. They
      inflate the standard deviation that every margin here is measured in, and
      a handful of them is enough to divide the signal by an order of magnitude.
    * **Discrete modes.** Many transports quantise: a DMA ring that occasionally
      pays for a descriptor sweep, a scheduler tick, a USB frame boundary. The
      result is two or more clusters hundreds of units apart, with the leak
      living *inside* each one. Pooling them measures the gap, not the cipher.

    Measured on this repo's own SNMPv3 capture, whose key is recoverable: raw,
    every test reads zero and the tool calls it clean. Conditioned, the same
    traces light up. That false negative is the reason this function exists.

    Outliers go by a MAD-based cut; modes are found as histogram valleys and
    then validated - each side has to hold `min_mode_share` of the traces and
    the two medians have to be `sep` within-cluster sigmas apart - and each
    surviving cluster is centred on its own median. Returns (blocks, y, info).

    WHAT THIS DOES NOT COVER. The outlier cut runs FIRST and knows nothing
    about modes, so a real mode that is both far out and small is deleted
    before mode-finding ever sees it: a cluster holding 8 % of the traces 30
    sigma away is dropped whole by the 6-MAD cut, and `dropped_outliers` is
    the only trace of it. Balanced modes like the SNMPv3 capture's are safe
    because each one drags the pooled median and MAD toward itself. If you
    are looking at a capture whose `dropped_outliers` is more than a percent
    or two, plot it before believing anything below.
    """
    t = np.asarray(timing, float)
    b = np.asarray(blocks)
    keep = np.isfinite(t)
    t, b = t[keep], b[keep]
    n0 = len(t)

    med = np.median(t)
    mad = np.median(np.abs(t - med)) * 1.4826
    if mad <= 0:
        mad = t.std() or 1.0
    k = np.abs(t - med) <= outlier_sigma * mad
    t, b = t[k], b[k]

    # Find modes by density, not by gap size. A gap-based rule needs a scale,
    # and the only scales available from pooled data - its sd or MAD - are
    # themselves inflated by the very gap being looked for, so a clean bimodal
    # capture reads as unimodal. (That is not hypothetical: this repo's SNMPv3
    # capture has modes ~1480 apart with a within-mode sigma of ~59, and the
    # gap rule merged them.) A histogram valley has no such circularity.
    edges = []
    if t.size > 500:
        lo, hi = t.min(), t.max()
        if hi > lo:
            nb_ = 256
            hist, be = np.histogram(t, bins=nb_, range=(lo, hi))
            thresh = max(hist.max() * 0.10, t.size * 0.002)
            occupied = hist >= thresh
            for i in range(1, nb_):
                if occupied[i - 1] and not occupied[i]:
                    j = i
                    while j < nb_ and not occupied[j]:
                        j += 1
                    if j < nb_:                      # a real valley, not the tail
                        edges.append(float(be[(i + j) // 2]))
            edges = edges[:8]
    # A valley in the histogram is necessary but NOT sufficient. The tails of
    # a perfectly unimodal Gaussian go sparse before they end, so an occupied
    # bin, a few empty ones and another occupied bin all sit inside one mode -
    # and the rule above calls that a valley. Measured on 20 000 samples of
    # clean N(1000, 3) with no cipher anywhere near it: 3 modes, shares 3.0 %
    # / 94.4 % / 2.6 %, which is the body and its own two tails. Each sliver
    # then got its own median subtracted, which drags the tails inward and
    # takes sigma down 16 % for nothing.
    #
    # That is not cosmetic. The thing being measured is a shift in the mean of
    # a subset, so re-centring arbitrary subsets removes signal: on the real
    # 250 000-trace tinyaes vector the splitter found NINE modes (eight
    # slivers of 1-4 % around an 80 % body) and cost 60 % of the output-side
    # statistic, 39.5 down to 14.5 against the same floor.
    #
    # So an edge now has to survive both tests a real transport mode passes
    # and a Gaussian tail does not: each side holds a real share of the data,
    # and the two medians are `sep` within-cluster sigmas apart. The SNMPv3
    # capture this function was written for clears that easily - its modes are
    # ~1480 apart with a within-mode sigma of ~59, so about 25 sigma.
    edges = _validate_modes(t, edges, min_share=min_mode_share, sep=sep)
    lab = np.searchsorted(np.array(edges), t) if edges else np.zeros(len(t), int)
    y = t.astype(float).copy()
    for m in np.unique(lab):
        sel = lab == m
        if sel.sum() > 10:
            y[sel] -= np.median(t[sel])
        else:
            y[sel] -= med
    info = {"dropped_outliers": int(n0 - len(t)), "n": int(len(t)),
            "modes": int(len(edges) + 1),
            "mode_shares": [float((lab == m).mean()) for m in np.unique(lab)],
            "sigma_raw": float(np.asarray(timing, float)[keep].std()),
            "sigma_conditioned": float(y.std())}
    return b, y, info


def data_dependence(blocks, timing, n_shuffle=200, seed=0) -> TestResult:
    """Does the timing depend on the observed bytes at all? Model-free.

    For every byte position and value, the mean timing of the traces carrying it.
    Under the null those 16 x 256 means are exchangeable, so the spread of the
    table is the statistic and shuffling the timings gives its null distribution
    directly. This catches *any* byte-value-dependent timing - a table lookup, a
    data-dependent branch, an early-exit memcmp - without assuming a cipher.

    It does NOT catch leakage that only shows up in a *combination* of bytes,
    which is exactly what cache-collision leakage is. A flat result here with a
    live pair test below is the normal signature of this channel, not a
    contradiction.
    """
    b = _as_blocks(blocks)
    y = np.asarray(timing, float)
    y = y - y.mean()
    n = len(y)

    def stat(yy):
        tot = 0.0
        for i in range(16):
            s = np.bincount(b[:, i], weights=yy, minlength=256)
            c = np.bincount(b[:, i], minlength=256).astype(float)
            m = c > 0
            tot += float(np.sum(c[m] * (s[m] / c[m]) ** 2))
        return tot / 16.0

    obs = stat(y)
    rng = np.random.default_rng(seed)
    null = np.array([stat(rng.permutation(y)) for _ in range(n_shuffle)])
    per_byte = {}
    for i in range(16):
        s = np.bincount(b[:, i], weights=y, minlength=256)
        c = np.bincount(b[:, i], minlength=256).astype(float)
        m = c > 0
        per_byte[i] = float(np.sum(c[m] * (s[m] / c[m]) ** 2) / max(m.sum(), 1))
    return TestResult("data_dependence", obs, float(null.mean()), float(null.std()),
                      n, {"per_byte": per_byte})


def pair_input_test(blocks, timing, line_shift=2, n_shuffle=64, seed=0) -> TestResult:
    """Treat the observed block as the cipher's INPUT.

    If lookups are indexed by `block ^ key`, two positions land in the same line
    exactly when `topbits(B[a] ^ B[b]) == topbits(k[a] ^ k[b])`. The right-hand
    side is fixed and unknown, so bucket by the left-hand side and look for one
    bucket that is anomalously fast. No key, no search.

    Statistic: the deepest standardised bucket dip, pooled over all 120 pairs.
    Null by shuffling, because the minimum over many buckets has an
    extreme-value distribution that no textbook formula covers.

    The dip alone is **not specific** - output-side leakage inflates it too,
    because along a fixed-XOR diagonal the S-box does not spread collisions
    evenly. `detail["concentration"]` is what separates them: input-side leakage
    is a function of `B[a] ^ B[b]` alone, so exactly one bucket is fast and it
    stands well clear of the rest; anything else smears across buckets. Use the
    concentration, not the dip, to decide which side you are on.
    """
    b = _as_blocks(blocks)
    y = np.asarray(timing, float)
    y = y - y.mean()
    n = len(y)
    nb = 1 << (8 - line_shift)
    hp = b >> line_shift
    pairs = [(a, c) for a in range(16) for c in range(a + 1, 16)]
    vs = [(hp[:, a] ^ hp[:, c]).astype(np.int64) for a, c in pairs]
    counts = [np.bincount(v, minlength=nb).astype(float) for v in vs]

    def stat(yy, per_pair=None, fast_counts=None):
        ysum = yy.sum()
        sd = yy.std() or 1.0
        tot = 0.0
        for k, v in enumerate(vs):
            c = counts[k]
            s = np.bincount(v, weights=yy, minlength=nb)
            m = c > 50
            if not m.any():
                continue
            dip = s[m] / c[m] - (ysum - s[m]) / np.maximum(n - c[m], 1)
            se = sd * np.sqrt(1.0 / c[m] + 1.0 / np.maximum(n - c[m], 1))
            z = dip / se
            worst = float(z.min())
            tot += worst
            if per_pair is not None:
                per_pair[pairs[k]] = worst
            if fast_counts is not None:
                # how many buckets sit in the fast cluster, not just the deepest.
                # At the true line width exactly one bucket is the colliding one;
                # assume a finer width and the same dip splits across 2^(L-shift)
                # of them. That count is what identifies L without a key.
                fast_counts.append(int((z < -3.0).sum()))
                # ...and how far the deepest bucket stands clear of the next.
                # This is what makes the test SPECIFIC. Input-side leakage is a
                # function of B[a]^B[b] alone, so exactly one bucket is fast and
                # the gap is large. Output-side leakage is not a function of the
                # XOR, so bucketing this way smears it and the gap collapses.
                # Measured on simulated targets: 15.9 for input-side at its true
                # width against 0.34-0.49 for output-side, no channel, and
                # input-side read at the wrong width.
                zs = np.sort(z)
                if zs.size >= 4:
                    c = float((zs[1] - zs[0]) / (zs[1:].std() + 1e-9))
                    conc.append(c)
                    conc_by_off.setdefault(
                        min((pairs[k][1] - pairs[k][0]) % 16,
                            (pairs[k][0] - pairs[k][1]) % 16), []).append(c)
        return tot / len(vs)

    per_pair: dict = {}
    fast: list = []
    conc: list = []
    conc_by_off: dict = {}
    obs = stat(y, per_pair, fast)
    rng = np.random.default_rng(seed)
    null = np.array([stat(rng.permutation(y)) for _ in range(n_shuffle)])
    nf = float(np.median(fast)) if fast else 0.0
    # more negative = stronger, so flip the sign to keep "bigger z = more leak"
    return TestResult("pair_input", -obs, -float(null.mean()), float(null.std()),
                      n, {"per_pair": per_pair, "line_shift": line_shift,
                          "fast_buckets": nf,
                          # Two statistics, because one does not do the job.
                          # "concentration" is the median over all 120 pairs. It
                          # identifies an input side cleanly when every pair can
                          # collide, and reads ~0 when the layout PARTITIONS the
                          # channel - in a 4-table implementation only 24 pairs
                          # can collide and the other 96 drown them. Hold-out
                          # validation caught exactly that: a genuinely
                          # input-side mbedTLS 4-table capture scored 0.56.
                          # "concentration_family" is the best offset family,
                          # which rescues the partitioned case - but it is
                          # raised by partitioning on EITHER side, so it cannot
                          # be used alone. See hypotheses.py for how they combine.
                          "concentration": float(np.median(conc)) if conc else 0.0,
                          "concentration_family": (max(float(np.median(v))
                                                       for v in conc_by_off.values())
                                                   if conc_by_off else 0.0),
                          "concentration_by_offset": {k: float(np.median(v))
                                                      for k, v in sorted(conc_by_off.items())},
                          "implied_shift": (line_shift + np.log2(nf)) if nf >= 1 else None})


def pair_output_test(blocks, timing, table="enc", line_shift=4,
                     pairs=None, floor=OUTPUT_NOISE_FLOOR) -> TestResult:
    """Treat the observed block as the OUTPUT of a final round with no MixColumns.

    Then each output byte came from one table lookup whose index is
    `tbl[B[j] ^ k[j]]`, and a 2^16 search over (k[a], k[b]) finds the guess whose
    predicted collision set is fastest. `table="enc"` uses the inverse S-box (the
    block is an encryption's ciphertext, or a keystream, or either XOR any fixed
    unknown mask - the mask is absorbed into the recovered key bytes, so it does
    not affect detection). `table="dec"` uses the forward S-box (the block is a
    decryption's plaintext).

    This is the expensive one: about 0.4 s per pair. `pairs` restricts it.
    """
    b = _as_blocks(blocks)
    y = np.asarray(timing, float)
    y = y - y.mean()
    tbl = {"enc": SINV, "dec": SBOX, "none": IDENTITY}[table]
    if pairs is None:
        pairs = [(a, c) for a in range(16) for c in range(a + 1, 16)]
    per_pair = {}
    for a, c in pairs:
        _, _, margin = _col_attack_scored(b[:, a], b[:, c], y, tbl, line_shift)
        per_pair[(a, c)] = float(margin)
    vals = np.array(list(per_pair.values()))
    # The statistic is the MEAN peak over the tested pairs, not the max. A max
    # depends on how many pairs were tested, so comparing one to a floor
    # estimated from a different number of pairs is not like-for-like - that
    # mismatch made the floor look like it was drifting between 4.34 and 4.52
    # run to run. The mean is stable and pairs with a shuffled mean directly.
    return TestResult(f"pair_output_{table}", float(vals.mean()), floor, 1.0,
                      len(y), {"per_pair": per_pair, "line_shift": line_shift,
                               "max": float(vals.max()), "n_pairs": len(vals),
                               "above_floor": int((vals > floor + 1.0).sum())})


#: Row widths the output-side scan tries, as log2(entries per flash row).
#: 3 is a byte S-box in an 8-byte row, 4 the same in a 16-byte row, 2 a
#: 4-byte word table in a 16-byte row, 1 a word table in an 8-byte one.
OUTPUT_SHIFTS = (1, 2, 3, 4)


def output_shift_scan(blocks, timing, shifts=OUTPUT_SHIFTS, n_pairs=8,
                      n_floor=8, max_traces=None, seed=0):
    """Which row width does the output-side collision live at?

    Nothing on the chip reports it and it is not derivable from the data
    without trying, so it gets tried. This was a constant 2 until it was
    measured: the simulated targets in `target.py` model a 16-byte row of
    1-byte entries, which is shift 4, and scoring them at 2 took a result
    that fires at 7.9 and 56.4 down to 0.7 and 7.0 against the same floor.
    Guessing the row width wrong returns a clean null that reads exactly
    like a target which does not leak - the same trap `flashattack`
    ladders its geometry to avoid.

    Cheap in PAIRS, not in traces. This only has to rank the widths, and a
    handful of pairs does that - but it needs all the traces, which was
    measured the embarrassing way after an earlier version capped them at
    50 000. On the 250 000-trace tinyaes vector, where the full 12-pair test
    says 1:+6.1 2:+21.7 3:+24.4 4:+39.5 and the answer is plainly 4:

        4 pairs,  50 000 traces  -> 3     8 pairs,  50 000 -> 3
       12 pairs,  50 000 traces  -> 1     4 pairs, 250 000 -> 4
                                          8 pairs, 250 000 -> 4

    More pairs did not rescue the capped version and none of the three
    capped budgets got it right. `max_traces` is therefore None by default;
    pass a number only if you know your capture is strong enough.

    Returns (best_shift, scan) where scan maps each shift to its excess
    over its own shuffled floor. Each shift is compared against a floor
    measured at that same shift, since the floor is mildly width-dependent
    and comparing across widths otherwise reads as signal.

    WHAT THIS DOES NOT COVER: picking the maximum over several widths
    inflates the statistic under the null, so the caller has to hold a
    higher bar than it would for one fixed width - see
    `hypotheses.OUTPUT_FIRES`. It also assumes the leak is at ONE width;
    a target reading two differently shaped tables in its last round
    would be ranked by whichever is louder.
    """
    b = _as_blocks(blocks)
    y = np.asarray(timing, float)
    if max_traces is not None and len(y) > max_traces:
        b, y = b[:max_traces], y[:max_traces]
    pairs = [(0, 4), (1, 5), (2, 6), (3, 7)][:max(n_pairs, 1)]
    scan = {}
    for s in shifts:
        best = -np.inf
        for table in ("enc", "dec"):
            r = pair_output_test(b, y, table, s, pairs=pairs)
            fl = floor_check(b, y, table, s, n_pairs=n_floor, seed=seed)
            se = (fl["se"] or 0.1) or 0.1
            best = max(best, (r.statistic - fl["mean"]) / se)
        scan[s] = float(best)
    return max(scan, key=scan.get), scan


def floor_check(blocks, timing, table="enc", line_shift=4, n_pairs=12, seed=0) -> dict:
    """Verify the output-side noise floor on THIS data instead of trusting 4.2.

    Shuffles the timings so any real structure is destroyed, then measures the
    peak a few pairs report. If the shuffled peaks do not sit near
    OUTPUT_NOISE_FLOOR, the analytic floor does not apply here and the output
    test's z should be read against the returned mean instead.
    """
    b = _as_blocks(blocks)
    y = np.asarray(timing, float)
    rng = np.random.default_rng(seed)
    ys = rng.permutation(y - y.mean())
    tbl = {"enc": SINV, "dec": SBOX, "none": IDENTITY}[table]
    allp = [(a, c) for a in range(16) for c in range(a + 1, 16)]
    idx = rng.choice(len(allp), size=min(n_pairs, len(allp)), replace=False)
    peaks = [float(_col_attack_scored(b[:, allp[i][0]], b[:, allp[i][1]],
                                      ys, tbl, line_shift)[2]) for i in idx]
    sd = float(np.std(peaks, ddof=1)) if len(peaks) > 1 else 1.0
    return {"peaks": peaks, "mean": float(np.mean(peaks)), "sd": sd,
            "se": sd / max(np.sqrt(len(peaks)), 1.0), "n": len(peaks),
            "assumed": OUTPUT_NOISE_FLOOR}


def offset_profile(per_pair: dict) -> dict:
    """Fold a per-pair statistic onto the byte-offset it spans.

    Which offsets carry signal is a fingerprint of the table layout, because two
    lookups can only collide if they are in the same table:

      every offset        one shared table (a single S-box, or one rotated
                          T-table) - the fully exposed case
      offsets 0 mod 4     four separate tables indexed by row, e.g. mbedTLS's
                          RT0..RT3; the channel is partitioned, not suppressed
      one offset family   an access order that only lets that family meet, e.g.
                          TinyCrypt's (i, i+3)
    """
    by: dict = {}
    for (a, b), v in per_pair.items():
        d = min((b - a) % 16, (a - b) % 16)
        by.setdefault(d, []).append(v)
    return {d: float(np.mean(v)) for d, v in sorted(by.items())}
