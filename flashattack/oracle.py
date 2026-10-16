"""Turning a raw remote round-trip time into a usable timing oracle.

**This is the surviving copy of what was `demo/oscore/oracle.py`.** It moved
into the package because three things outside that demo had come to depend on
it - `demo/snmpv3/analyse.py`, `demo/tls_https/analyse.py` and most of
`research/round2/` - and they reached it with
`sys.path.insert(0, "demo/oscore")`, which is the repository's own "a one-off
that grows a third caller graduates into the toolkit" rule (CLAUDE.md,
*Conventions*), met and unnoticed. `demo/oscore/oracle.py` is now a shim over
this.

It is NOT `demo/knx_secure/oracle.py`, which shares the filename and nothing
else: that one is a KNX triage instrument on a socket and a `perf_counter_ns`,
and it stays where it is.

Related but different: `stats.py` holds the timing preprocessing that needs no
model of the transport - trimming, drift detrending, a min-filter over repeats.
This module is for a *network* oracle specifically, where the nuisance has
structure worth fitting.

WHAT IT DOES NOT COVER. Every number below was measured on ST's NO_SYS lwIP
port on an F4 and an F7 victim timed by an F7 attacker. The METHOD - fit the
discrete transport artefact, subtract it per mode, then cut outliers on a
robust scale - is general; the mode count, the widths and the parity accident
are that rig's. On any other transport, run `stationary_segments` first and
read `describe()` before trusting a conditioned capture.

The victim's request-to-response turnaround, measured from the attacker's
Ethernet interrupts, carries the AES leak but arrives with two additive nuisance
terms that have nothing to do with the key:

1. **A large multi-mode offset (~1433 attacker cycles, 6.6 us, one frame time).**
   ST's NO_SYS lwIP port only calls ``HAL_ETH_ReleaseTxPacket()`` when
   ``HAL_ETH_Transmit_IT()`` reports the transmit ring full, so one send in every
   ``ETH_TX_DESC_CNT`` pays for a descriptor sweep and a frame-time of waiting.
   Measured causally: rebuilding the victim with ``ETH_TX_DESC_CNT=8`` moved the
   slow share from 1-in-4 to 1-in-8 and its period from 4 to 8. It happens
   *after* the crypto, so the victim's own cycle counter never sees it.

2. **Rare large outliers**, from the victim's periodic console print and its
   100 ms PHY link poll landing inside an exchange.

Both are independent of the AES output block, so removing them is sound, and the
modes are ~15 sigma apart while the leak is a few hundredths of a sigma - the
chance of assigning a trace to the wrong mode *because of* its AES timing is
around 1e-13, so the label carries no information about the key.

Methods:

``mode``  the default. Fit the two modes (EM, independent widths), subtract
          each one's mean, keep everything.
``fast``  keep only the largest (fastest) mode. A subset chosen by a threshold
          seven sigma away from anything the signal can move, so it is an
          independent check that ``mode`` is not manufacturing the answer.
``norm``  as ``mode``, then divide each mode by its own sigma, so a plain mean
          over traces of unequal noise is the right estimator.
``even``  keep only even-numbered exchanges. Where the artefact happens to align
          with packet parity this is a selector that never looks at the timing
          at all. The alignment is an accident of how the boards came up, so
          ``describe()`` reports whether it held; when it did not, this method
          is useless and says so.
``raw``   no conditioning, for comparison.
"""
from __future__ import annotations

import numpy as np


def _robust_sigma(v, p=0.25):
    """Within-mode spread, estimated from the SHORTEST interval holding a
    fraction `p` of the data.

    A MAD would do if the distribution were unimodal, but it is not: when the
    two Tx-descriptor modes are close to equal in size the median falls in the
    gap between them and the MAD reports half the gap - roughly seven times the
    real spread, which then hides the gap it was meant to find. The shortest
    quarter always lies inside one mode, so this estimate stays between 1.0 and
    about 2.1 times the true sigma for every split from 50/50 to unimodal.
    """
    v = np.sort(np.asarray(v, float))
    n = v.size
    h = max(int(round(p * n)), 2)
    if n <= h:
        return max(float(v.std()), 1.0)
    width = float(np.min(v[h:] - v[:n - h]))
    # width of the shortest central interval of a normal holding p
    from math import erf, sqrt
    z = 0.0
    lo, hi = 0.0, 10.0
    for _ in range(60):                       # invert the normal CDF
        z = 0.5 * (lo + hi)
        if erf(z / sqrt(2.0)) < p:
            lo = z
        else:
            hi = z
    return max(width / (2.0 * z), 1.0)


def find_modes(t, lo_q=0.2, hi_q=99.8, min_sep=3.0, min_share=0.02, iters=100):
    """Fit the timing as one or two Gaussians, by EM, with **independent** widths.

    Two earlier versions of this were wrong in instructive ways. A density-gap
    search worked on the F4 victim, where the modes are 16 sigma apart, and
    reported a single mode on the F7, where the same 1433-cycle offset sits on a
    distribution three times wider. Replacing it with an equal-variance EM fixed
    that but still collapsed on some F7 captures, because the F7's two modes are
    not the same width at all - the fast one has sigma ~184 and the slow one
    ~536. Tying them forces a pooled sigma large enough to make the separation
    look insignificant, and the fit gives up.

    Returns (edges, centres); `np.searchsorted(edges, t)` labels any value,
    including the outliers excluded from the fit. `mode_sigmas` is exposed
    through `condition()` because the widths differ enough to matter.
    """
    t = np.asarray(t, float)
    lo, hi = np.percentile(t, [lo_q, hi_q])
    v = t[(t >= lo) & (t <= hi)]
    if v.size < 200:
        return np.array([]), np.array([t.mean()]), np.array([_robust_sigma(t)])

    s0 = _robust_sigma(v)
    mu = np.percentile(v, [25.0, 90.0]).astype(float)
    sig = np.array([s0, s0], float)
    w = np.array([0.7, 0.3])
    for _ in range(iters):
        p = w[None, :] * np.exp(-0.5 * ((v[:, None] - mu[None, :]) / sig[None, :]) ** 2) \
            / sig[None, :]
        s = p.sum(axis=1)
        s[s == 0] = 1e-300
        r = p / s[:, None]
        nk = r.sum(axis=0)
        if np.min(nk) < 2.0:
            break
        new_mu = (r * v[:, None]).sum(axis=0) / nk
        new_sig = np.sqrt((r * (v[:, None] - new_mu[None, :]) ** 2).sum(axis=0) / nk)
        new_sig = np.maximum(new_sig, 1e-9)
        done = np.max(np.abs(new_mu - mu)) < 1e-3
        mu, sig, w = new_mu, new_sig, nk / v.size
        if done:
            break

    order = np.argsort(mu)
    mu, sig, w = mu[order], sig[order], w[order]
    # separation measured against the tighter mode, which is the one the attack
    # will actually use
    sep = float(abs(mu[1] - mu[0]) / max(sig.min(), 1e-9))
    if sep < min_sep or np.min(w) < min_share:
        return np.array([]), np.array([v.mean()]), np.array([s0])
    # threshold where the two fitted densities cross
    edge = (mu[0] * sig[1] + mu[1] * sig[0]) / (sig[0] + sig[1])
    return np.array([edge]), mu, sig


def condition(t, method="mode", index=None, outlier_sigma=6.0, fast_sigma=4.0):
    """Return (y, keep, info): nuisance-removed timing, which traces survive,
    and what was removed. `y` is centred; only differences matter to the attack.
    """
    t = np.asarray(t, float)
    n = t.size
    if index is None:
        index = np.arange(n)
    info = {"method": method, "n_in": n}

    edges, centres, sigmas = find_modes(t)
    lab = np.searchsorted(edges, t) if edges.size else np.zeros(n, np.int64)
    info["n_modes"] = int(centres.size)
    info["centres"] = [float(c) for c in centres]
    info["mode_sigmas"] = [float(x) for x in sigmas]
    if centres.size > 1:
        info["separation"] = float(np.min(np.diff(centres)) / max(sigmas.min(), 1e-9))
        info["mode_shares"] = [float((lab == k).mean()) for k in range(centres.size)]
    else:
        info["separation"] = None
        info["mode_shares"] = [1.0]

    keep = np.ones(n, bool)
    if method == "even":
        keep &= (index % 2 == 0)
    elif method == "fast":
        # A window around the fast mode rather than "everything below the edge".
        # Where the two modes have very different widths the fitted edge sits
        # only ~2 sigma out and throws away good traces; where they are far apart
        # (the F4) a 4-sigma window and the edge select the same set. Measured on
        # the F7 capture, the pooled signal is flat from 3 to 5 sigma (-7.8,
        # -8.0, -7.8) and collapses at 8 sigma once the slow mode is admitted --
        # so the cut is in a plateau, not tuned to a peak.
        keep &= (lab == 0) | (np.abs(t - centres[0]) <= fast_sigma * sigmas[0])
        keep &= t <= centres[0] + fast_sigma * sigmas[0]

    y = t.copy()
    if method == "fast":
        # One window, one offset. Splitting it by the fitted mode label and
        # centring each half separately would be removing a difference that is
        # not physically there - and it measurably flattens the signal
        # (pooled z -8.0 -> -6.6 on the F7 capture).
        y = y - np.median(t[keep])
    elif method != "raw":
        for k in range(centres.size):
            m = lab == k
            sel = m & keep
            if sel.sum() > 10:
                # median, not mean: the outliers assigned to this mode would
                # otherwise drag the offset by hundreds of cycles
                y[m] -= np.median(t[sel])
            elif m.any():
                y[m] -= centres[k]
    if method == "norm" and centres.size > 1:
        # Inverse-variance weighting. The collision dip is the same number of
        # cycles in both modes, but one mode is several times wider, so treating
        # their traces alike throws away information. Dividing each mode by its
        # own sigma leaves every trace with unit noise, after which a plain mean
        # - which is what the recovery takes - is the right estimator.
        ref = float(sigmas.min())
        for k in range(centres.size):
            m = lab == k
            if m.any():
                y[m] *= ref / max(sigmas[k], 1e-9)

    # Drop the housekeeping outliers, now that the mode offsets are gone. The
    # cut has to use a robust scale or the outliers set their own threshold.
    y = y - np.median(y[keep])
    s = _robust_sigma(y[keep])
    keep &= np.abs(y) <= outlier_sigma * s
    y = y - y[keep].mean()

    if method == "even" and centres.size > 1:
        # Did the artefact actually align with packet parity in this run?
        share = float((lab[index % 2 == 0] > 0).mean())
        info["even_slow_share"] = share
        info["even_aligned"] = bool(share < 0.05)

    info["n_out"] = int(keep.sum())
    info["std"] = float(y[keep].std())
    return y, keep, info


def describe(info):
    bits = [f"{info['method']}: {info['n_out']}/{info['n_in']} traces",
            f"std={info['std']:.1f}"]
    if info.get("n_modes"):
        bits.append(f"{info['n_modes']} modes")
    if info.get("separation"):
        bits.append(f"sep={info['separation']:.1f} sigma")
    if info.get("mode_shares") and len(info["mode_shares"]) > 1:
        bits.append("shares=" + "/".join(f"{s:.2f}" for s in info["mode_shares"]))
        bits.append("mode sigma=" + "/".join(f"{s:.0f}" for s in info["mode_sigmas"]))
    if info.get("runs", 1) > 1:
        bits.append(f"{info['runs']} runs, conditioned separately")
    if "even_aligned" in info:
        bits.append("parity-aligned" if info["even_aligned"]
                    else f"PARITY NOT ALIGNED (slow share {info['even_slow_share']:.2f})")
    return "  ".join(bits)


def stationary_segments(t, chunks=10, tol=6.0):
    """Split a capture where its timing baseline shifts. -> (segments, report).

    `_check_same_regime` in hil_oscore refuses to pool two *captures* the boards
    were in different states for. The same thing happens **inside** one capture
    and is easier to miss, because there is only one file and it looks uniform.

    Measured on the SNMPv3 run: the first ~30 000 of 250 000 exchanges are 1730
    cycles (8.0 us) faster than the rest, in both timing channels and in both
    victim builds, so it is real round-trip time and not a measurement
    artefact. Conditioning is what suffers. A window entirely inside either
    regime fits cleanly (sigma 59-64); one that *straddles* the step has to fit
    a mode spanning both, sigma goes to 690, and the signal is gone - pooled z
    -0.09 against -4 to -7 for its neighbours. That single bad chunk is why the
    first 100 000 exchanges of that capture recover nothing while a clean 65 000
    recovers the key.

    So the rule is not "drop the start", it is "do not let one mode fit straddle
    a level shift". Each returned segment is safe to condition on its own.

    tol is in units of the within-chunk spread, so it does not need tuning to a
    particular victim's absolute round-trip time.
    """
    t = np.asarray(t, float)
    n = t.size
    if n < chunks * 100:
        return [(0, n)], "capture too short to check"
    edges = np.linspace(0, n, chunks + 1).astype(int)
    med = np.array([np.median(t[a:b]) for a, b in zip(edges[:-1], edges[1:])])
    # Robust within-chunk scale: the typical chunk-to-chunk wobble, not the
    # raw spread, which the shift itself would inflate.
    step = np.abs(np.diff(med))
    scale = max(float(np.median(step)), 1e-9)
    cuts = [i + 1 for i, s in enumerate(step) if s > tol * scale]
    segs, prev = [], 0
    for c in cuts:
        segs.append((prev, int(edges[c])))
        prev = int(edges[c])
    segs.append((prev, n))
    if len(segs) == 1:
        return segs, (f"stationary: {chunks} chunk medians within "
                      f"{step.max() / scale:.1f}x the typical wobble")
    lines = [f"NOT stationary: {len(segs)} regimes, "
             f"conditioning must not straddle them"]
    for a, b in segs:
        lines.append(f"  [{a}:{b}] median {np.median(t[a:b]):.0f}")
    return segs, "\n".join(lines)
