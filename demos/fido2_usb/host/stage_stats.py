"""Is a ladder stage's argmin a measurement or the max of 64 noisy draws?

A stage sweeps 64 delta classes and takes the class with the lowest mean poll count. That
statistic has no null attached: with 64 classes the *minimum* is low by construction, so
"margin over runner-up" cannot be read directly. This supplies the null by SHUFFLING the delta
labels within the same capture, which preserves every property of the data except the
association between class and observation, and recomputes the margin each time.

Three things it reports, and each answers a different question.

* **`p`** -- the fraction of label shuffles reaching the observed margin. This is the only
  number that says whether the argmin is distinguishable from noise. On the Dongle it separated
  a gated stage (`p = 0.010`) from an ungated one (`p = 0.590`) whose raw dip was LARGER.
* **per-class mean `ftrem` spread** -- whether the classes were measured at the same USB frame
  phase. §5j established that the reply time depends on frame phase, so classes at different
  average phases can differ for a reason that has nothing to do with a collision. Ungated this
  read 1 330 clocks and gated 25, which is what explained the two p-values above. **A stage
  with a large spread is confounded whatever its p-value.**
* **the argmin in each phase half** -- an internal replication that costs nothing. A real dip
  should survive splitting the capture; the ungated stage's argmin moved (120 against 132)
  while the gated one did not (244 twice).

What it cannot tell you: whether the argmin is the CORRECT class. A blind run has no key to
check against, so significance and correctness are different questions and only a recovery
settles the second -- this repository's own rule that a statistic is not a channel.

    python demos/fido2_usb/host/stage_stats.py demos/fido2_usb/host/ladder_r4-seed-2_gated.npz
    python demos/fido2_usb/host/stage_stats.py demos/fido2_usb/host/ladder_*.npz --shuffles 800
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np


def analyse(path: Path, shuffles: int = 400, seed: int = 20260928) -> dict:
    d = np.load(path)
    a = d["rows"]
    deltas = np.asarray(d["deltas"])
    polls = a[:, 1].astype(float)
    lab = a[:, 0].astype(int)
    # The phase column only exists for captures taken after 2026-09-28; older ones cannot be
    # audited for the confound at all, which is itself worth saying out loud rather than
    # silently reporting zero.
    ph = a[:, 2].astype(float) if a.shape[1] >= 3 else None
    rng = np.random.default_rng(seed)

    def margin(labels: np.ndarray):
        means = {int(dd): polls[labels == dd].mean()
                 for dd in deltas if (labels == dd).sum() > 2}
        items = sorted(means.items(), key=lambda kv: kv[1])
        n_bar = np.mean([(labels == dd).sum() for dd in deltas])
        se = polls.std(ddof=1) / np.sqrt(n_bar)
        dip = items[0][1] - np.mean([v for _, v in items[1:]])
        return items[0][0], (items[1][1] - items[0][1]) / se, dip

    arg, marg, dip = margin(lab)
    null = np.array([margin(rng.permutation(lab))[1] for _ in range(shuffles)])
    out = {"file": path.name, "n": int(len(polls)), "argmin": int(arg),
           "margin": float(marg), "dip": float(dip),
           "p": float(np.mean(null >= marg)),
           "null_mean": float(null.mean()), "null_p95": float(np.percentile(null, 95)),
           "has_phase": ph is not None}
    if ph is not None:
        per_class = np.array([ph[lab == dd].mean() for dd in deltas
                              if (lab == dd).sum() > 2])
        out["phase_sd"] = float(ph.std())
        out["class_phase_spread"] = float(per_class.max() - per_class.min())
        out["corr_polls_phase"] = float(np.corrcoef(polls, ph)[0, 1])
        med = np.median(ph)
        halves = []
        for m in (ph <= med, ph > med):
            means = {int(dd): polls[m & (lab == dd)].mean()
                     for dd in deltas if (m & (lab == dd)).sum() > 2}
            halves.append(int(sorted(means.items(), key=lambda kv: kv[1])[0][0])
                          if means else -1)
        out["half_argmins"] = halves
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("npz", nargs="+")
    ap.add_argument("--shuffles", type=int, default=400)
    ap.add_argument("--expect-argmin", type=int, default=None,
                    help="a previous run's argmin for this stage. Given, the exit code is 0 "
                         "only if the argmin matches AND p < --alpha, which is how an "
                         "unattended driver decides whether a stage reproduced.")
    ap.add_argument("--alpha", type=float, default=0.05)
    ap.add_argument("--max-class-phase-spread", type=float, default=200.0,
                    help="reject a capture whose classes were measured at different frame "
                         "phases by more than this many PHY clocks. Gated runs sit near 25 "
                         "and the ungated one read 1330, so 200 separates them with room.")
    args = ap.parse_args()

    ok = True
    for pat in args.npz:
        p = Path(pat)
        if not p.exists():
            print(f"{pat}: missing")
            ok = False
            continue
        r = analyse(p, args.shuffles)
        print(f"\n{r['file']}  n={r['n']}")
        print(f"  argmin {r['argmin']} (0x{r['argmin']:02x})   margin {r['margin']:+.2f} sigma"
              f"   dip {r['dip']:+.3f} polls")
        print(f"  p = {r['p']:.3f}   (null mean {r['null_mean']:+.2f}, "
              f"95th {r['null_p95']:+.2f}, {args.shuffles} shuffles)")
        if r["has_phase"]:
            print(f"  phase: sd {r['phase_sd']:.0f} clocks, per-class spread "
                  f"{r['class_phase_spread']:.0f} clocks, corr(polls,ftrem) "
                  f"{r['corr_polls_phase']:+.3f}")
            print(f"  argmin per phase half: {r['half_argmins']}")
        else:
            print("  no phase column: taken before 2026-09-28, so it CANNOT be audited for "
                  "the\n  frame-phase confound -- treat its margin as unverified rather than "
                  "as clean.")
        if args.expect_argmin is not None:
            reasons = []
            if r["argmin"] != args.expect_argmin:
                reasons.append(f"argmin {r['argmin']} != expected {args.expect_argmin}")
            if r["p"] >= args.alpha:
                reasons.append(f"p {r['p']:.3f} >= alpha {args.alpha}")
            if r["has_phase"] and r["class_phase_spread"] > args.max_class_phase_spread:
                reasons.append(f"class phase spread {r['class_phase_spread']:.0f} > "
                               f"{args.max_class_phase_spread:.0f} clocks: the gate did not "
                               f"hold, so this capture is confounded")
            if reasons:
                print("  DID NOT REPRODUCE: " + "; ".join(reasons))
                ok = False
            else:
                print(f"  REPRODUCED: argmin {r['argmin']} again, p {r['p']:.3f}, and the "
                      f"classes are phase-balanced.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
