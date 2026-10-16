"""Rendering an Assessment for a human who has to decide what to do next."""
from __future__ import annotations

import json


def _bar(z, width=24, lo=0.0, hi=30.0):
    if z != z:
        return " " * width
    frac = max(0.0, min(1.0, (z - lo) / (hi - lo)))
    n = int(round(frac * width))
    return "#" * n + "." * (width - n)


def render(a, verbose=False) -> str:
    L = []
    t = a.timing
    L.append("=" * 72)
    L.append("FLASHLEAK ASSESSMENT")
    L.append("=" * 72)
    L.append("")
    L.append(f"  traces            {t['n']:,}")
    L.append(f"  distinct timings  {t['distinct']:,}"
             + ("   <-- constant time" if t["constant_time"] else ""))
    L.append(f"  median / sigma    {t['median']:.1f} / {t['sigma']:.3f}")
    L.append(f"  resolution        {t['quantum']:g} (smallest gap between "
             f"observed values)")
    L.append("")

    if a.tests:
        L.append("-" * 72)
        L.append("TESTS                              statistic   vs null")
        L.append("-" * 72)
        for name in ("data_dependence", "pair_input"):
            r = a.tests.get(name)
            if r is None:
                continue
            L.append(f"  {name:<28} {r.statistic:>10.3f}   z={r.z:+7.1f}  "
                     f"{_bar(r.z)}")
        for name in ("pair_output_enc", "pair_output_dec"):
            r = a.tests.get(name)
            if r is None:
                continue
            L.append(f"  {name:<28} {r.statistic:>10.3f}   floor "
                     f"{r.null_mean:.1f}, excess {r.statistic - r.null_mean:+.2f}")
        g = a.tests.get("granularity")
        if g:
            L.append("  granularity sweep            "
                     + "  ".join(f"{1<<s}B:z={r.z:+.1f}" for s, r in g.items()))
        fl = a.tests.get("floor_check")
        if fl:
            L.append(f"  shuffled-null floor          {fl['mean']:.2f} "
                     f"(assumed {fl['assumed']})")
        prof = a.tests.get("offset_profile")
        if prof:
            L.append("  offset profile               "
                     + "  ".join(f"{d}:{v:+.2f}" for d, v in prof.items()))
        L.append("")

    L.append("-" * 72)
    L.append("FINDINGS")
    L.append("-" * 72)
    if not a.findings:
        L.append("  (none)")
    for f in a.findings:
        L.append(f"  {f.question}")
        L.append(f"      {f.answer}   [{f.confidence}]")
        L.append(f"      {f.evidence}")
    L.append("")

    if a.notes:
        L.append("-" * 72)
        L.append("READ THIS BEFORE ACTING ON THE ABOVE")
        L.append("-" * 72)
        for n in a.notes:
            L.append("  * " + _wrap(n, 68, "    "))
        L.append("")
    return "\n".join(L)


def _wrap(s, width, indent):
    out, line = [], ""
    for w in s.split():
        if len(line) + len(w) + 1 > width:
            out.append(line); line = w
        else:
            line = (line + " " + w).strip()
    out.append(line)
    return ("\n" + indent).join(out)


def to_json(a) -> str:
    def conv(r):
        if hasattr(r, "statistic"):
            return {"statistic": r.statistic, "z": r.z, "null_mean": r.null_mean,
                    "null_sd": r.null_sd, "n": r.n_used, "fired": r.fired}
        if isinstance(r, dict):
            return {str(k): conv(v) for k, v in r.items()}
        return r
    return json.dumps({
        "timing": a.timing,
        "tests": {k: conv(v) for k, v in a.tests.items()
                  if k != "granularity" or True},
        "findings": [{"question": f.question, "answer": f.answer,
                      "confidence": f.confidence, "evidence": f.evidence}
                     for f in a.findings],
        "notes": a.notes,
    }, indent=2, default=str)
