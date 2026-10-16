"""flashmap.report - render a `Structure` as a measured datasheet.

Every line of the summary is a claim; every claim can be expanded into the
measurements that produced it.  An `unknown` is printed as prominently as a
value, because "the data does not support this" is the result the five bespoke
probes this tool replaces had no way to express.
"""
from __future__ import annotations

import json
from typing import Any, List, Optional

from .infer import Structure, _Unknown

_CONF_MARK = {"high": "***", "medium": "** ", "low": "*  ", "none": "   "}


def _fmt_value(name: str, v: Any) -> str:
    if isinstance(v, _Unknown) or v is None:
        return "unknown"
    if name == "read_width":
        return f"{v} bytes"
    if name == "fill_unit":
        return f"{v} bytes"
    if name == "latch":
        if not v.get("present"):
            return "absent"
        g, k = v["granularity_bytes"], v["entries"]
        d = v.get("depth")
        s = f"{k} entr{'y' if k == 1 else 'ies'} x {g} B"
        s += f", depth {d}" if d is not None else ", depth unknown"
        if v.get("indexed_on"):
            s += f", indexed on {v['indexed_on']}"
        s += f"; differential {v['differential_cycles']:g} cyc"
        if v.get("differential_at"):
            s += f" at {v['differential_at']}"
        s += "; no knob reaches it" if not v.get("knob_reaches_it") else "; a knob reaches it"
        return s
    if name == "cache":
        if not v.get("present"):
            return "none (no multi-line data reuse in any configuration)"
        fa = v.get("fully_associative")
        if fa is True:
            assoc = "fully associative"
        elif fa is False:
            assoc = "%d-way, %d sets, %d B line" % (v["ways"], v["sets"],
                                                    v["line_bytes"])
        elif v.get("ways") is None:
            assoc = ("associativity undetermined (candidates: %s way)"
                     % "/".join(str(w) for w in v.get("ways_candidates", [])))
        else:
            assoc = ("%d-way, conflict period %d B (sets x line not separable)"
                     % (v["ways"], v["conflict_period_bytes"]))
        if v.get("capacity_bytes") is None:
            floor = v.get("capacity_bytes_min")
            return ("%s, %s; %d B fetch unit"
                    % ("capacity not determined" if floor is None
                       else ">= %d B (capacity not determined)" % floor,
                       assoc, v["line_bytes"]))
        # The unit clause only says something when the unit is known; it used
        # to render as "capacity counted in not applicable".
        unit = v.get("capacity_unit")
        tail = ("" if unit in (None, "unknown", "not applicable",
                               "not_applicable")
                else "; capacity counted in %s" % unit)
        return ("%d B, %s; %d entries of %d B fetched%s"
                % (v["capacity_bytes"], assoc, v["capacity_entries"],
                   v["line_bytes"], tail))
    if name == "replacement_policy":
        return {"lru_or_fifo": "LRU or FIFO (not separable - see caveats)",
                "lru": "LRU (measured against FIFO, not assumed)",
                "fifo": "FIFO (measured against LRU, not assumed)",
                "pseudo_random": "pseudo-random",
                "not_applicable": ("not applicable - every configuration is "
                                   "direct-mapped, so the index chooses the "
                                   "victim")}.get(v, str(v))
    if name == "waitstate_scaling":
        return f"{v:g} cycles per wait state"
    if name == "twin_calibration":
        x = v["cyc_per_access"] if isinstance(v, dict) else v
        where = (f" in {v['config']} (`{v['body']}` body)"
                 if isinstance(v, dict) else "")
        return (f"{x:+g} cyc/access at 0 wait states{where}"
                + ("  (clean: the subtraction is unbiased)" if abs(x) < 0.1
                   else "  (BIASED: subtract it from every flash-twin figure "
                        "measured here)"))
    if name == "knob_map":
        out = []
        for knob, per in v.items():
            ctl = [m for m, e in per.items() if e["verdict"] == "controls"]
            ctl += [m + " (re-indexes, same capacity)"
                    for m, e in per.items() if e["verdict"] == "re-indexes"]
            ctl += [m + " (instrument confound, not a register)"
                    for m, e in per.items() if e["verdict"] == "confounds"]
            out.append(f"{knob} -> {', '.join(ctl) if ctl else 'nothing measured here'}")
        return "; ".join(out)
    return str(v)


def render(st: Structure, evidence: bool = True, width: int = 78) -> str:
    L: List[str] = []
    m = st.meta
    L.append("=" * width)
    L.append(f"  MEASURED DATASHEET - {st.part}")
    L.append("=" * width)
    if m:
        L.append(f"  core        {m.get('core','?')}   clock {m.get('clk_hz',0)/1e6:g} MHz")
        L.append(f"  counter     {m.get('timer','?')} @ {m.get('timer_hz',0)/1e6:g} MHz"
                 f"   caps: {','.join(m.get('caps', [])) or '-'}")
        L.append(f"  flash       {m.get('flash_region','?')}"
                 f"   twin: {m.get('twin_region','?')} ({m.get('twin_kind','?')})")
        knobs = m.get("knobs", [])
        if knobs:
            L.append("  knobs       " + ";  ".join(
                f"{k['name']} {k['values'][0]}..{k['values'][-1]}"
                if len(k["values"]) > 2 else f"{k['name']} {k['values']}"
                for k in knobs))
        L.append(f"  captured    {m.get('captured','?')}"
                 f"   {m.get('elapsed_s','?')} s"
                 f"   reps={m.get('reps','?')}")
    L.append("")
    L.append("  confidence: *** high   **  medium   *   low   (blank) unsupported")
    L.append("-" * width)

    order = ["read_width", "fill_unit", "latch", "cache", "replacement_policy",
             "waitstate_scaling", "twin_calibration", "knob_map"]
    for name in order:
        c = st.claims.get(name)
        if c is None:
            continue
        mark = _CONF_MARK.get(c.confidence, "   ")
        L.append(f"{mark} {name:20s} {_fmt_value(name, c.value)}")
    L.append("-" * width)

    if st.notes:
        L.append("")
        L.append("CROSS-CHECKS")
        for n in st.notes:
            L.extend(_wrap("  - " + n, width))

    if not evidence:
        return "\n".join(L) + "\n"

    for name in order:
        c = st.claims.get(name)
        if c is None:
            continue
        L.append("")
        L.append("=" * width)
        L.append(f"{name.upper()}  =  {_fmt_value(name, c.value)}"
                 f"   [{c.confidence}]")
        L.append("=" * width)
        if c.basis:
            L.append("method")
            L.extend(_wrap("  " + c.basis, width))
        if c.evidence:
            L.append("evidence")
            for e in c.evidence:
                L.append(e if e.startswith(" ") else "  " + e)
        if c.caveats:
            L.append("caveats")
            for cv in c.caveats:
                L.extend(_wrap("  ! " + cv, width))
    return "\n".join(L) + "\n"


def _wrap(s: str, width: int) -> List[str]:
    indent = " " * (len(s) - len(s.lstrip()))
    words, out, cur = s.split(), [], indent
    for w in words:
        if len(cur) + len(w) + 1 > width and cur.strip():
            out.append(cur.rstrip())
            cur = indent + "  " + w
        else:
            cur = (cur + " " + w) if cur.strip() else cur + w
    if cur.strip():
        out.append(cur.rstrip())
    return out


def to_json(st: Structure, path: Optional[str] = None) -> str:
    s = json.dumps(st.to_dict(), indent=1)
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(s + "\n")
    return s


def markdown(st: Structure) -> str:
    """A table suitable for pasting next to the repo's hand-written write-ups."""
    L = [f"# Measured memory system - {st.part}", ""]
    m = st.meta
    L.append(f"`{m.get('banner','')}`" if m.get("banner") else "")
    L.append("")
    L.append("| property | measured | confidence |")
    L.append("|---|---|---|")
    for name in ["read_width", "fill_unit", "latch", "cache",
                 "replacement_policy", "waitstate_scaling", "twin_calibration"]:
        c = st.claims.get(name)
        if c is None:
            continue
        L.append(f"| {name.replace('_',' ')} | {_fmt_value(name, c.value)} | "
                 f"{c.confidence} |")
    L.append("")
    km = st.claims.get("knob_map")
    if km is not None and km.known:
        L.append("| knob | read width | latch | data reuse |")
        L.append("|---|---|---|---|")
        for knob, per in km.value.items():
            row = [per.get(mm, {}).get("verdict", "unknown")
                   for mm in ("read_width", "latch", "data_reuse")]
            L.append(f"| `{knob}` | " + " | ".join(row) + " |")
        L.append("")
    for name, c in st.claims.items():
        if c.caveats:
            L.append(f"**{name}** caveats:")
            for cv in c.caveats:
                L.append(f"- {cv}")
            L.append("")
    if st.notes:
        L.append("Cross-checks:")
        for n in st.notes:
            L.append(f"- {n}")
    return "\n".join(L) + "\n"


def compare(a: Structure, b: Structure, width: int = 78) -> str:
    L = ["=" * width, f"  COMPARE  {a.part}  vs  {b.part}", "=" * width]
    names = list(dict.fromkeys(list(a.claims) + list(b.claims)))
    for n in names:
        ca, cb = a.claims.get(n), b.claims.get(n)
        va = _fmt_value(n, ca.value) if ca else "(absent)"
        vb = _fmt_value(n, cb.value) if cb else "(absent)"
        same = va == vb
        L.append(f"{'=' if same else '!':1s} {n}")
        L.append(f"    {a.part:>18s}: {va}")
        L.append(f"    {b.part:>18s}: {vb}")
    return "\n".join(L) + "\n"
