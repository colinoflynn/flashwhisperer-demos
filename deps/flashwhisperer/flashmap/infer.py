"""flashmap.infer - raw timings in, a memory-system structure out.

The input is a `MeasurementSet`: a flat bag of `(config, mode, args, cycles)`
observations, flash and twin.  The output is a `Structure`: a set of `Claim`s,
each carrying a value, a confidence, the method that produced it, and the
measurements that support it.  A claim the data cannot support comes out as
`UNKNOWN`.  Nothing here ever fills a gap with a datasheet number or a guess.

The five bespoke probes this replaces each answered one part by printing a table
a human read.  What is generalised here is the *reasoning*:

* **Read width** is a property of the flash array, not of the accelerator, so it
  must be invariant across every knob setting - and the tool checks that rather
  than assuming it.  Where it is *not* invariant, the larger saturation stride is
  a cache line fill and the smaller is the array; both are reported.
* **The latch** is fitted as a model family, not eyeballed: granularity, depth,
  number of entries and how entries are indexed all fall out of one offset
  sweep, including the L552's two entries indexed on address bit 3, which a
  "one 16-byte latch" reading gets wrong.
* **The cache** is fitted as `(ways, sets, line)` against the whole
  spacing/eviction surface via `N_evict(sp) = ways * (sets*line / gcd(sp,
  sets*line))`.  That single formula separates fully-associative from indexed
  without a special case: a fully-associative cache is `sets = 1`.
* **Capacity in tags versus capacity in bytes** is tested explicitly, because it
  is the distinction a naive tool gets wrong - the G474 evicts when the *line*
  count crosses 8 -> 9, not when 32 doublewords are touched.
* **Replacement policy** is attempted and expected to hit a wall.  It does; see
  `policy`'s caveats, which name the primitive that would settle it.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .experiments import (LATCH_GRANULARITIES, Config, MeasurementSet,
                          cfgkey, cfgname)


class _Unknown:
    """A value the data does not support.  Never a guess, never a default."""
    _inst = None

    def __new__(cls):
        if cls._inst is None:
            cls._inst = super().__new__(cls)
        return cls._inst

    def __repr__(self):
        return "unknown"

    def __str__(self):
        return "unknown"

    def __bool__(self):
        return False

    def __eq__(self, other):
        return isinstance(other, _Unknown)

    def __hash__(self):
        return hash("<unknown>")


UNKNOWN = _Unknown()

HIGH, MED, LOW, NONE_ = "high", "medium", "low", "none"


@dataclass
class Claim:
    name: str
    value: Any
    confidence: str = NONE_
    basis: str = ""
    evidence: List[str] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    @property
    def known(self) -> bool:
        return not isinstance(self.value, _Unknown) and self.value is not None

    def to_dict(self) -> dict:
        return {"name": self.name,
                "value": (None if isinstance(self.value, _Unknown) else self.value),
                "known": self.known,
                "confidence": self.confidence,
                "basis": self.basis,
                "evidence": list(self.evidence),
                "caveats": list(self.caveats),
                "data": _jsonable(self.data)}


def _jsonable(x):
    if isinstance(x, _Unknown):
        return None
    if isinstance(x, dict):
        return {str(k): _jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_jsonable(v) for v in x]
    return x


@dataclass
class Structure:
    part: str
    meta: dict = field(default_factory=dict)
    claims: Dict[str, Claim] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def add(self, c: Claim) -> Claim:
        self.claims[c.name] = c
        return c

    def get(self, name: str) -> Optional[Claim]:
        return self.claims.get(name)

    def value(self, name: str, default=UNKNOWN):
        c = self.claims.get(name)
        return c.value if (c is not None and c.known) else default

    def to_dict(self) -> dict:
        return {"part": self.part, "meta": _jsonable(self.meta),
                "claims": {k: v.to_dict() for k, v in self.claims.items()},
                "notes": list(self.notes)}


# ==========================================================================
# numeric helpers
# ==========================================================================

def _median(xs: Sequence[float]) -> float:
    s = sorted(xs)
    if not s:
        return float("nan")
    m = len(s) // 2
    return s[m] if len(s) % 2 else 0.5 * (s[m - 1] + s[m])


def _levels(values: Sequence[float], min_gap: float = 1.0):
    """Split a set of cycle counts into a fast and a slow level.

    Returns `(fast, slow, gap)` or None when the values do not separate.  These
    probes are integer-valued with a hard floor, so a genuine structural
    difference shows up as a clean bimodal split; anything else is reported as
    "did not separate" rather than thresholded into existence.
    """
    vs = sorted(set(round(v, 6) for v in values))
    if len(vs) < 2 or (vs[-1] - vs[0]) < min_gap:
        return None
    gaps = [(vs[i + 1] - vs[i], i) for i in range(len(vs) - 1)]
    gap, i = max(gaps)
    if gap < min_gap:
        return None
    lo = [v for v in values if v <= vs[i]]
    hi = [v for v in values if v > vs[i]]
    return _median(lo), _median(hi), gap


def _classify(v: float, fast: float, slow: float) -> str:
    return "fast" if abs(v - fast) <= abs(v - slow) else "slow"


def _isclose(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


# ==========================================================================
# per-config extraction
# ==========================================================================

def _walk_series(ms: MeasurementSet, cfg: Config, count_hint=None):
    """stride -> (per-access delta vs twin, per-access delta vs stride-0 flash)."""
    out = {}
    base0 = None
    for o in ms.rows("walk", "flash", cfg):
        st, n = (list(o.args) + [0, 0])[:2]
        if st == 0:
            base0 = (o.cycles, n)
    for o in ms.rows("walk", "flash", cfg):
        st, n = (list(o.args) + [0, 0])[:2]
        if n <= 0 or st == 0:
            continue
        d_twin = ms.delta(cfg, "walk", o.args)
        per_twin = None if d_twin is None else d_twin / n
        per_self = None
        if base0 and base0[1] == n:
            per_self = (o.cycles - base0[0]) / n
        out[st] = (per_twin, per_self, o.cycles, n)
    return out


def _saturation(series: Dict[int, Tuple], key: int = 0, rtol: float = 0.06,
                atol: float = 0.30):
    """Smallest stride from which the per-access cost is flat to the end."""
    strides = sorted(series)
    vals = []
    for st in strides:
        v = series[st][key]
        if v is None:
            return None
        vals.append(v)
    if not vals:
        return None
    top = max(vals)
    if top < 0.5:
        return None  # nothing resolvable: LATENCY 0, or no flash penalty at all
    tol = max(atol, rtol * abs(top))
    for i, st in enumerate(strides):
        if all(_isclose(v, top, tol) for v in vals[i:]):
            return st, top, tol
    return None


def _reread_series(ms: MeasurementSet, cfg: Config, kind: str = "flash"):
    out = {}
    for o in ms.rows("reread", kind, cfg):
        if len(o.args) >= 1:
            out[int(o.args[0])] = o.cycles
    return out


def _evict_table(ms: MeasurementSet, cfg: Config, kind: str = "flash"):
    """(spacing -> {n -> cycles})."""
    out: Dict[int, Dict[int, float]] = {}
    for o in ms.rows("evict", kind, cfg):
        if len(o.args) == 2:      # 3-argument evicts are the policy probe
            n, sp = int(o.args[0]), int(o.args[1])
            out.setdefault(sp, {})[n] = o.cycles
    return out


def _reread_deltas(ms: MeasurementSet, cfg: Config):
    """offset -> (flash - its own twin).  Zero means the re-read was free."""
    out = {}
    for o in ms.rows("reread", "flash", cfg):
        d = ms.delta(cfg, "reread", o.args)
        if d is not None:
            out[int(o.args[0])] = d
    return out


def _evict_deltas(ms: MeasurementSet, cfg: Config):
    """spacing -> {n -> (flash - its own twin)}."""
    out: Dict[int, Dict[int, float]] = {}
    for o in ms.rows("evict", "flash", cfg):
        if len(o.args) != 2:      # 3-argument evicts are the policy probe
            continue
        d = ms.delta(cfg, "evict", o.args)
        if d is not None:
            n, sp = int(o.args[0]), int(o.args[1])
            out.setdefault(sp, {})[n] = d
    return out


def _miss_scale(ms: MeasurementSet, cfg: Optional[Config] = None) -> float:
    """What one missed flash access costs **in this configuration**, in cycles.

    Taken from that configuration's own cold stride walk, at the stride where it
    saturates: a walk with no reuse in it is a direct measurement of the array,
    and every hit/miss classification downstream is then a comparison against a
    measured cost rather than a threshold someone chose.

    It is deliberately per-configuration.  A single scale pooled over the whole
    knob grid is set by the highest wait-state cell, and a miss at LATENCY 4 is
    then less than half of a miss at LATENCY 15 and classifies as a *hit* - so
    an entire capacity sweep run at 4 wait states silently reports "no eviction
    at any spacing".  That is not hypothetical; it is what a pooled scale did to
    a G474 capture whose raw data shows a crisp 8-tag transition.
    """
    if cfg is not None:
        series = _walk_series(ms, cfg)
        sat = _saturation(series, 0)
        if sat:
            return sat[1]
        cand = [v[0] for v in series.values() if v[0] is not None]
        if cand and max(cand) >= 0.5:
            return max(cand)
        return 0.0
    best = 0.0
    for c in ms.configs():
        best = max(best, _miss_scale(ms, c))
    return best


def _classify_delta(d: float, scale: float) -> str:
    """`fast` == the access was free relative to its own SRAM twin."""
    return "fast" if abs(d) < 0.5 * scale else "slow"


def _config_levels(ms: MeasurementSet, cfg: Config, min_gap: float = 1.0):
    """The fast/slow pair for one knob setting, pooled over reread and evict.

    Kept for the absolute-cycle evidence lines; classification uses the
    twin-referenced deltas above, which stay correct when a whole configuration
    is flat (the STM32F303 case: every re-read costs what a fresh read costs, so
    the cycle counts do not separate and only the twin says which level it is).
    """
    vals: List[float] = []
    vals += list(_reread_series(ms, cfg).values())
    for sp, series in _evict_table(ms, cfg).items():
        vals += list(series.values())
    return _levels(vals, min_gap)


def _n_evict(series: Dict[int, float], scale: float):
    """Smallest n whose re-read is slow, and stays slow for every larger tested n.

    `series` is n -> delta against the twin.  Returns `(n, determined)`;
    `determined=False` means the target survived every n tested, so the true
    value is only bounded below.
    """
    ns = sorted(series)
    if not ns:
        return None, False
    cls = {n: _classify_delta(series[n], scale) for n in ns}
    for i, n in enumerate(ns):
        if cls[n] == "slow" and all(cls[m] == "slow" for m in ns[i:]):
            return n, True
    return ns[-1], False


def _evict_shape(series: Dict[int, float], scale: float):
    """What one eviction series says - and whether the step model holds at all.

    `N_evict` is only a number if retention is a THRESHOLD in the working-set
    size: fast below it, slow at it and above.  That is an assumption about
    the part, and it has to be checked in the data before any geometry is read
    off, because every quantity the fit produces - ways, sets, conflict
    period, capacity, and the survival floor - is meaningless without it.

    Four statuses, and only the first is a measurement of `N_evict`:

    * `threshold`      - fast below n, slow at n and at every larger n tested.
    * `uncorroborated` - the ONLY slow reading is the largest n tested.  There
      is nothing above it to confirm the target stays lost, so this is an
      upper bound (`N_evict <= n`), not a value.  A run that ends on the first
      slow point looks identical to one that ends on a one-off.
    * `survived`       - fast at every n tested: a lower bound, `N_evict > n`.
    * `non_monotone`   - a FAST reading sits above a slow one.  The threshold
      model is falsified by this configuration's own data; the series cannot
      be summarised by one number and must not be fitted as if it could.

    This is the positive-control rule applied to a model rather than to a
    configuration: before the fit is allowed to read `N_evict` off a series,
    the series has to be the kind of thing `N_evict` describes.
    """
    ns = sorted(series)
    if not ns:
        return None
    cls = {n: _classify_delta(series[n], scale) for n in ns}
    slow = [n for n in ns if cls[n] == "slow"]
    if not slow:
        return {"n": ns[-1], "status": "survived", "cls": cls, "max_n": ns[-1]}
    first = slow[0]
    above = [n for n in ns if n > first]
    if any(cls[n] == "fast" for n in above):
        return {"n": first, "status": "non_monotone", "cls": cls,
                "max_n": ns[-1],
                "recovered": [n for n in above if cls[n] == "fast"]}
    if not above:
        return {"n": first, "status": "uncorroborated", "cls": cls,
                "max_n": ns[-1]}
    return {"n": first, "status": "threshold", "cls": cls, "max_n": ns[-1]}


# ==========================================================================
# discriminating power - the positive control every claim consults
# ==========================================================================
#
# THE RULE.  Before a configuration is allowed to contribute evidence *for* or
# *against* a structural claim, it must be established that the configuration
# could have shown the opposite.  A cell with no discriminating power is
# SILENT; it is not a vote for the thing it happened to display.
#
# This is the same principle as a positive control in a bench experiment, and
# it lives here - in one place - rather than in each claim, because five
# separate defects in this tool have now been instances of it:
#
#   * five six-offset wait-state cells outvoting one 47-offset latch sweep on
#     the L552, because six offsets cannot separate `8 B x 2` from `16 B x 1`;
#   * one `waitstates = 0` cell out of thirty-eight setting the H723's read
#     width to 8 bytes, because at LATENCY 0 every flash structure reads flat;
#   * a `waysel` verdict of "no effect" taken from a scalar that is the same
#     number in both of the settings it distinguishes;
#   * a `pseudo_random` verdict from a chase whose stride could not produce a
#     conflict however large the working set;
#   * and `knob_reaches_it: True` on the H723's latch, from three wait-state
#     cells at LATENCY 0, 1 and 2 - where a hit and a miss cost so nearly the
#     same that "no reuse at any offset" is the resolution floor speaking.
#
# The rule is deliberately ASYMMETRIC, because the two directions are not
# equally demanding:
#
#   * a configuration that SHOWED a difference has demonstrated its own
#     discriminating power, and needs no control;
#   * a configuration that showed NO difference is claiming an absence, and
#     an absence is only a measurement if the presence would have been
#     visible.  That is what the control establishes.
#
# The control is measured, never assumed, and it is measured INSIDE the flash
# column so the twin's own offset cannot manufacture or hide it - on the H723
# the DTCM twin reads +3 to +4 cycles per access at zero wait states, which is
# exactly the pedestal that turned two resolved cells into "no data-side
# reuse" and put a register behind them that does not exist.

#: The smallest difference this instrument can call a difference.  The
#: counters here are integer-valued and every repeat in every capture in this
#: repository has `min == max`, so a one-cycle split is real and a zero-cycle
#: split is silence.  This is a property of the instrument, not of any part.
_RESOLUTION_CYCLES = 1.0


@dataclass
class Power:
    """Could this configuration have shown a hit and a miss differently?"""
    ok: bool
    contrast: float
    source: str
    reason: str


def _waitstate_contrast(ms: MeasurementSet, cfg: Config) -> Optional[float]:
    """`flash(LATENCY) - flash(0)` at the same stride, all other knobs equal.

    The control has to be INDEPENDENT of the structure it licenses a claim
    about, and this one is: it asks only whether this configuration resolves
    the flash array's own access cost at all.  The obvious alternative --
    comparing a stride-0 walk with a saturated one in the same cell - is
    circular for the latch, because a part with no latch reads zero there for
    the very reason the claim is trying to establish (the STM32F303).

    Both halves are flash, so the twin and every instrument offset it carries
    cancel exactly; on the H723 that offset is +4 cycles per access, and it is
    the whole reason three flat cells read as "no data-side reuse".

    Returns `None` where the capture has no `waitstates = 0` cell to reference
    against - there the flash is never known to be free and the difference is
    not a calibrated zero.
    """
    if "waitstates" not in cfg:
        return None
    ws_lo = min(ms.knob_values("waitstates") or [cfg["waitstates"]])
    if ws_lo != 0:
        return None
    if cfg["waitstates"] == ws_lo:
        return 0.0
    ref = dict(cfg)
    ref["waitstates"] = ws_lo
    if not any(cfgkey(c) == cfgkey(ref) for c in ms.configs()):
        return None
    here = _walk_series(ms, cfg)
    there = _walk_series(ms, ref)
    diffs = [here[st][0] - there[st][0]
             for st in set(here) & set(there)
             if here[st][0] is not None and there[st][0] is not None]
    return max(diffs) if diffs else None


def _discriminating_power(ms: MeasurementSet, cfg: Config) -> Power:
    """How large a hit/miss difference this configuration could have shown."""
    cache = ms.__dict__.setdefault("_power_cache", {})
    key = cfgkey(cfg)
    hit = cache.get(key)
    if hit is not None:
        return hit
    value = _waitstate_contrast(ms, cfg)
    src = ("the same walk at `waitstates = 0`, where a flash access is known "
           "to cost no more than an SRAM one")
    assumed = ""
    if value is None:
        # No calibrated zero on the wait-state axis.  Fall back to the twin,
        # which `PROTOCOL.md`'s `R` rule exists to make usable for exactly
        # this - and say so, because this capture could not check it.
        value = _miss_scale(ms, cfg)
        src = "a flash access measured against its own SRAM twin"
        assumed = (" This capture has no `waitstates = 0` cell for this "
                   "configuration, so the twin is taken at its word rather "
                   "than calibrated; see the twin_calibration claim.")
    if value < _RESOLUTION_CYCLES:
        p = Power(False, value, src,
                  "a hit and a miss differ by %.3g cycles here (%s), below the "
                  "%.3g-cycle resolution of an integer counter, so this "
                  "configuration could not have shown a structure whether or "
                  "not one is present - at LATENCY 0 in particular every "
                  "flash structure reads flat by construction "
                  "(MEASURING_CHANNELS B3)"
                  % (value, src, _RESOLUTION_CYCLES) + assumed)
    else:
        p = Power(True, value, src, "")
    cache[key] = p
    return p


def _replay_disagreements(ms: MeasurementSet, mode: str = "evict"):
    """Rows measured twice in one capture that did not come back the same.

    The plan re-measures a few `evict` rows at the very end of the programme,
    in the opposite order (`default_plan`'s replay control).  A probe whose
    result is a function of its arguments returns the same number both times.
    Where it does not, the measurement depends on what ran BEFORE it, and no
    amount of repeating one row can reveal that - repeats of a single command
    leave the same residue behind each time, so they agree while the surface
    as a whole does not.

    This is the positive-control rule applied to the instrument itself: before
    a number is read as a property of the part, it has to be established that
    the number is a property of the measurement rather than of its neighbours.
    """
    seen: Dict[Tuple, Any] = {}
    out = []
    for o in ms.rows(mode, "flash"):
        key = (cfgkey(o.config), tuple(o.args))
        first = seen.get(key)
        if first is None:
            seen[key] = o
        elif abs(first.cycles - o.cycles) >= _RESOLUTION_CYCLES:
            out.append((dict(o.config), tuple(o.args), first.cycles, o.cycles))
    return out


# Knobs that move the INSTRUMENT rather than the part.  `loopmem` selects where
# the probe loop itself lives; it is not a register of the memory system, and a
# difference across it is a statement about the measurement, not about silicon.
# `PROTOCOL.md` declares it with that meaning, which is why the host may reason
# about it by name.
_INSTRUMENT_KNOBS = ("loopmem",)


def _isolating_value(ms: MeasurementSet, knob: str):
    """The value of `knob` at which the probe loop is NOT sharing memory with
    the data under test.

    `loopmem` is declared by `PROTOCOL.md` with 0 = the probe loop runs from
    RAM/ITCM (isolated) and 1 = it runs from flash (deliberately confounded),
    so the isolating value is the smallest advertised one.  No other knob is
    treated this way, and a part that does not advertise `loopmem` is taken at
    its word that protocol rule 3 holds.
    """
    vals = ms.knob_values(knob)
    return min(vals) if vals else None


def _is_isolated(ms: MeasurementSet, cfg: Config) -> bool:
    """Is the probe loop out of the memory whose structure is under test?"""
    if "loopmem" not in ms.knob_names():
        return True
    iso = _isolating_value(ms, "loopmem")
    return cfg.get("loopmem", iso) == iso


# ==========================================================================
# 1. read width
# ==========================================================================

def _structural_configs(ms: MeasurementSet) -> List[Config]:
    """The cross-product grid, excluding the wait-state sweep's thin cells.

    `default_plan` measures two kinds of configuration: a full cross-product of
    the binary knobs at ONE reference wait state - that is the structural grid
    - and, separately, two corners swept over the whole `waitstates` axis so a
    coefficient can be fitted.  The second kind exists to measure a slope, and
    it includes `waitstates = 0`, where a hit and a miss cost the same cycle and
    every flash structure reads flat by construction (MEASURING_CHANNELS B3).

    A structural claim must therefore be decided on the grid.  Letting the
    sweep's cells vote is how one `waitstates = 0` cell out of thirty-eight came
    to set the H723's read width to 8 bytes against a published 32, and it is
    the same shape of error as five six-offset cells outvoting a dense latch
    sweep: a configuration that exists to measure something else deciding a
    structure it was never sized to resolve.
    """
    configs = ms.configs()
    # ... and on the ISOLATED ones.  A configuration whose probe loop lives in
    # the memory under test measures the probe, and on a part whose cache is
    # unified it measures nothing else: on the L552 the one `icache=1 waysel=1
    # loopmem=1` cell fits a 16-byte cache where its isolated twin fits 8 KB,
    # which is enough to turn "WAYSEL re-indexes at constant capacity" into
    # "WAYSEL changes the capacity".
    iso = [c for c in configs if _is_isolated(ms, c)]
    if len(iso) >= 2:
        configs = iso
    if "waitstates" not in ms.knob_names():
        return configs
    by_ws: Dict[Any, List[Config]] = {}
    for c in configs:
        by_ws.setdefault(c.get("waitstates"), []).append(c)
    grid = max(by_ws.values(), key=len)
    return grid if len(grid) >= 2 else configs


def infer_read_width(ms: MeasurementSet) -> Tuple[Claim, Claim]:
    per_cfg = {}
    ev: List[str] = []
    grid = _structural_configs(ms)
    grid_keys = {cfgkey(c) for c in grid}
    n_other = len(ms.configs()) - len(grid)
    for cfg in ms.configs():
        if cfgkey(cfg) not in grid_keys:
            continue
        series = _walk_series(ms, cfg)
        if not series:
            continue
        sat_twin = _saturation(series, 0)
        sat_self = _saturation(series, 1)
        per_cfg[cfgkey(cfg)] = {"cfg": cfg, "twin": sat_twin, "self": sat_self,
                                "series": series}

    resolved = [(k, v) for k, v in per_cfg.items() if v["twin"]]
    if not resolved:
        c = Claim("read_width", UNKNOWN, NONE_,
                  "cold stride walk, flash minus its own twin, per access",
                  caveats=["No knob setting produced a resolvable per-access flash "
                           "cost. At LATENCY = 0 a hit and a miss cost the same "
                           "cycle, so every flash structure reads flat "
                           "(MEASURING_CHANNELS B3) - over-program the wait "
                           "states and re-run."])
        return c, Claim("fill_unit", UNKNOWN, NONE_, "cold stride walk with reuse enabled")

    widths = {}
    for k, v in resolved:
        st, top, tol = v["twin"]
        widths.setdefault(st, []).append((v["cfg"], top))
        ev.append(f"  {cfgname(v['cfg'])}: saturates at stride {st}, "
                  f"{top:.2f} cyc/access")

    width = min(widths)
    per_word = _median([t for _, t in widths[width]])
    invariant = len(widths) == 1
    if n_other:
        ev.append(f"  fitted on the {len(per_cfg)}-configuration cross-product "
                  f"at one reference wait state; the {n_other} wait-state-sweep "
                  f"cell(s) are excluded, because they exist to measure a slope "
                  f"and include LATENCY 0, where every flash structure reads "
                  f"flat whether or not it is there")

    caveats: List[str] = []
    if invariant:
        conf = HIGH
        basis = ("Cold forward stride walk, flash minus its own SRAM twin. The "
                 "per-access cost rises with the number of distinct flash words "
                 "touched and saturates at one word per access; the saturating "
                 "stride is the array's read width.")
        ev.append(f"  invariant across all {len(resolved)} knob settings measured "
                  f"-- consistent with a property of the flash array, not of the "
                  f"accelerator")
    else:
        conf = MED
        basis = ("Cold forward stride walk. The saturating stride is NOT the same "
                 "at every knob setting, so it is reported as two numbers: the "
                 "smallest is the array's read width, the largest is a cache line "
                 "fill (a line-filling cache saturates only when the stride "
                 "reaches the line).")
        # Which knob, if any, explains the split?  A line-filling cache makes
        # the walk saturate LATER, and the knob that enables it separates the
        # configurations cleanly.  If no knob does, the split is not a fill
        # unit - it is contamination, and the claim must not be dressed up as
        # a two-number answer.
        small = {cfgkey(c) for c, _ in widths[min(widths)]}
        explain = []
        for knob in ms.knob_names():
            if knob == "waitstates":
                continue
            vals = {}
            ok = True
            for k, v in per_cfg.items():
                if not v["twin"]:
                    continue
                kv = v["cfg"].get(knob)
                want = cfgkey(v["cfg"]) in small
                if kv in vals and vals[kv] != want:
                    ok = False
                    break
                vals[kv] = want
            if ok and len(vals) > 1:
                explain.append(knob)
        caveats.append(
            "Read width is NOT invariant across knob settings: saturation at "
            + ", ".join(f"stride {st} in {len(v)} config(s)" for st, v in sorted(widths.items()))
            + ". "
            + (("The split is explained exactly by `%s`, which is what a knob "
                "enabling a line-filling cache looks like: the smaller stride "
                "is the array's read width and the larger is the unit the cache "
                "fills. The cache claim should carry the larger figure as its "
                "line size; if it disagrees, one of the two is wrong."
                % "`, `".join(explain))
               if explain else
               "NO knob explains the split - no single knob separates the "
               "configurations that saturate early from the ones that do not. "
               "A fill unit is enabled by a knob, so this is not one; treat "
               "both numbers as suspect and the difference as contamination "
               "until a knob is found that accounts for it."))
        if not explain:
            conf = LOW

    # A within-column cross-check (NRF52_GEOMETRY 1a): the twin can eat the
    # effect when the probe loop is loose enough that the SRAM side does work
    # the flash side gets for free.
    self_widths = {v["self"][0] for _, v in resolved if v["self"]}
    if self_widths and self_widths != set(widths):
        caveats.append(
            f"The twin-subtracted saturation ({sorted(widths)}) and the "
            f"stride-0-referenced saturation ({sorted(self_widths)}) disagree. "
            f"The within-column reference is the build-stable one - a loose "
            f"probe loop inflates the SRAM baseline and understates the flash "
            f"penalty (NRF52_GEOMETRY 1a).")

    width_claim = Claim("read_width", width, conf, basis, ev, caveats,
                        {"per_word_cycles": round(per_word, 3),
                         "by_config": {cfgname(v["cfg"]): (v["twin"][0] if v["twin"] else None)
                                       for _, v in per_cfg.items()},
                         "invariant": invariant})

    fill = max(widths) if len(widths) > 1 else UNKNOWN
    fill_claim = Claim(
        "fill_unit", fill, MED if len(widths) > 1 else NONE_,
        "Largest saturating stride across knob settings: where a knob makes the "
        "walk saturate later than the array's read width, that later stride is "
        "the unit the cache fills.",
        [e for e in ev if "saturates" in e],
        [] if len(widths) > 1 else ["Every knob setting saturates at the same "
                                    "stride, so no separate fill unit is "
                                    "distinguishable from the read width."])
    return width_claim, fill_claim


# ==========================================================================
# 2. latch
# ==========================================================================

#: Imported from `experiments` so the sweep and the fit cannot drift apart: a
#: model family the plan does not probe the boundaries of is a family the fit
#: will report as under-determined.
_LATCH_G = LATCH_GRANULARITIES
_LATCH_K = (1, 2, 4, 8)


def _latch_predict(off: int, g: int, k: int, a: int) -> bool:
    """True == the re-read is SLOW (the target was lost)."""
    b0 = a // g
    b1 = (a + off) // g
    return (b1 != b0) and ((b1 % k) == (b0 % k))


def _latch_predict_dist(off: int, g: int) -> bool:
    """The rival 'proximity' model: slow iff further than g bytes away."""
    return abs(off) >= g


def _fit_latch(obs: Dict[int, str]):
    """Fit (granularity, entries, alignment) to a fast/slow offset sweep."""
    best = None
    for g, k, a in _latch_models():
        hits = sum(1 for off, cl in obs.items()
                   if _latch_predict(off, g, k, a) == (cl == "slow"))
        cand = (hits, -k, -g, -a, g, k, a)
        if best is None or cand[:4] > best[:4]:
            best = cand
    if best is None:
        return None
    hits, _, _, _, g, k, a = best
    return {"granularity": g, "entries": k, "align": a,
            "score": hits / max(1, len(obs)), "hits": hits, "total": len(obs)}


#: The target's alignment within its own block is searched at BYTE resolution.
#: It used to be searched in steps of 4, on the reasoning that the probe reads
#: 4-byte words - and that was a constant with a fact about the sweep buried
#: in it.  A 4-byte read at offset `off` touches bytes `off .. off+3`, so the
#: block boundary the sweep sees is set by the LAST byte read, which puts the
#: effective alignment at 3 modulo the granularity.  Every sweep whose offsets
#: are all multiples of 4 cannot tell a = 0 from a = 3 and never noticed; the
#: two parts whose plans include odd offsets (the H723 and the nRF52840) both
#: land on a = 1..3, and with a stepped by 4 NO model in the family fitted
#: their densest sweep exactly.  The consequence was not a slightly worse fit:
#: the most discriminating configuration on each part was dropped from the
#: intersection entirely, leaving the answer to the six-offset wait-state
#: cells (the H723: a six-member family instead of one) or to nothing at all
#: (the nRF52840: an empty family with the model reported as undetermined).
def _latch_models():
    """Every (granularity, entries, alignment) in the model family."""
    for g in _LATCH_G:
        for k in _LATCH_K:
            for a in range(0, g * k):
                yield g, k, a


_LATCH_N_MODELS = sum(1 for _ in _latch_models())


def _latch_consistent(obs: Dict[int, str]) -> List[Tuple[int, int, int]]:
    """Every model in the family that predicts this sweep EXACTLY.

    This, not the best fit, is what a configuration knows.  A sweep of six
    offsets is consistent with `16 B x 1 entry` **and** `8 B x 2 entries`,
    because at those six offsets the two models make the same prediction; a
    dense sweep across the boundary is consistent with only one of them.
    Counting best-fits gives both sweeps one vote each and lets the sparse one
    decide; intersecting consistency sets gives a configuration a voice only
    against the models its own offsets actually exclude.
    """
    out = []
    for g, k, a in _latch_models():
        if all(_latch_predict(off, g, k, a) == (cl == "slow")
               for off, cl in obs.items()):
            out.append((g, k, a))
    return out


def _latch_separating_offsets(models, already_swept, want: int = 4) -> str:
    """Which offsets would tell the surviving models apart.

    An under-determined latch claim is only actionable if it says what to
    measure next, and "a denser sweep around g" is not good enough: with
    `16 B x 1` and `8 B x 2` still standing, every offset in [8, 16) is a hit
    under BOTH and decides nothing, while [24, 32) separates them cleanly.  So
    the models are simply evaluated against each other, and the offsets where
    they disagree - excluding the ones already swept - are named.
    """
    ms = sorted(models)
    if len(ms) < 2:
        return ""
    span = 8 * max(g for g, _, _ in ms)
    out = []
    for off in sorted(range(-span, span + 1, 4), key=lambda o: (abs(o), o)):
        if off in already_swept:
            continue
        preds = {_latch_predict(off, g, k, a) for g, k, a in ms}
        if len(preds) > 1:
            out.append(off)
            if len(out) >= want:
                break
    if not out:
        return ("No offset within +/-%d bytes separates them at all, so they "
                "are not distinguishable by a `reread` sweep of any density." % span)
    return ("They are separable, and this sweep did not try the offsets that "
            "would do it: %s (the models disagree there and nowhere in the "
            "measured set)." % ", ".join("%+d" % o for o in out))


def _fit_latch_distance(obs: Dict[int, str]):
    best = None
    for g in _LATCH_G:
        hits = sum(1 for off, cl in obs.items()
                   if _latch_predict_dist(off, g) == (cl == "slow"))
        if best is None or hits > best[0]:
            best = (hits, g)
    return {"granularity": best[1], "score": best[0] / max(1, len(obs)),
            "hits": best[0], "total": len(obs)}


def _classify_reread(ms: MeasurementSet, cfg: Config, rr: Dict[int, float],
                     scale: float) -> Tuple[Dict[int, str], bool]:
    """fast/slow per offset, decided INSIDE the configuration where it can be.

    Returns `(obs, uniform)`; `uniform` means the column showed one level, so
    whatever it says is a claim of absence and the caller must consult the
    positive control before letting it speak.

    The split is read off the configuration's OWN column rather than compared
    against an absolute threshold, because the threshold carries the twin's
    offset with it.  On the H723 the SRAM twin reads +3 cycles per `reread`;
    at one and two wait states the flash column splits cleanly (13 vs 14, 13
    vs 15) while both levels sit above `0.5 x scale`, so an absolute test
    called every offset a miss and the configuration reported "no data-side
    reuse at any offset" - the exact negation of what it measured.  The
    `waitstate_scaling` claim already took its differential this way, from the
    same rows, and got 1 and 2 cycles out of them.

    The split is accepted only if it is at least as large as the resolution
    floor and a serious fraction of the hit/miss contrast the positive control
    measured for this configuration; a one-cycle wobble in a cell where a miss
    is worth nine is not a hit/miss split, and falls back to the absolute test.
    """
    lv = _levels(list(rr.values()), _RESOLUTION_CYCLES)
    if lv is not None:
        fast, slow, gap = lv
        want = max(_RESOLUTION_CYCLES,
                   0.4 * _discriminating_power(ms, cfg).contrast)
        if gap >= want:
            obs = {off: _classify(d, fast, slow) for off, d in rr.items()}
            return obs, len(set(obs.values())) < 2
    obs = {off: _classify_delta(d, scale) for off, d in rr.items()}
    return obs, len(set(obs.values())) < 2


def infer_latch(ms: MeasurementSet) -> Claim:
    per_cfg = {}
    ev: List[str] = []
    caveats: List[str] = []
    scale = _miss_scale(ms)          # only for the "nothing is resolvable" gate
    if scale < 0.5:
        return Claim("latch", UNKNOWN, NONE_,
                     "reread sweep: read A, read A+off, re-read A",
                     [],
                     ["A missed flash access costs less than half a cycle more "
                      "than an SRAM access in every configuration measured, so a "
                      "hit and a miss are indistinguishable and no reuse "
                      "structure can be resolved. Over-program the wait states "
                      "(MEASURING_CHANNELS B3) and re-run."])

    silent: List[Config] = []
    for cfg in ms.configs():
        rr = _reread_deltas(ms, cfg)
        if len(rr) < 4:
            continue
        # Each configuration is classified against ITS OWN miss cost.
        scale = _miss_scale(ms, cfg)
        rr_abs = _reread_series(ms, cfg)
        tk = ms.twin_kind()
        rrt = _reread_series(ms, cfg, tk) if tk else {}
        if rrt and _levels(list(rrt.values()), 1.0) is not None:
            caveats.append(
                "The SRAM twin is NOT flat across the reread offsets in "
                + cfgname(cfg) + ": the probe's own address arithmetic costs "
                "something, so part of the flash column is not a flash effect.")
        obs, uniform = _classify_reread(ms, cfg, rr, scale)
        if uniform:
            # The column showed ONE level.  That is a claim of absence (or of
            # masking), and an absence is only a measurement where the
            # presence would have been visible - so the positive control
            # decides whether this configuration may say anything at all.
            pw = _discriminating_power(ms, cfg)
            if not pw.ok:
                silent.append(cfg)
                per_cfg[cfgkey(cfg)] = {"cfg": cfg, "state": "no-resolution",
                                        "rr": rr, "rr_abs": rr_abs,
                                        "differential": 0.0, "why": pw.reason}
                continue
        slow_d = [d for off, d in rr.items() if obs[off] == "slow"]
        fast_d = [d for off, d in rr.items() if obs[off] == "fast"]
        rec = {"cfg": cfg, "rr": rr, "rr_abs": rr_abs,
               "differential": (_median(slow_d) - _median(fast_d)) if (slow_d and fast_d) else 0.0}
        if all(c == "slow" for c in obs.values()):
            rec["state"] = "no-reuse"
        elif all(c == "fast" for c in obs.values()):
            rec["state"] = "all-hit"
        else:
            rec["state"] = "resolved"
            rec["fit"] = _fit_latch(obs)
            rec["fit_distance"] = _fit_latch_distance(obs)
            rec["consistent"] = _latch_consistent(obs)
        per_cfg[cfgkey(cfg)] = rec

    resolved = [v for v in per_cfg.values() if v["state"] == "resolved"]
    if not resolved and per_cfg and all(v["state"] == "no-reuse" for v in per_cfg.values()):
        # Every knob setting, every offset, including offset 0: the re-read costs
        # what a fresh read costs.  There is no data-side reuse of any kind.
        # This is the STM32F303 answer, and it is a measurement, not a gap.
        return Claim("latch", {"present": False}, HIGH,
                     "reread sweep at every knob setting: a re-read of A is as "
                     "dear as a fresh read even when the intervening access was "
                     "to A itself (offset 0)",
                     [f"  {cfgname(v['cfg'])}: slow at every offset including 0"
                      for v in per_cfg.values()],
                     ["Absence of a *data-side* latch. The flash array may still "
                      "be wider than the access size - the row register can "
                      "exist without the data path being wired to it (STM32F303). "
                      "The instruction path is not measured here."])
    if not resolved:
        states = {v["state"] for v in per_cfg.values()}
        why = ("every knob setting re-read at one cost, so the probe could not "
               "separate a hit from a miss"
               if states <= {"flat", "no-resolution"} else
               "; ".join(sorted(states)))
        return Claim("latch", UNKNOWN, NONE_,
                     "reread sweep: read A, read A+off, re-read A; the offset at "
                     "which the re-read becomes dear is the granularity",
                     [f"  {cfgname(v['cfg'])}: {v['state']}" for v in per_cfg.values()],
                     [f"No knob setting resolved a latch: {why}.",
                      "'all-hit' is masking, not absence: a cache large enough to "
                      "hold both probe addresses hides the latch underneath it."])

    # ---- consensus by discriminating power, not by majority --------------
    #
    # Every resolved configuration contributes the SET of models its own
    # offsets are consistent with, and the answer is the intersection.  A
    # configuration that cannot separate two models is silent on that
    # distinction instead of casting a vote for whichever its tie-break
    # happened to prefer - which is what let five six-offset wait-state cells
    # outvote one 47-offset sweep on the L552 and report its two 8-byte latch
    # entries as one 16-byte latch.
    for v in resolved:
        v.setdefault("consistent", [])
    with_model = [v for v in resolved if v["consistent"]]
    agree = set(with_model[0]["consistent"]) if with_model else set()
    for v in with_model[1:]:
        agree &= set(v["consistent"])
    unexplained = [v for v in resolved if not v["consistent"]]

    contradiction = False
    if agree:
        # Order the surviving family by SIMPLICITY - fewest entries first, then
        # smallest granularity - so the representative of an under-determined
        # family is the least elaborate model in it, never the most.  The
        # family itself is reported; the representative is only its label.
        pairs = sorted({(gg, kk) for gg, kk, _ in agree}, key=lambda t: (t[1], t[0]))
        g, k = pairs[0]
        a = min(aa for gg, kk, aa in agree if (gg, kk) == (g, k))
        best_cfgs = [v for v in resolved if (g, k, a) in v["consistent"]]
    else:
        # Either nothing in the family explains a sweep, or two configurations
        # exclude each other's models - a knob that CHANGES the latch, or a
        # measurement artefact.  Fall back to the single most discriminating
        # sweep and say so rather than pooling contradictory evidence.
        contradiction = True
        ranked = sorted(resolved,
                        key=lambda v: (len(v["consistent"]) or _LATCH_N_MODELS,
                                       -len(v["rr"])))
        pick = ranked[0]
        f = pick["fit"]
        g, k, a = f["granularity"], f["entries"], f["align"]
        # The family is what the sweep we fell back on admits - not empty.
        # An empty family beside `model_determined: False` says both "the
        # answer is undecided" and "there are no candidates", which cannot
        # both be true; the H723's latch claim, which names six candidates
        # and the offsets that would separate them, is what this path owes
        # the reader too.
        pairs = sorted({(gg, kk) for gg, kk, _ in pick["consistent"]},
                       key=lambda t: (t[1], t[0])) or [(g, k)]
        agree = set(pick["consistent"]) or {(g, k, a)}
        best_cfgs = [v for v in resolved
                     if (v["fit"]["granularity"], v["fit"]["entries"],
                         v["fit"]["align"]) == (g, k, a)]
    ambiguous = len(pairs) > 1
    exact = all(v["fit"]["score"] == 1.0 for v in best_cfgs)
    dense_rr = set()
    for v in resolved:
        dense_rr |= set(v["rr"])

    for v in sorted(resolved, key=lambda x: cfgname(x["cfg"])):
        f = v["fit"]
        n_cons = len(v["consistent"])
        if n_cons == 0:
            disc = "  [no model in the family fits it exactly]"
        else:
            excl = {(gg, kk) for gg, kk, _ in v["consistent"]}
            disc = ("  [discriminating: this sweep admits only %s]"
                    % ", ".join("%dBx%d" % gk for gk in sorted(excl))
                    if len(excl) <= 3 else
                    "  [%d granularity x entries combinations fit it equally "
                    "well - it does not discriminate]" % len(excl))
        ev.append(f"  {cfgname(v['cfg'])}: {f['hits']}/{f['total']} offsets fit "
                  f"granularity {f['granularity']} B x {f['entries']} entr"
                  f"{'y' if f['entries'] == 1 else 'ies'}"
                  f"{' (align ' + str(f['align']) + ')' if f['align'] else ''}, "
                  f"differential {v['differential']:.3g} cyc" + disc)
    if with_model:
        ev.append("  -> intersecting what each configuration is consistent with "
                  "leaves %s; the fit is taken from the %d configuration(s) that "
                  "admit it, not from a majority of per-configuration best fits"
                  % (", ".join("%d B x %d entr%s" % (gg, kk, "y" if kk == 1 else "ies")
                               for gg, kk in pairs) or "nothing",
                     len(best_cfgs)))
    if ambiguous:
        caveats.append(
            "The offset sweep does not separate these models: "
            + ", ".join("%d B x %d entr%s" % (gg, kk, "y" if kk == 1 else "ies")
                        for gg, kk in pairs)
            + ". Every one of them predicts every offset measured. "
            + _latch_separating_offsets(agree, dense_rr)
            + " The simplest is reported, and it is a representative of the "
              "family, not a measurement.")
    if contradiction:
        caveats.append(
            "No single model in the family explains every configuration's "
            "sweep: %d configuration(s) resolved and their consistent-model "
            "sets do not intersect%s. The claim below is the most "
            "discriminating single sweep (%s), and the disagreement itself is "
            "the finding - either a knob changes the latch or one sweep is "
            "contaminated."
            % (len(resolved),
               (", and %d admitted no exact model at all" % len(unexplained))
               if unexplained else "",
               cfgname(best_cfgs[0]["cfg"]) if best_cfgs else "?"))

    # The aligned-block / proximity comparison is only meaningful where the
    # sweep actually crossed the boundary in BOTH directions, so it is scored on
    # the densest sweep rather than averaged over the thin wait-state cells --
    # on a sweep of non-negative offsets alone the two models are identical by
    # construction, and averaging them in manufactures a false tie.
    dense = max(best_cfgs, key=lambda v: len(v["rr"]))
    n_neg = sum(1 for off in dense["rr"] if off < 0)
    rival = dense["fit_distance"]["score"]
    mine = dense["fit"]["score"]
    if n_neg == 0:
        caveats.append(
            "The densest offset sweep has no negative offsets, so an aligned "
            "block and a 'within +/-g bytes' proximity rule are the same "
            "prediction and this claim cannot tell them apart.")
    elif rival >= mine:
        caveats.append(
            f"A 'within +/-{g} bytes' proximity model fits the same sweep as well "
            f"({rival:.0%} vs {mine:.0%}). The two are only separable with "
            f"negative offsets or by moving the target's own alignment; if the "
            f"sweep had no negative offsets, this claim cannot distinguish an "
            f"aligned block from a distance.")
    else:
        ev.append(f"  aligned-block model {mine:.0%} vs proximity model "
                  f"{rival:.0%} over {len(dense['rr'])} offsets ({n_neg} of them "
                  f"negative) - it is a latch holding one aligned {g}-byte "
                  f"flash word, not a +/-{g} byte neighbourhood")

    # Depth, from `evict` at a spacing that lands in the same entry.
    depth = UNKNOWN
    depth_ev = []
    for v in best_cfgs:
        tab = _evict_deltas(ms, v["cfg"])
        sp = g * k
        if sp in tab:
            n, det = _n_evict(tab[sp], _miss_scale(ms, v["cfg"]))
            if det:
                depth_ev.append((v["cfg"], sp, n))
    if depth_ev:
        cands = {n for _, _, n in depth_ev}
        if len(cands) == 1:
            depth = depth_ev[0][2]
            ev.append(f"  depth: {depth} - at spacing {g*k} B (which maps to the "
                      f"same entry) the target is lost after {depth} intervening "
                      f"distinct word(s), in {len(depth_ev)} config(s)")
        else:
            caveats.append(f"Depth did not agree across configs: {sorted(cands)}.")
    else:
        caveats.append("Depth not determined: no `evict` series at spacing "
                       f"{g*k} B in a config where the latch resolved.")

    if k > 1:
        sp2 = g
        for v in best_cfgs:
            tab = _evict_deltas(ms, v["cfg"])
            if sp2 in tab:
                n, det = _n_evict(tab[sp2], _miss_scale(ms, v["cfg"]))
                if det:
                    ev.append(f"  entries are independent: walking at spacing {g} B "
                              f"(alternating entries) survives to n={n}, against "
                              f"n={depth} at spacing {g*k} B")
                    break

    # Which knobs reach it.  Only DEVICE configurations count: a configuration
    # whose probe loop lives in the memory under test is the instrument
    # confounding itself, and reading it as "a register reaches the latch" is
    # exactly the error the L552 produced.
    all_fast = [v for v in per_cfg.values() if v["state"] == "all-hit"]
    if silent:
        caveats.append(
            "%d configuration(s) are SILENT on this claim rather than evidence "
            "for or against it: %s. In each the positive control fails - %s - "
            "so the flat column they produced is the resolution floor, not a "
            "register. A configuration that could not have shown the opposite "
            "does not get a vote."
            % (len(silent), ", ".join(cfgname(c) for c in silent[:4])
               + (" ..." if len(silent) > 4 else ""),
               _discriminating_power(ms, silent[0]).reason))
    no_reuse = [v for v in per_cfg.values()
                if v["state"] == "no-reuse" and _is_isolated(ms, v["cfg"])]
    confounded_no_reuse = [v for v in per_cfg.values()
                           if v["state"] == "no-reuse" and not _is_isolated(ms, v["cfg"])]
    flat = [v for v in per_cfg.values() if v["state"] == "flat"]
    if confounded_no_reuse:
        caveats.append(
            "%d configuration(s) show no data-side reuse at any offset - but in "
            "every one of them the probe loop is resident in the memory under "
            "test (%s), so what vanished is the measurement, not the latch. They "
            "are excluded from 'does a register reach it', and they are the "
            "reason a run with the loop in flash reports the exact negation of "
            "the truth on a part with a unified cache."
            % (len(confounded_no_reuse),
               ", ".join(cfgname(v["cfg"]) for v in confounded_no_reuse[:3])))
    reaches: Any
    if no_reuse:
        reaches = [cfgname(v["cfg"]) for v in no_reuse]
        knob_note = (f"{len(no_reuse)} knob setting(s) show no data-side reuse at "
                     f"any offset, including offset 0 - there a register DOES "
                     f"reach the latch, or disables the path that serves it: "
                     + ", ".join(reaches[:4]))
        caveats.append(knob_note)
        reachable = True
    else:
        reachable = False
        ev.append(f"  no knob setting removed it: the latch resolved in "
                  f"{len(resolved)} setting(s) and in the remaining "
                  f"{len(all_fast) + len(flat)} the probe read uniformly *fast*, "
                  f"which is a larger structure masking it, not its absence")

    if all_fast:
        caveats.append(
            f"{len(all_fast)} knob setting(s) re-read fast at every offset. That "
            f"is consistent with both the latch and a cache holding both probe "
            f"addresses, so those settings do not discriminate; the latch is "
            f"inferred there, not measured.")

    # Sub-cycle corroboration from `alt`.
    alt_ev = _alt_differential(ms, best_cfgs[0]["cfg"], g, k, a)
    if alt_ev:
        ev.append("  " + alt_ev)

    # An INVARIANT on the assembled claim, not a cosmetic one: `equivalent
    # models` is the family the evidence leaves standing, and `model_determined`
    # says whether that family is a single model.  The two are two readings of
    # one fact and must never be assembled independently - the nRF52840
    # shipped `model_determined: False` beside an EMPTY family, which asserts
    # both that the answer is undecided and that nothing is a candidate.  The
    # family always contains at least the model being reported.
    if not pairs:
        pairs = [(g, k)]
    determined = len(pairs) == 1 and not contradiction

    value = {"present": True, "granularity_bytes": g, "entries": k,
             "depth": (None if isinstance(depth, _Unknown) else depth),
             "indexed_on": (f"address bits [{int(math.log2(g*k))-1}:{int(math.log2(g))}]"
                            if k > 1 else None),
             "knob_reaches_it": reachable,
             "model_determined": bool(determined),
             "equivalent_models": ["%dBx%d" % gk for gk in pairs],
             "differential_cycles": round(dense["differential"], 3),
             "differential_at": cfgname(dense["cfg"])}
    if contradiction or ambiguous:
        conf = LOW
    else:
        conf = HIGH if (exact and len(best_cfgs) >= 2
                        and depth is not UNKNOWN) else (MED if exact else LOW)
    return Claim("latch", value, conf,
                 "reread sweep (read A, read A+off, re-read A) fitted against a "
                 "model family {granularity g, entries k, index = (A>>log2 g) mod "
                 "k, target alignment a}; depth from `evict` at a spacing that "
                 "maps to the same entry; reachability by repeating the sweep at "
                 "every knob combination",
                 ev, caveats,
                 {"per_config": {cfgname(v["cfg"]): v["state"] for v in per_cfg.values()},
                  "fit_score": mine, "rival_distance_score": rival,
                  "align": a})


def _alt_differential(ms: MeasurementSet, cfg: Config, g: int,
                      k: int = 1, a: int = 0) -> Optional[str]:
    """`alt` accumulates the same effect over many reps -> sub-cycle resolution."""
    rows = {tuple(o.args): o for o in ms.rows("alt", "flash", cfg)}
    if not rows:
        return None
    base = None
    for (off, reps), o in rows.items():
        if off == 0:
            base = (o.cycles, reps)
    if base is None:
        return None
    for (off, reps), o in sorted(rows.items()):
        # The comparison offset has to be one the fitted model says is a MISS.
        # With two entries the first offset past `g` is a hit in the other
        # entry, and comparing against it reports a 0.000-cycle differential.
        if _latch_predict(off, g, k, a) and reps == base[1] and reps > 1:
            per = (o.cycles - base[0]) / reps
            return (f"sub-cycle cross-check: `alt` off={off} over {reps} reps gives "
                    f"{per:.3f} cyc/iteration against off=0, at 1/{reps}-cycle "
                    f"resolution (single-shot `reread` sits on the counter's floor)")
    return None


# ==========================================================================
# 3. cache
# ==========================================================================

_HITS_CACHE = {}


def _conflict_hits(sp: int, line: int, sets: int, want: int, cap: int):
    """The walk indices at which a *new* conflicting line lands in the target's set.

    `evict n spacing` reads the target T (aligned), then T+sp, T+2sp, ... T+n*sp,
    then re-reads T.  T is lost once `ways` distinct OTHER lines that map to T's
    set have been touched.  This enumerates those indices exactly, with no
    closed-form special-casing for `sp < line`, `sp = line` or aliasing spacings,
    so one predictor covers the whole surface.
    """
    key = (sp, line, sets, want, cap)
    hit = _HITS_CACHE.get(key)
    if hit is not None:
        return hit
    period = sets * line
    seen, out, i = set(), [], 1
    while i <= cap and len(out) < want:
        a = i * sp
        if a % period < line:            # lands in a line of the target's set
            blk = a // period
            if blk != 0 and blk not in seen:
                seen.add(blk)
                out.append(i)
        i += 1
    _HITS_CACHE[key] = out
    return out


def _n_evict_pred(sp: int, ways: int, sets: int, line: int, cap: int):
    hits = _conflict_hits(sp, line, sets, ways, cap)
    return hits[ways - 1] if len(hits) >= ways else None


def _fit_cache(measured, line: int, cap: int = 4096):
    """Fit (ways, sets) to N_evict(spacing) at a FIXED line size.

    The line is fixed deliberately, and this is the load-bearing honesty in the
    cache inference.  An eviction surface constrains the **conflict period**
    `sets x line` and the **ways**, and nothing in this protocol separates the
    two factors of that product: an N-way cache with S sets of L-byte lines
    behaves identically, under every primitive here, to an N-way cache with S/2
    sets of 2L-byte lines whose fill unit is L.  So the fit is run at the finest
    line the measurements justify - the fetch granularity - and the ambiguity
    is reported rather than resolved by preference.
    """
    if not measured:
        return None
    best = None
    pts = {sp: v for sp, v in measured.items() if sp >= line}
    if len(pts) < 2:
        return None
    for ways in (1, 2, 4, 8, 16, 32, 64):
        for log_sets in range(0, 15):
            sets = 1 << log_sets
            ok, err = 0, 0.0
            for sp, (n, determined) in pts.items():
                pred = _n_evict_pred(sp, ways, sets, line, cap)
                if determined is True:
                    if pred == n:
                        ok += 1
                    else:
                        err += abs(math.log(((pred or cap) + 0.5) / (n + 0.5)))
                elif determined == "upper":
                    # `N_evict <= n`: the target was lost by n, but nothing
                    # above n confirms where.
                    if pred is not None and pred <= n:
                        ok += 1
                    else:
                        err += abs(math.log((((pred or cap)) + 0.5) / (n + 0.5))) + 0.5
                else:
                    if pred is None or pred > n:
                        ok += 1
                    else:
                        err += abs(math.log((pred + 0.5) / (n + 0.5))) + 0.5
            cand = (ok, -err, -(ways * sets), ways, sets)
            if best is None or cand[:3] > best[:3]:
                best = cand
    if best is None:
        return None
    ok, negerr, _, ways, sets = best
    n_exact = sum(1 for sp, (n, determined) in pts.items()
                  if determined is True
                  and _n_evict_pred(sp, ways, sets, line, cap) == n)
    # Every (ways, sets) that explains the surface exactly as well.  A uniform
    # stride walk revisits one set, so `ways` conflicts in an S-set cache and
    # `ways/2` conflicts in a 2S-set cache land at the same walk index: the two
    # are separable only by a spacing at or above the LARGER conflict period,
    # which a probe region may simply be too small to reach.
    alts = []
    for w2 in (1, 2, 4, 8, 16, 32, 64):
        for ls2 in range(0, 15):
            s2 = 1 << ls2
            ok2, err2 = 0, 0.0
            for sp, (n, determined) in pts.items():
                pred = _n_evict_pred(sp, w2, s2, line, cap)
                if determined is True:
                    ok2 += 1 if pred == n else 0
                    err2 += 0 if pred == n else 1
                elif determined == "upper":
                    good = pred is not None and pred <= n
                    ok2 += 1 if good else 0
                    err2 += 0 if good else 1
                else:
                    good = pred is None or pred > n
                    ok2 += 1 if good else 0
                    err2 += 0 if good else 1
            if ok2 == ok and err2 == 0 and -negerr == 0:
                alts.append((w2, s2))
    if (ways, sets) not in alts:
        alts.append((ways, sets))
    alts = sorted(set(alts))
    return {"ways": ways, "sets": sets, "line": line,
            "period": sets * line,
            "capacity_bytes": ways * sets * line,
            "capacity_entries": ways * sets,
            "alternatives": alts,
            "ways_unique": len({a[0] for a in alts}) == 1,
            "capacity_unique": len({a[0] * a[1] * line for a in alts}) == 1,
            "exact": ok, "pinned": n_exact,
            "total": len(pts), "score": ok / max(1, len(pts)),
            "err": -negerr}


def _span_capacity(tab: Dict[int, Dict[int, float]], scale: float):
    """Capacity from the working-set SPAN at which the target is first lost.

    An instrument that does not need `N_evict` to be a threshold at all, and
    the one that gets the H723 right.

    For a `(ways W, sets S, line L)` cache and a uniform walk at spacing `sp`,
    the target is lost once `W` other lines have landed in its set.  Those
    arrive every `P / gcd(sp, P)` steps, `P = S x L`, so the loss happens after

        n = W x P / gcd(sp, P)   steps, i.e. a SPAN of
        n x sp = W x P x sp / gcd(sp, P)  >=  W x P = the capacity,

    with equality for every spacing that divides the period.  So the smallest
    loss span anywhere on the surface IS the capacity, whatever the (W, S, L)
    split - and it is read off the surface directly, with no fit.

    That matters because the minimum is robust to exactly what the H723 does
    to a threshold fit: retention just ABOVE capacity is not monotone there
    (the target survives 1025 lines at one spacing and is lost after 64 at
    another), and `N_evict` per spacing is not a number.  The smallest loss
    span uses none of that - it uses only the bottom edge, where every
    measurement agrees.

    Measured: 128 B on the F429, 256 B on the G474, 8192 B on the L552 and
    32768 B on the H723, each exactly the published capacity, and on the H723
    with 417 rows below it that never lose the target.
    """
    miss, hit = [], []
    for sp, series in tab.items():
        for n, d in series.items():
            if n <= 0:
                continue
            (miss if _classify_delta(d, scale) == "slow" else hit).append(
                (n * sp, sp, n))
    if not miss:
        return None
    lo = min(miss)
    below = [h for h in hit if h[0] < lo[0]]
    return {"capacity": lo[0], "spacing": lo[1], "n": lo[2],
            "clean": max((h[0] for h in below), default=0),
            "rows_below": len(below),
            "misses_below": 0}


def _geometry_family(capacity: int, line: int):
    """Every `(ways, sets)` whose product with the line is this capacity.

    A uniform-stride walk cannot separate them: for every spacing at or below
    the conflict period the loss lands at the same SPAN, so `ways` traded
    against `sets` at constant capacity is invisible.  Separating them needs a
    spacing ABOVE the period, where the loss span grows to `ways x spacing` --
    which is a statement about how big a probe region the shim must expose.
    """
    out = []
    for w in (1, 2, 4, 8, 16, 32, 64):
        if capacity % (w * line) == 0 and capacity // (w * line) >= 1:
            out.append((w, capacity // (w * line)))
    return out


def infer_cache(ms: MeasurementSet, latch: Claim, width: Claim,
                fill: Optional[Claim] = None) -> Claim:
    ev: List[str] = []
    caveats: List[str] = []
    has_latch = latch.known and latch.value.get("present")
    latch_g = latch.value["granularity_bytes"] if has_latch else 0
    latch_depth = (latch.value.get("depth") or 1) if has_latch else 1

    # The line used for the fit is the measured FETCH granularity: the stride at
    # which a cold walk saturates with reuse enabled, falling back to the array's
    # read width.  Anything coarser is not measured, it is assumed.
    fetch = None
    if fill is not None and fill.known:
        fetch = fill.value
    if fetch is None and width.known:
        fetch = width.value
    if fetch is None:
        return Claim("cache", UNKNOWN, NONE_, "eviction-surface fit", [],
                     ["No read width was resolved, so the eviction surface has no "
                      "line to be fitted at."])

    per_cfg = {}
    silent: List[Config] = []
    for cfg in ms.configs():
        tab = _evict_deltas(ms, cfg)
        scale = _miss_scale(ms, cfg)
        pw = _discriminating_power(ms, cfg)
        if not tab or scale < 0.5 or not pw.ok:
            if tab and not pw.ok:
                silent.append(cfg)
            per_cfg[cfgkey(cfg)] = {"cfg": cfg, "state": "flat", "tab": tab}
            continue
        measured, nmax, shapes = {}, {}, {}
        for sp, series in tab.items():
            sh = _evict_shape(series, scale)
            if sh is None:
                continue
            shapes[sp] = sh
            nmax[sp] = max(series)
            if sh["status"] == "threshold":
                measured[sp] = (sh["n"], True)
            elif sh["status"] == "uncorroborated":
                measured[sp] = (sh["n"], "upper")
            elif sh["status"] == "survived":
                measured[sp] = (sh["n"], False)
            # `non_monotone` contributes nothing: the model it would be fitted
            # against is the one its own data falsifies.
        per_cfg[cfgkey(cfg)] = {"cfg": cfg, "state": "ok", "scale": scale,
                                "measured": measured, "nmax": nmax, "tab": tab,
                                "shapes": shapes,
                                "broken": [sp for sp, sh in shapes.items()
                                           if sh["status"] == "non_monotone"]}

    usable = [v for v in per_cfg.values() if v["state"] == "ok" and v["measured"]]
    if not usable:
        return Claim("cache", UNKNOWN, NONE_,
                     "`evict n spacing`: read A, touch n addresses `spacing` apart, "
                     "re-read A; N_evict(spacing) fitted against an exact model of "
                     "which walk addresses land in the target's set",
                     [], ["No knob setting produced a usable eviction surface."])

    fits = []
    for v in usable:
        cap = max(max(v["nmax"].values(), default=64) * 2, 128)
        f = _fit_cache(v["measured"], fetch, cap)
        if f:
            v["fit"] = f
            fits.append((v, f))
    if not fits:
        return Claim("cache", UNKNOWN, NONE_, "eviction-surface fit", [],
                     ["The eviction surface did not admit a (ways, sets) fit."])

    def reuse(v):
        return max(n for n, _ in v["measured"].values())

    # Most reuse first, and among equals the ISOLATED configuration: the
    # headline geometry is what every later claim is sized from (the policy
    # probes take their spacing and associativity from it), so it must not be
    # a cell whose probe loop shares the structure under test.
    fits.sort(key=lambda vf: (reuse(vf[0]), _is_isolated(ms, vf[0]["cfg"]),
                              vf[1]["capacity_bytes"]), reverse=True)
    top_v, top_f = fits[0]

    for v, f in fits:
        ev.append("  " + cfgname(v["cfg"]) + ": N_evict " +
                  " ".join("%d:%d%s" % (sp, n, "" if det else "+")
                           for sp, (n, det) in sorted(v["measured"].items())) +
                  "  -> %d-way, conflict period %d B, %d B (%d/%d exact)"
                  % (f["ways"], f["period"], f["capacity_bytes"], f["exact"], f["total"]))

    if top_f["capacity_entries"] <= latch_depth and top_f["period"] <= max(latch_g, fetch):
        return Claim("cache", {"present": False}, HIGH,
                     "eviction-surface fit; the best fit has the capacity and "
                     "granularity of the latch already claimed, so there is no "
                     "multi-line structure above it",
                     ev,
                     ["No data-side cache: in every knob setting the target is "
                      "lost after the latch's own depth. Reuse that is not "
                      "back-to-back is not retained anywhere."],
                     {"per_config": dict((cfgname(v["cfg"]), f) for v, f in fits)})

    period, ways = top_f["period"], top_f["ways"]

    # ---- does the threshold model hold in the headline configuration? ----
    #
    # `N_evict(spacing)` is a number only where retention is a threshold in
    # the working-set size.  Where a FAST reading sits above a slow one the
    # series is not a step, and every quantity the fit derives from it - ways,
    # sets, conflict period, capacity - is a fit to a model the data has
    # already falsified.  The H723 is that case: at spacing 4096 B the target
    # is lost at n = 9, present at 10, lost at 11 and present at 12, each
    # reading stable over all seven repeats.  Fitting it anyway produced
    # "1-way, 2048 sets, 65536 B" against a CCSIDR-read 4-way, 256-set,
    # 32768 B cache, at `low` confidence but as a definite number.
    replay = _replay_disagreements(ms)
    warmup = [w for w in (ms.meta.get("warnings") or [])
              if "warm-up outlier" in w and "evict" in w]
    if warmup:
        caveats.append(
            "%d `evict` row(s) in this capture had their DISCARDED warm-up "
            "repetition disagree with the kept ones, in both directions "
            "(e.g. %s). The discarded value is not in `obs[].raw`, so the "
            "kept repeats read `min == max` for rows the instrument itself "
            "reported as unstable. Every eviction-derived number here is a "
            "median of a filtered sample, and `min == max` on these rows is "
            "not evidence of reproducibility."
            % (len(warmup), warmup[0]))
    broken = sorted(top_v.get("broken") or [])
    if replay:
        cfgr, argsr, a_, b_ = replay[0]
        caveats.append(
            "The REPLAY CONTROL failed: %d `evict` row(s) re-measured later in "
            "the programme, in the opposite order, did not come back the same "
            "number - e.g. %s evict%s read %g and then %g. The probe's result "
            "is therefore not a function of its arguments alone but of what ran "
            "before it, so the eviction surface is not a measurement of a "
            "geometry and none is reported. Protocol rule 2 (a fixed warm-up "
            "before every timed access) is not sufficient on a part whose data "
            "cache is large: one warm-up access cannot restore tens of "
            "kilobytes of cache state."
            % (len(replay), cfgname(cfgr), argsr, a_, b_))
    if broken:
        sh = top_v["shapes"][broken[0]]
        caveats.append(
            "The eviction surface in %s is NOT a step function, so no "
            "(ways, sets, line) geometry is reported from it. At spacing %d B "
            "the target is lost at n = %d and present again at n = %s; %d of "
            "%d spacings behave that way. A threshold model is what `N_evict` "
            "means, and this configuration's own data falsifies it, so the "
            "ways, the sets and the conflict period are `unknown` rather than "
            "a fit to a model that does not hold. The CAPACITY survives, "
            "because it is read off the smallest loss span rather than "
            "fitted: that uses only the bottom edge of the surface, below "
            "every non-monotone row."
            % (cfgname(top_v["cfg"]), broken[0], sh["n"],
               ", ".join(str(x) for x in sh["recovered"][:3]),
               len(broken), len(top_v["shapes"])))
        # Reproducibility is the discriminator between the two explanations,
        # and it is in the capture: a pseudo-random victim would not repeat.
        agree = _repeats_agree(ms)
        caveats.append(
            "Two things look like this and they are not the same finding: a "
            "NON-DETERMINISTIC victim choice (the target survives past "
            "capacity some of the time), or an address-dependent effect the "
            "(ways, sets, line) family cannot express (the outcome depends on "
            "WHICH lines the walk ends on, not how many). They are separable "
            "by repeatability, and "
            + ("this capture cannot settle it: its own warnings record the "
               "DISCARDED warm-up repetition disagreeing with the kept ones "
               "on `evict` rows, so `min == max` over the stored repeats is a "
               "statement about a filtered sample. The replay control - the "
               "same row re-measured later and in the opposite order - is "
               "what settles it, not more repeats of one row."
               if agree is None else
               "every repeat of every `evict` row here agrees, which a random "
               "victim would not do. That points at the geometry model rather "
               "than at a random replacement policy."
               if agree is True else
               "the repeats here disagree, which is the signature of a "
               "non-deterministic victim rather than of a model that does not "
               "fit."))
    model_holds = not broken and not replay

    # ---- capacity, from the span instrument rather than from the fit ----
    #
    # `_span_capacity` reads the capacity off the bottom edge of the surface:
    # the smallest working-set SPAN at which the target is ever lost.  That
    # number is the capacity for every (ways, sets, line) split, needs no fit,
    # and it does not need `N_evict` to be a threshold, because
    # it uses only measurements at or below the first loss, where the whole
    # surface agrees.
    #
    # It replaces a floor that was wrong in two ways at once: counted in
    # ACCESSES (which made the F429's floor 512 B against its own measured
    # 128 B capacity, because at a sub-line spacing four accesses share a line
    # and the first few are the target's own) and taken from the LARGEST
    # survival at any spacing (which on the H723 gave 49184 B for a cache the
    # CCSIDR says is 32768, because the target survives 1536 lines at one
    # spacing and is lost after 9 at another).
    line_b = top_f["line"]
    span = _span_capacity(top_v["tab"], top_v["scale"])
    if span:
        cap_bytes = span["capacity"]
        cap_min = span["clean"]
        entries_min = cap_min // line_b
        floor_why = ("the target is first lost at a working-set span of %d B "
                     "(spacing %d B, n = %d) and is never lost below that in "
                     "%d further rows, the largest of which spans %d B. For a "
                     "uniform walk the loss span is `ways x sets x line` for "
                     "every spacing that divides the conflict period, so that "
                     "smallest loss span IS the capacity, whatever the (ways, "
                     "sets) split"
                     % (span["capacity"], span["spacing"], span["n"],
                        span["rows_below"], span["clean"]))
    else:
        # Never lost anywhere: the capacity is not measured, but the largest
        # working set the target lived through is still a floor, and this time
        # it is one - nothing above it contradicts it, because there is no
        # "above it".
        cap_bytes = None
        cap_min = max((n * sp for sp, ser in top_v["tab"].items()
                       for n in ser), default=0)
        entries_min = cap_min // line_b
        floor_why = ("not measured: the target was never lost at any working "
                     "set this region admits, so the capacity is bounded only "
                     "below, at more than %d B - the largest span the probe "
                     "could reach" % cap_min)

    # Where the (ways, sets) fit also held, the two instruments must agree.
    if span and model_holds and top_f.get("capacity_unique")             and top_f["capacity_bytes"] != span["capacity"]:
        caveats.append(
            "The two capacity instruments disagree: the eviction-surface fit "
            "gives %d B and the smallest loss span gives %d B. The span is "
            "the one that needs no model, so it is reported; the difference "
            "is worth understanding before either is trusted."
            % (top_f["capacity_bytes"], span["capacity"]))

    # ---- is the (ways, sets) split even determined? --------------------
    if not top_f.get("ways_unique", True):
        alts = top_f["alternatives"]
        need_sp = max(a[1] for a in alts) * top_f["line"]
        need_n = max(a[0] for a in alts)
        caveats.append(
            "Associativity is NOT determined by this capture. "
            + ", ".join("%d-way x %d sets" % (w, st_) for w, st_ in alts)
            + " predict the same N_evict at every spacing measured, because a "
              "uniform-stride walk revisits a single set: %d conflicts in an "
              "S-set cache and %d in a 2S-set cache land at the same walk index. "
              "Separating them needs a walk of %d addresses at spacing %d B, "
              "i.e. a probe region of at least %d B - larger than the one this "
              "shim exposes."
            % (need_n, need_n // 2 if need_n > 1 else 1, need_n, need_sp,
               need_n * need_sp + need_sp))
        if top_f.get("capacity_unique"):
            ev.append("  capacity is determined even where the associativity is "
                      "not: every (ways, sets) that fits gives %d B"
                      % top_f["capacity_bytes"])
        else:
            caveats.append(
                "Total capacity is NOT determined either, for the same reason. "
                "What IS measured is a floor: %s." % floor_why)

    # ---- indexed or fully associative ---------------------------------
    MAX_PLAUSIBLE_LINE = 64
    if not top_f.get("ways_unique", True) or not model_holds:
        fully = UNKNOWN
    elif period == fetch:
        fully = True
        ev.append("  fully associative: the conflict period (%d B) equals the "
                  "fetch granularity, so one line IS the whole index space - "
                  "N_evict is flat at %d for every spacing from %d B upward and "
                  "no address bits select a set" % (period, ways, fetch))
    elif period > MAX_PLAUSIBLE_LINE:
        fully = False
        ev.append("  indexed: N_evict collapses to %d at spacings that are "
                  "multiples of %d B and is larger in between. No cache line is "
                  "%d B, so that is an index period and the index is address "
                  "bits [%d:%d]"
                  % (ways, period, period, int(math.log2(period)) - 1,
                     int(math.log2(fetch))))
    else:
        fully = UNKNOWN
        family = [(period // l, l) for l in (fetch, 2 * fetch, 4 * fetch, 8 * fetch)
                  if l <= period and period % l == 0]
        caveats.append(
            "Indexed versus fully associative is NOT decided here, and the "
            "conflict period (%d B) is small enough to be a single cache line. "
            "Every geometry with sets x line = %d predicts the same number for "
            "every primitive in this protocol: " % (period, period)
            + ", ".join("%d-way x %d sets x %d B line" % (ways, s, l)
                        for s, l in family)
            + " - including '%d fully-associative %d B tags'. Separating them "
              "needs a probe that distinguishes 'two words of one line' from "
              "'two lines of one set', e.g. a random-access working set swept "
              "across its alignment (the G474 'tent' measurement), and "
              "`memmap/1` has no mode for that." % (ways, period))
        ev.append("  conflict period %d B with a %d B fetch: the geometry is "
                  "determined only up to sets x line = %d" % (period, fetch, period))

    # ---- capacity in tags/sets versus capacity in bytes ----------------
    n_at_period = top_v["measured"].get(period)
    slots = top_f["capacity_bytes"] // max(1, fetch)
    if n_at_period and n_at_period[1] and slots != ways:
        got = n_at_period[0]
        verdict = "tags" if got == ways else ("bytes" if got == slots else "neither")
        ev.append("  tags vs bytes at spacing %d B (one word of each of n fresh "
                  "lines): measured N_evict = %d; a conflict structure predicts "
                  "%d, a flat budget of %d B / %d B = %d independent word slots "
                  "predicts %d -> %s"
                  % (period, got, ways, top_f["capacity_bytes"], fetch, slots,
                     slots, verdict))
        if verdict == "tags":
            ev.append("  -> capacity is a count of TAGS in a set, not a byte "
                      "budget: a tag is claimed whole even when only one word of "
                      "it has ever been fetched")
        else:
            caveats.append(
                "The tags-versus-bytes test came out '%s' (measured %d, tag model "
                "%d, byte model %d). That is unlike every part characterised in "
                "this repository; treat it as a finding to check."
                % (verdict, got, ways, slots))
        capacity_unit = verdict
    else:
        capacity_unit = "not applicable"
        ev.append("  tags vs bytes: with a %d B fetch and a %d B conflict period "
                  "the two models predict the same number (%d), so the test "
                  "cannot discriminate and no claim is made"
                  % (fetch, period, ways))

    # Configurations that fit nothing bigger than the latch have no cache in
    # them at all - that is the cache-enable knob doing its job, not a rival
    # geometry - so they are separated out before anything is called a clash.
    geoms, off_cfgs = {}, []
    for v, f in fits:
        if f["capacity_entries"] <= max(1, latch_depth) and f["period"] <= max(latch_g, fetch):
            off_cfgs.append(v)
            continue
        geoms.setdefault((f["ways"], f["period"], f["capacity_bytes"]), []).append(v)
    if off_cfgs:
        ev.append("  %d configuration(s) hold nothing above the latch at all "
                  "(%s): there the cache is switched off, which is a knob "
                  "working rather than a geometry disagreeing"
                  % (len(off_cfgs),
                     ", ".join(cfgname(v["cfg"]) for v in off_cfgs[:3])
                     + (" ..." if len(off_cfgs) > 3 else "")))
    if len(geoms) > 1:
        # Does ONE knob select between them?  If so this is not an
        # inconsistency, it is the most interesting thing the part does, and
        # filing it as a clash is how the L552's WAYSEL came to be reported as
        # having no effect.
        selector = None
        for knob in ms.knob_names():
            if knob == "waitstates":
                continue
            seen = {}
            ok = True
            for g, vs in geoms.items():
                for v in vs:
                    kv = v["cfg"].get(knob)
                    if seen.setdefault(kv, g) != g:
                        ok = False
                        break
                if not ok:
                    break
            if ok and len(seen) > 1:
                selector = knob
                break
        listing = "; ".join("%d-way/period %d B/%d B in %d config(s)"
                            % (w, pd, cap, len(vs))
                            for (w, pd, cap), vs in sorted(geoms.items()))
        caps = {g[2] for g in geoms}
        if selector and len(caps) == 1:
            ev.append("  `%s` selects between %s - same capacity, different "
                      "index: the knob RE-INDEXES the cache rather than "
                      "resizing it. The headline geometry is the one measured "
                      "in %s" % (selector, listing, cfgname(top_v["cfg"])))
            caveats.append(
                "This part has more than one cache geometry and `%s` chooses "
                "between them at constant capacity (%d B). The headline above "
                "is the geometry of `%s`; the other is in the per-configuration "
                "evidence and in `knob_map`. Neither is more true than the "
                "other." % (selector, next(iter(caps)), cfgname(top_v["cfg"])))
        elif selector:
            caveats.append(
                "More than one geometry fits, and `%s` selects between them: %s. "
                "The headline is the configuration with the most reuse."
                % (selector, listing))
        else:
            caveats.append(
                "Not every knob setting fits the same geometry, and no single "
                "knob separates them: " + listing
                + ". The geometry reported is from the setting with the most "
                  "reuse; settings with less reuse under-constrain the fit "
                  "rather than contradict it, but an unexplained split is worth "
                  "checking before the headline is trusted.")

    family = (_geometry_family(cap_bytes, top_f["line"])
              if (cap_bytes and not (model_holds and top_f.get("ways_unique", True)))
              else [])
    if family:
        biggest_period = max(st_ * top_f["line"] for _, st_ in family)
        # The separating probe: one spacing ABOVE the largest candidate
        # period, where the loss lands at n = ways directly.  Quoted twice --
        # for the whole family, and for the part of it a microcontroller L1
        # plausibly has.  MAX_PLAUSIBLE_WAYS is an architectural prior of the
        # same kind as MAX_PLAUSIBLE_LINE and is stated, not applied silently.
        MAX_PLAUSIBLE_WAYS = 8
        sep_sp = 2 * biggest_period
        need = sep_sp * (max(w for w, _ in family) + 1)
        plausible = [w for w, _ in family if w <= MAX_PLAUSIBLE_WAYS]
        need_small = sep_sp * (max(plausible) + 1) if plausible else need
        caveats.append(
            "The capacity is measured (%d B) and the (ways, sets) split is "
            "NOT: %s all predict the same loss span at every spacing this "
            "capture used, because a uniform walk at or below the conflict "
            "period loses the target after exactly `ways x sets x line` bytes "
            "however the two factors divide it. Separating them needs a "
            "spacing ABOVE the largest candidate period (%d B), where the "
            "loss lands at n = ways directly: `evict n %d` with n reaching "
            "%d, i.e. a probe region of at least %d B - or %d B to separate "
            "only the associativities an L1 plausibly has (<= %d-way, an "
            "architectural prior, stated here rather than applied silently). "
            "This shim's `evict` reaches %d B. The published geometry of this "
            "part is in the family; the tool does not pick from it."
            % (cap_bytes,
               ", ".join("%d-way x %d sets" % (w, st_) for w, st_ in family),
               biggest_period, sep_sp, max(w for w, _ in family), need,
               need_small, MAX_PLAUSIBLE_WAYS,
               max((n * sp for sp, ser in top_v["tab"].items() for n in ser),
                   default=0)))
    conf = LOW if not model_holds else (
        HIGH if top_f["score"] >= 0.95 and top_f["total"] >= 4 else
        (MED if top_f["score"] >= 0.8 else LOW))
    ev.append("  capacity floor: " + floor_why)
    if cap_min is None:
        caveats.append("No capacity floor is reported: " + floor_why[15:] + ".")
    ways_known = top_f.get("ways_unique", True) and model_holds
    cap_known = bool(top_f.get("capacity_unique", True)) and model_holds
    value = {"present": True,
             "ways": ways if ways_known else None,
             "ways_candidates": ([a[0] for a in top_f.get("alternatives", [])]
                                 if model_holds else
                                 [w for w, _ in family]),
             "geometry_candidates": ["%d-way x %d sets x %d B line"
                                     % (w, st_, top_f["line"])
                                     for w, st_ in family],
             "conflict_period_bytes": period if ways_known else None,
             "capacity_bytes": (top_f["capacity_bytes"] if (cap_known and span is None)
                                else cap_bytes),
             "capacity_bytes_min": cap_min,
             "line_bytes": top_f["line"],
             "sets": top_f["sets"] if ways_known else None,
             "capacity_entries": (top_f["capacity_entries"] if (cap_known and span is None)
                                  else (None if cap_bytes is None
                                        else cap_bytes // top_f["line"])),
             "capacity_entries_min": entries_min,
             "fully_associative": (None if isinstance(fully, _Unknown) else fully),
             "geometry_unique": (not isinstance(fully, _Unknown)) and model_holds,
             "threshold_model_holds": model_holds,
             "index_bits": (None if (fully is True or isinstance(fully, _Unknown)
                                     or not model_holds)
                            else "address bits [%d:%d]"
                                 % (int(math.log2(period)) - 1,
                                    int(math.log2(fetch)))),
             "capacity_unit": capacity_unit,
             "enabled_in": cfgname(top_v["cfg"])}
    return Claim("cache", value, conf,
                 "`evict n spacing` over a spacing sweep. N_evict(spacing) is "
                 "fitted against an exact enumeration of which walk addresses land "
                 "in the target's set, which yields the ways and the conflict "
                 "period (sets x line) with no special case for sub-line, "
                 "line-sized or aliasing spacings. The line used is the measured "
                 "fetch granularity; where the period is larger, the split between "
                 "sets and line is reported as undetermined rather than assumed",
                 ev, caveats,
                 {"fit": top_f, "fetch_granularity": fetch,
                  # Only configurations whose own eviction surface IS a step
                  # function export a geometry.  Everything downstream - the
                  # replacement-policy claim, the knob map - reads this table,
                  # and a falsified fit handed on from here is how "1-way"
                  # became "every configuration is direct-mapped, so there is
                  # no policy to infer" at HIGH confidence on the H723.
                  "per_config": dict((cfgname(v["cfg"]), f) for v, f in fits
                                     if not v.get("broken")
                                     and v not in off_cfgs),
                  # Provisional fits, falsified ones included.  A geometry may
                  # not be CLAIMED from these, but the second-pass probes are
                  # SIZED from them: sizing a probe from a wrong geometry
                  # costs a probe that does not fire, while refusing to size
                  # one costs the only instrument that can tell a
                  # non-deterministic victim from a model error.
                  "per_config_sizing": dict((cfgname(v["cfg"]), f)
                                            for v, f in fits),
                  "per_config_broken": sorted(
                      cfgname(v["cfg"]) for v, _ in fits if v.get("broken"))})


# ==========================================================================
# 4. replacement policy
# ==========================================================================

def _step_sharpness(series, scale: float, n_evict: int):
    """How cleanly the eviction series is a step function.

    A deterministic victim choice (LRU, FIFO, or a direct-mapped index) makes
    `N_evict` a hard threshold: every n below it hits, every n at or above it
    misses.  A pseudo-random victim makes survival a coin flip, so the series
    is graded and some large n still hit.  1.0 is a perfect step.
    """
    cls = {n: _classify_delta(d, scale) for n, d in series.items()}
    if not cls:
        return None
    wrong = sum(1 for n, c in cls.items() if (c == "slow") != (n >= n_evict))
    return 1.0 - wrong / len(cls)


def _per_config_geometry(cache: Claim, sizing: bool = False):
    """`cfgname -> fitted (ways, period, capacity)` from the cache claim.

    The headline geometry is the configuration with the most reuse, which is
    not necessarily the configuration a policy probe ran in: on a part whose
    associativity is itself a knob, the direct-mapped setting has no victim to
    choose and the set-associative one does.  Every prediction below is made
    against the geometry of the configuration it is compared with.
    """
    out = {}
    key = "per_config_sizing" if sizing else "per_config"
    table = (cache.data or {}).get(key) or (cache.data or {}).get("per_config", {})
    for name, f in table.items():
        if isinstance(f, dict) and f.get("ways"):
            out[name] = f
    return out


def _lru_fifo_probe(ms: MeasurementSet, cache: Claim):
    """Read the three-argument `evict` rows, if any, as an LRU/FIFO test.

    `evict n spacing -k*spacing` walks THROUGH the target: k conflicting lines,
    then the target itself, then the rest.  The re-touch is a hit, which
    promotes the line under LRU and is invisible under FIFO, so

        LRU  loses the target at n >= ways + k + 1
        FIFO loses it at         n >= ways + 1

    The two predictions differ by exactly k, so a single sweep over n decides
    it - provided `k < ways` (otherwise the target is already gone before the
    re-touch happens), the walk spacing is a multiple of the conflict period of
    THAT configuration (otherwise the walk addresses do not land in the
    target's set at all), and the shim really honoured the third argument,
    which is why `Bench.supports_evict_start` checks the checksum rather than
    the timing.
    """
    geom = _per_config_geometry(cache, sizing=True)
    out = []
    for cfg in ms.configs():
        scale = _miss_scale(ms, cfg)
        if scale < 0.5:
            continue
        f = geom.get(cfgname(cfg))
        if not f:
            continue
        ways, period = f["ways"], f["period"]
        by_k = {}
        for o in ms.rows("evict", "flash", cfg):
            if len(o.args) != 3:
                continue
            n, sp, start = (int(x) for x in o.args)
            if start >= 0 or sp <= 0 or start % sp:
                continue
            if period <= 0 or sp % period:
                continue          # the walk never reaches the target's set
            d = ms.delta(cfg, "evict", o.args)
            if d is None:
                continue
            by_k.setdefault((-start // sp, sp), {})[n] = d
        for (k, sp), series in sorted(by_k.items()):
            if len(series) < 4 or k >= ways:
                continue
            n_evict, det = _n_evict(series, scale)
            if not det:
                continue
            out.append({"cfg": cfg, "k": k, "spacing": sp, "ways": ways,
                        "n_evict": n_evict,
                        "lru": ways + k + 1, "fifo": ways + 1,
                        "isolated": _is_isolated(ms, cfg),
                        "sharp": _step_sharpness(series, scale, n_evict)})
    return out or None


def _chase_knee(ms: MeasurementSet, cache: Claim, cfgs):
    """The cyclic-`chase` working-set knee, where the probe can reach it.

    A cyclic reference string over `m` lines that all map to ONE set thrashes
    completely under LRU and under FIFO once `m > ways`, and only partially
    under a random victim.  That is the whole discriminator, and it has two
    preconditions the tool must check rather than assume:

    * the chase stride must be a multiple of the measured **conflict period**,
      or the nodes land in different sets and nothing ever conflicts.  Emitting
      the chase at a fixed small stride is the failure this replaced: on a part
      whose conflict period is 4 KB, a 16/32/64 B chase never reaches the knee
      and whatever gradient it does show is something else;
    * the two sizes compared must be **adjacent**, or "one line over the knee"
      is not what was measured.
    """
    geom = _per_config_geometry(cache, sizing=True)
    for cfg in cfgs:
        f = geom.get(cfgname(cfg))
        if not f:
            continue
        period = f["period"]
        per_word = _miss_scale(ms, cfg) or 1.0
        if per_word < 0.5 or period <= 0:
            continue
        rates = {}
        for o in ms.rows("chase", "flash", cfg):
            if len(o.args) < 3 or int(o.args[2]) < 2:
                continue
            stride = int(o.args[1])
            if stride <= 0 or stride % period:
                continue
            d = ms.delta(cfg, "chase", o.args)
            if d is None:
                continue
            n, sp, reps = (int(x) for x in o.args[:3])
            rates[n] = max(0.0, d / (n * reps) / per_word)
        if len(rates) < 2:
            continue
        ns = sorted(rates)
        fit_ns = []
        for n in ns:
            if rates[n] <= 0.15:
                fit_ns.append(n)
            else:
                break
        if not fit_ns or fit_ns[-1] == ns[-1]:
            continue
        c_fit = fit_ns[-1]
        n2 = ns[ns.index(c_fit) + 1]
        if n2 != c_fit + 1:
            continue                     # not "one line over the knee"
        # A working set FAR past the knee is the 1.0 reference.  Without it the
        # "one line over" rate has to be compared against a miss cost taken
        # from a different loop body, and that ratio is only good to a few tens
        # of a percent - on the L552 a genuinely thrashing 3-line set over a
        # 2-way cache normalises to 0.75, close enough to the pseudo-random
        # band to be decided by the normalisation rather than by the part.
        # "Far" is measured from the KNEE, not from the fitted associativity:
        # a random victim inflates the fitted ways (the target sometimes
        # survives past capacity), so sizing the reference from `ways` is
        # sizing it from a number the random case has already corrupted.
        far_ns = [n for n in ns if n >= max(2 * c_fit, c_fit + 2)]
        if not far_ns:
            continue
        far = max(rates[n] for n in far_ns)
        if far <= 0.15:
            continue                     # nothing thrashes: no knee was found
        return {"cfg": cfg, "fits": c_fit, "rate_fits": rates[c_fit],
                "over": n2, "rate_over": rates[n2], "per_word": per_word,
                "far": max(far_ns), "rate_far": far,
                "ratio": rates[n2] / far,
                "period": period, "ways": f["ways"]}
    return None


def _repeats_agree(ms: MeasurementSet) -> Optional[bool]:
    """Did every repeated `evict` measurement come back the same number?

    The discriminator between the two things a non-monotone eviction surface
    can mean.  A NON-DETERMINISTIC victim is a coin flip, so its repeats
    disagree; an address-dependent effect the (ways, sets, line) family cannot
    express is perfectly reproducible.  Returns `None` where the capture
    carries no repeat information to judge by.
    """
    # The kept repeats are a FILTERED sample.  `Bench` discards a warm-up
    # repetition before taking the median and records the disagreement as a
    # capture warning - but the discarded value is not in `obs[].raw`, so a
    # row can read min == max here while the capture's own warnings say the
    # first reading of it was different.  On the H723 that is true of 16
    # distinct (n, spacing) pairs, in both directions, and it includes rows
    # whose stored verdict is what breaks monotonicity.  Reading "every
    # repetition agrees" off the kept sample would be reading past the
    # instrument's own report of disagreement, so the warnings veto it.
    warned = [w for w in (ms.meta.get("warnings") or [])
              if "warm-up outlier" in w and "evict" in w]
    if warned:
        return None
    seen = False
    for o in ms.rows("evict", "flash"):
        if o.n and o.n > 1:
            seen = True
            if o.lo != o.hi:
                return False
    return True if seen else None


def infer_policy(ms: MeasurementSet, cache: Claim, width: Claim) -> Claim:
    caveats = [
        "LRU and FIFO are NOT separable with `memmap/1`'s two-argument "
        "primitives, and that is a property of the primitives rather than of "
        "the part. `walk` and `evict` produce a monotone reference string and "
        "`chase` a cyclic one, and on a cyclic string over capacity+1 lines LRU "
        "and FIFO evict exactly the same line at every step. Separating them "
        "needs a reference string that re-touches an already-resident line "
        "before bringing in a new one - which is what the optional third "
        "`evict` argument provides, and what a shim that does not implement it "
        "leaves unreachable.",
    ]
    if not (cache.known and cache.value.get("present")):
        return Claim("replacement_policy", UNKNOWN, NONE_,
                     "step sharpness of the eviction surface, plus a cyclic "
                     "`chase` over capacity and capacity+1 lines",
                     [], caveats + ["No multi-line cache was found, so there is "
                                    "no replacement policy to infer: a 1-entry "
                                    "latch has no victim to choose."])
    ev: List[str] = []
    geom = _per_config_geometry(cache)

    # ---- 0. is there a victim to choose at all? -------------------------
    #
    # "Direct-mapped, so there is no policy" is a POSITIVE claim about the
    # part, and it may only be made from configurations that could have shown
    # associativity: ones where a multi-line structure exists and where the
    # eviction surface is a step function, so `ways` means something.  The
    # H723 reported it at HIGH confidence from a `ways = 1` that came out of a
    # fit to a model its own data falsifies, and from cells with the cache
    # switched off, which have no ways to count.
    model_broken = not cache.value.get("threshold_model_holds", True)
    if model_broken:
        # A non-monotone eviction surface is EVIDENCE about the policy, not a
        # reason to stop: a victim that is not a deterministic function of the
        # working-set size is exactly what "pseudo-random" means.  So the
        # probes below are sized from the provisional geometry and allowed to
        # speak; what may not happen is a `not_applicable` verdict taken from
        # a `ways` the same data falsifies.
        agree = _repeats_agree(ms)
        ev.append("  the eviction surface is not monotone in the working-set "
                  "size in the configuration with the most reuse, and every "
                  "repeat of those rows %s"
                  % ("agrees (min == max)" if agree is True else
                     "does NOT agree" if agree is False else
                     "carries no repeat information"))
        caveats.append(
            "The cache claim reports no geometry here, so nothing below is "
            "sized from a measured associativity - the probes are sized from "
            "a provisional fit and fire only if it happens to be close. Read "
            "a negative result as 'the instrument did not run', not as a "
            "property of the part."
            + (" And the repeats cannot settle what the non-monotonicity "
               "means: this capture's own warnings record the DISCARDED "
               "warm-up repetition disagreeing with the kept ones on several "
               "`evict` rows, so `min == max` over the kept sample is not "
               "evidence that the measurement is reproducible. What settles "
               "it is the replay control - the same row re-measured later "
               "and in the opposite order - not more repeats of one row."
               if agree is None else
               " And note what the repeats say: every non-monotone row is "
               "bit-identical across all its repeats, which a random victim "
               "would not be. That points at a geometry the (ways, sets, "
               "line) family cannot express rather than at a random "
               "replacement policy, and `pseudo_random` is not claimed on "
               "the strength of the non-monotonicity alone."
               if agree is True else ""))
    elif cache.value.get("ways") is None:
        caveats.append(
            "The cache geometry is not determined in the configuration with "
            "the most reuse, so the associativity is unknown and with it the "
            "question of whether there is a victim to choose at all. Nothing "
            "below can be read as a statement about a replacement policy: a "
            "`ways` taken from a falsified fit would decide this claim by "
            "itself.")
        return Claim("replacement_policy", UNKNOWN, NONE_,
                     "requires a determined associativity, which the cache "
                     "claim does not have", [], caveats)
    max_ways = max((f["ways"] for f in geom.values()), default=0)
    if geom and max_ways < 2 and not model_broken:
        return Claim("replacement_policy", "not_applicable", HIGH,
                     "the fitted geometry in every configuration measured",
                     ["  every configuration fits %d-way: %s"
                      % (max_ways, ", ".join("%s %d-way/period %d B"
                                             % (n, f["ways"], f["period"])
                                             for n, f in sorted(geom.items())[:4]))],
                     ["A direct-mapped cache has no replacement policy: the "
                      "victim is the line the index selects, and no policy can "
                      "choose otherwise. This is a measurement, not a gap."])

    # ---- 1. is the victim choice deterministic at all? ------------------
    sizing = _per_config_geometry(cache, sizing=True)
    sharp = []
    for cfg in ms.configs():
        tab = _evict_deltas(ms, cfg)
        scale = _miss_scale(ms, cfg)
        if not tab or scale < 0.5 or not _discriminating_power(ms, cfg).ok:
            continue
        f = sizing.get(cfgname(cfg))
        if not f or f["ways"] < 2:
            continue                     # no victim to choose here
        for sp in sorted(tab):
            if sp < f["line"] or f["period"] <= 0 or sp % f["period"]:
                continue                 # only spacings that conflict at all
            n, det = _n_evict(tab[sp], scale)
            if n is None or not det:
                continue
            st = _step_sharpness(tab[sp], scale, n)
            if st is not None:
                sharp.append((cfg, sp, n, st))
    if not sharp:
        caveats.append(
            "No eviction series in a set-associative configuration had both a "
            "determined transition and a spacing that is a multiple of the "
            "measured conflict period, so the step-sharpness instrument did not "
            "run.")
        med = None
    else:
        worst = min(x[3] for x in sharp)
        med = _median([x[3] for x in sharp])
        ev.append("  eviction-step sharpness over %d series at spacings that "
                  "conflict: median %.3f, worst %.3f (1.000 = every n below "
                  "N_evict hits and every n at or above it misses)"
                  % (len(sharp), med, worst))
        for cfg, sp, n, st in sharp[:6]:
            ev.append("    %s spacing %d: N_evict %d, sharpness %.3f"
                      % (cfgname(cfg), sp, n, st))

    # ---- 2. cyclic chase, at a stride the geometry says will conflict ----
    # Isolated configurations only.  With the probe loop resident in the memory
    # under test the loop's own lines occupy sets alongside the data, so a
    # cyclic working set "one step over the knee" is not one step over the knee
    # at all and its partial hit rate is the probe, not the part.
    order = sorted(ms.configs(),
                   key=lambda c: (not _is_isolated(ms, c),
                                  cfgname(c) != cache.value.get("enabled_in", ""),
                                  -(sizing.get(cfgname(c), {}).get("ways") or 0)))
    knee = _chase_knee(ms, cache, [c for c in order
                                   if _is_isolated(ms, c)
                                   and (sizing.get(cfgname(c), {}).get("ways") or 0) >= 2])
    if knee:
        ev.append("  %s: cyclic chase at stride %d B (a multiple of the measured "
                  "%d B conflict period): %d lines -> %.2f miss/access, %d lines "
                  "-> %.2f, %d lines -> %.2f. One line over the knee reaches "
                  "%.0f%% of a full thrash"
                  % (cfgname(knee["cfg"]), knee["period"], knee["period"],
                     knee["fits"], knee["rate_fits"], knee["over"],
                     knee["rate_over"], knee["far"], knee["rate_far"],
                     100 * knee["ratio"]))
    else:
        confounded = _chase_knee(ms, cache,
                                 [c for c in order if not _is_isolated(ms, c)])
        caveats.append(
            "The cyclic-chase discriminator did not run: it needs `chase` at "
            "two ADJACENT working-set sizes with a stride that is a multiple of "
            "the measured conflict period, in an isolated configuration. A "
            "chase whose stride is smaller than the conflict period never "
            "produces a conflict however large the working set, so it cannot "
            "reach the knee; and it needs a third, much larger working set to "
            "calibrate what a full thrash costs%s."
            % ("; the only configuration that did produce one has the probe "
               "loop resident in the memory under test, and its gradient is the "
               "loop's own footprint rather than a replacement policy"
               if confounded else ""))

    # ---- 3. LRU versus FIFO, where the shim offers the walk start -------
    lf = _lru_fifo_probe(ms, cache)
    if lf:
        for row in lf:
            ev.append("  %s: evict walk re-touching the target after k=%d "
                      "conflicts (spacing %d, %d-way) loses it at n=%d; LRU "
                      "predicts %d, FIFO predicts %d  [step sharpness %.3f]"
                      % (cfgname(row["cfg"]), row["k"], row["spacing"],
                         row["ways"], row["n_evict"], row["lru"], row["fifo"],
                         row["sharp"]))
        iso_rows = [r for r in lf if r["isolated"]] or lf
        lru_hits = sum(1 for r in iso_rows if r["n_evict"] == r["lru"])
        fifo_hits = sum(1 for r in iso_rows if r["n_evict"] == r["fifo"])
        if lru_hits == len(iso_rows) and fifo_hits == 0:
            ev.append("  -> every re-touch position lands on the LRU "
                      "prediction and none on the FIFO one. The hit promoted "
                      "the line, so the victim is chosen by recency")
            return Claim("replacement_policy", "lru",
                         HIGH if len(iso_rows) >= 2 else MED,
                         "`evict n spacing -k*spacing` walks THROUGH the target, "
                         "so one access in the middle of the interference is a "
                         "hit. LRU promotes the line and loses it at "
                         "ways+k+1; FIFO ignores the hit and loses it at "
                         "ways+1. The spacing is the measured conflict period "
                         "of that configuration and k is chosen below its "
                         "measured associativity, so the probe is sized from "
                         "the geometry rather than from a constant",
                         ev, caveats[1:] + [
                             "This uses the optional third argument to `evict`, "
                             "which `flashmap/PROTOCOL.md` documents as an "
                             "addendum. The host verifies the shim honours it by "
                             "checking that the CHECKSUM changes, not the timing "
                             "-- a shim that silently ignored the argument would "
                             "return the default walk and read as FIFO."])
        if fifo_hits == len(iso_rows) and lru_hits == 0:
            ev.append("  -> every re-touch position lands on the FIFO "
                      "prediction. The hit did not protect the line, so the "
                      "victim is chosen by insertion order")
            return Claim("replacement_policy", "fifo",
                         HIGH if len(iso_rows) >= 2 else MED,
                         "`evict n spacing -k*spacing`: a hit in the middle of "
                         "the interference protects the line under LRU and not "
                         "under FIFO", ev, caveats[1:])
        caveats.append(
            "The LRU/FIFO probe ran but did not land cleanly on either "
            "prediction (%d of %d rows matched LRU, %d matched FIFO). Neither "
            "is claimed." % (lru_hits, len(iso_rows), fifo_hits))
    else:
        caveats.append(
            "The re-touch probe (`evict n spacing -k*spacing`) contributed no "
            "usable row: either the shim does not honour the optional walk "
            "start, or no row was taken at a spacing that is a multiple of the "
            "measured conflict period with k below the measured associativity. "
            "Without it LRU and FIFO are not separable and neither is claimed.")

    # ---- verdict --------------------------------------------------------
    graded = (med is not None and med <= 0.92)
    # Relative to a working set far past the knee, not to an absolute rate:
    # LRU and FIFO both reach a full thrash one line over, a random victim does
    # not, and the comparison cancels every normalisation constant.
    random_evidence = (knee is not None and knee["ratio"] < 0.75)
    thrash_evidence = (knee is not None and knee["ratio"] >= 0.85)

    if random_evidence or graded:
        caveats.append(
            "A non-deterministic victim also biases the CAPACITY estimate "
            "upward: the target sometimes survives past the true capacity, so "
            "`N_evict` is a quantile of a distribution rather than a threshold. "
            "Read the cache claim's capacity as an upper bound in this "
            "configuration.")
        if random_evidence:
            ev.append("  -> a cyclic working set one line over the knee still "
                      "hits part of the time - %.0f%% of what the same probe "
                      "costs far past the knee, in an isolated configuration at "
                      "a conflicting stride. Neither LRU nor FIFO nor an address "
                      "index can do that: all three are deterministic functions "
                      "of the reference string" % (100 * knee["ratio"]))
        if graded:
            ev.append("  -> the eviction step is graded rather than a "
                      "threshold, which is the same conclusion from the other "
                      "instrument")
        return Claim("replacement_policy", "pseudo_random",
                     HIGH if (random_evidence and graded) else MED,
                     "two instruments: the sharpness of the eviction step, and a "
                     "cyclic `chase` one line past the working-set knee at a "
                     "stride the measured geometry says will conflict, in a "
                     "configuration where the probe loop does not share the "
                     "structure under test. A deterministic victim makes the "
                     "first a hard threshold and the second a complete thrash; "
                     "a random one does neither",
                     ev, caveats)

    if thrash_evidence and med is not None and med >= 0.98:
        ev.append("  -> a cyclic working set one line over the knee misses on "
                  "essentially every access, which is what LRU and FIFO both do "
                  "and what pseudo-random does not")
        return Claim("replacement_policy", "lru_or_fifo", MED,
                     "the eviction step is a clean threshold, so the victim is a "
                     "deterministic function of the reference string; the cyclic "
                     "chase then separates {LRU, FIFO} from pseudo-random, and "
                     "nothing available separates LRU from FIFO",
                     ev, caveats)

    if med is not None and med >= 0.98 and knee is None:
        caveats.append(
            "Only one of the two instruments ran. The eviction step is a clean "
            "threshold, which rules out a random victim, but with no cyclic "
            "chase there is no second opinion.")
        return Claim("replacement_policy", "lru_or_fifo", LOW,
                     "eviction-step sharpness alone", ev, caveats)

    caveats.append(
        "The instruments did not agree, or none of them ran%s, so the policy is "
        "reported as unresolved rather than rounded to the nearer answer."
        % ("" if med is None else
           " (eviction-step sharpness %.3f%s)"
           % (med, "" if knee is None else
              ", chase one line over the knee at %.0f%% of a full thrash"
              % (100 * knee["ratio"]))))
    return Claim("replacement_policy", UNKNOWN, NONE_,
                 "eviction-step sharpness and cyclic chase", ev, caveats)


# ==========================================================================
# 5. which knob controls which structure
# ==========================================================================

def _metric_geometry(ms: MeasurementSet, cfg: Config, scale: float = 0.0,
                     fetch: int = 0):
    """The fitted `(ways, conflict period, capacity)` of this configuration.

    This replaced a scalar `max N_evict`, which is the same number (1024, at
    spacing 8) in both of the L552's `WAYSEL` modes: that knob's entire effect
    is in the SHAPE of `N_evict(spacing)`, so the scalar reported the most
    interesting thing about the part as "no effect".

    This is the knob-map's data-reuse metric.  The eviction surface is fitted
    per configuration and compared as a triple, so the three ways a knob can
    move a cache are distinguishable: it can turn reuse on or off (capacity
    changes), it can resize it (capacity changes), or it can **re-index** it --
    trade associativity against index width at constant capacity, which is what
    the L552's `WAYSEL` does and what a scalar cannot see.
    """
    if not fetch:
        return None
    tab = _evict_deltas(ms, cfg)
    if not tab or scale < 0.5:
        return None
    if not _discriminating_power(ms, cfg).ok:
        return None
    measured, nmax, broken = {}, {}, []
    reuse = 0
    for sp, series in tab.items():
        sh = _evict_shape(series, scale)
        if sh is None:
            continue
        nmax[sp] = max(series)
        if sh["status"] == "non_monotone":
            broken.append(sp)
        elif sh["status"] == "threshold":
            measured[sp] = (sh["n"], True)
        elif sh["status"] == "uncorroborated":
            measured[sp] = (sh["n"], "upper")
        else:
            measured[sp] = (sh["n"], False)
        for n, d in series.items():
            if _classify_delta(d, scale) == "fast":
                reuse = max(reuse, n)
    if broken:
        # The geometry model is falsified here, so this configuration cannot
        # report a triple - but it can still say whether there is reuse at
        # all, which is what a cache-enable knob moves.  Reporting the
        # falsified triple instead is how the H723's `dcache` came to be
        # credited with switching on a 65536 B direct-mapped cache.
        return ("reuse beyond the latch, geometry not determined"
                if reuse > 1 else "no reuse")
    if not measured:
        return None
    cap = max(max(nmax.values(), default=64) * 2, 128)
    f = _fit_cache(measured, fetch, cap)
    if not f:
        return None
    return (f["ways"], f["period"], f["capacity_bytes"])


def _fmt_geometry(g):
    if g is None:
        return "?"
    if not isinstance(g, tuple):
        return str(g)
    ways, period, cap = g
    return "%d-way/period %d B/%d B" % (ways, period, cap)


def _metric_latch(ms: MeasurementSet, cfg: Config, scale: float = 0.0):
    rr = _reread_deltas(ms, cfg)
    if not rr or scale < 0.5:
        return None
    cl = {off: _classify_delta(d, scale) for off, d in rr.items()}
    if all(c == "fast" for c in cl.values()):
        return "all-hit"
    if all(c == "slow" for c in cl.values()):
        return "no-reuse"
    f = _fit_latch(cl)
    return f"{f['granularity']}Bx{f['entries']}"


def _metric_width(ms: MeasurementSet, cfg: Config, scale: float = 0.0):
    s = _saturation(_walk_series(ms, cfg), 0)
    return None if s is None else s[0]


_METRIC_NAMES = ("read_width", "latch", "data_reuse")


def infer_knob_map(ms: MeasurementSet, width: Optional[Claim] = None,
                   fill: Optional[Claim] = None) -> Claim:
    knobs = [k for k in ms.knob_names() if k != "waitstates"]
    configs = ms.configs()
    matrix: Dict[str, Dict[str, Any]] = {}
    ev: List[str] = []
    caveats: List[str] = []
    if not knobs:
        return Claim("knob_map", UNKNOWN, NONE_,
                     "cross-product: hold every other knob and vary one",
                     [], ["This part exposes no knobs besides the wait states, so "
                          "there is nothing to attribute."])

    fetch = 0
    if fill is not None and fill.known:
        fetch = fill.value
    elif width is not None and width.known:
        fetch = width.value

    # A DEVICE knob's effect is measured with the instrument isolated.  Pairing
    # across a configuration whose probe loop is resident in the memory under
    # test attributes the confound to the register: on the L552 exactly one
    # such cell turns `waysel` from "re-indexes at constant capacity" into
    # "controls the capacity".  The instrument knob's own rows still use every
    # configuration - showing that difference is the whole point of them.
    device_cfgs = [c for c in configs if _is_isolated(ms, c)]
    if len(device_cfgs) < 2:
        device_cfgs = configs
        if "loopmem" in ms.knob_names():
            caveats.append(
                "Fewer than two isolated configurations were measured, so the "
                "knob map is built from configurations whose probe loop shares "
                "the memory under test. Every verdict below inherits that "
                "confound.")

    metrics = (
        ("read_width", _metric_width, "saturating stride of the cold walk"),
        ("latch", _metric_latch, "granularity x entries fitted to the reread sweep"),
        ("data_reuse",
         lambda m, c, sc: _metric_geometry(m, c, sc, fetch),
         "the (ways, conflict period, capacity) fitted to the eviction surface"),
    )

    cache = {}
    for cfg in configs:
        scale = _miss_scale(ms, cfg)
        for mname, fn, _ in metrics:
            cache[(cfgkey(cfg), mname)] = fn(ms, cfg, scale)

    for knob in knobs:
        vals = ms.knob_values(knob)
        matrix[knob] = {}
        pool = configs if knob in _INSTRUMENT_KNOBS else device_cfgs
        for mname, _, how in metrics:
            pairs = []
            for cfg in pool:
                if knob not in cfg or cfg[knob] != vals[0]:
                    continue
                for v in vals[1:]:
                    other = dict(cfg)
                    other[knob] = v
                    if not any(cfgkey(c) == cfgkey(other) for c in pool):
                        continue
                    a = cache[(cfgkey(cfg), mname)]
                    b = cache[(cfgkey(other), mname)]
                    if a is None or b is None:
                        continue
                    pairs.append((cfg, v, a, b))
            if not pairs:
                matrix[knob][mname] = {"verdict": "unknown",
                                       "why": "no complete pair of configs"}
                continue
            changed = [p for p in pairs if p[2] != p[3]]
            if knob in _INSTRUMENT_KNOBS:
                # Not a register: this knob moves where the probe loop lives.
                # A difference across it is the instrument confounding itself,
                # and calling it "controls" would report the measurement as a
                # property of the part.
                lo = _fmt_geometry(changed[0][2]) if (changed and mname == "data_reuse") \
                    else (changed[0][2] if changed else pairs[0][2])
                hi = _fmt_geometry(changed[0][3]) if (changed and mname == "data_reuse") \
                    else (changed[0][3] if changed else pairs[0][2])
                matrix[knob][mname] = {
                    "verdict": "confounds" if changed else "no effect",
                    "pairs": len(pairs), "changed": len(changed),
                    "from": lo, "to": hi,
                    "why": (f"{len(changed)} of {len(pairs)} matched pairs "
                            f"moved, {lo} -> {hi} - but this knob is the "
                            f"probe loop's own residence, not a register of "
                            f"the memory system"
                            if changed else
                            f"identical in all {len(pairs)} matched pairs")}
                continue
            if not changed:
                matrix[knob][mname] = {
                    "verdict": "no effect", "pairs": len(pairs),
                    "value": _fmt_geometry(pairs[0][2]) if mname == "data_reuse"
                             else pairs[0][2],
                    "why": f"identical in all {len(pairs)} matched pairs"}
                continue
            if mname == "data_reuse":
                # Three distinguishable things a knob can do to a cache, and
                # the middle one has no name in a scalar metric.
                reindex = all(isinstance(p[2], tuple) and isinstance(p[3], tuple)
                              and p[2][2] == p[3][2] for p in changed)
                lo = _fmt_geometry(changed[0][2])
                hi = _fmt_geometry(changed[0][3])
                if reindex:
                    matrix[knob][mname] = {
                        "verdict": "re-indexes", "pairs": len(pairs),
                        "changed": len(changed), "from": lo, "to": hi,
                        "why": ("%d of %d matched pairs moved, %s -> %s: "
                                "associativity and conflict period change while "
                                "the capacity does not, so this knob re-indexes "
                                "the cache rather than resizing it"
                                % (len(changed), len(pairs), lo, hi))}
                else:
                    matrix[knob][mname] = {
                        "verdict": "controls", "pairs": len(pairs),
                        "changed": len(changed), "from": lo, "to": hi,
                        "why": ("%d of %d matched pairs moved, %s -> %s"
                                % (len(changed), len(pairs), lo, hi))}
                continue
            lo = _median([p[2] for p in changed if isinstance(p[2], (int, float))]) \
                if all(isinstance(p[2], (int, float)) for p in changed) else changed[0][2]
            hi = _median([p[3] for p in changed if isinstance(p[3], (int, float))]) \
                if all(isinstance(p[3], (int, float)) for p in changed) else changed[0][3]
            # A latch that goes from resolved to "fast at every offset"
            # was not switched off: it was hidden under something that
            # holds both probe addresses. That is a different claim, and
            # it is the one the ground-truth write-ups make ("no register
            # reaches it").
            masks = (mname == "latch"
                     and "all-hit" in (str(lo), str(hi))
                     and "no-reuse" not in (str(lo), str(hi)))
            matrix[knob][mname] = {
                "verdict": "masks" if masks else "controls",
                "pairs": len(pairs), "changed": len(changed),
                "from": lo, "to": hi,
                "why": (f"{len(changed)} of {len(pairs)} matched pairs "
                        f"moved, {lo} -> {hi}"
                        + (" - the probe reads uniformly fast, which "
                           "hides the latch rather than removing it"
                           if masks else ""))}

    for knob in knobs:
        for mname in _METRIC_NAMES:
            e = matrix[knob][mname]
            ev.append(f"  {knob:9s} -> {mname:11s}: {e['verdict']:11s}  {e.get('why','')}")

    if not fetch:
        caveats.append(
            "No read width or fill unit was resolved, so the data-reuse metric "
            "had no line to fit the eviction surface at and every data-reuse "
            "verdict is `unknown` rather than `no effect`.")

    # The headline the repo's five write-ups all reach by hand.  Instrument
    # knobs are excluded: they cannot "control" a structure, only hide it from
    # the probe.
    device = [k for k in knobs if k not in _INSTRUMENT_KNOBS]
    controllers = {m: [k for k in device if matrix[k][m]["verdict"] == "controls"]
                   for m in _METRIC_NAMES}
    reindexers = [k for k in device
                  if matrix[k]["data_reuse"]["verdict"] == "re-indexes"]
    for k in knobs:
        if k not in _INSTRUMENT_KNOBS:
            continue
        moved = [m for m in _METRIC_NAMES
                 if matrix[k][m]["verdict"] == "confounds"]
        if moved:
            ev.append("  -> `%s` is an instrument control, not a device "
                      "register: it says where the probe loop runs. It moves %s, "
                      "which measures the probe sharing a memory with the data "
                      "under test, and is reported here so the confound is "
                      "visible rather than attributed to the silicon"
                      % (k, ", ".join(moved)))
            caveats.append(
                "`%s` moved %s. That is the probe loop's own residence, not a "
                "register that reaches those structures: with the loop in flash "
                "its instruction fetches share the structure under test (and on "
                "a part whose caps include `unified`, share it by construction). "
                "Every structural claim in this report is taken from the "
                "isolated setting; this row is the control that shows what "
                "running the probe from flash would have done to it."
                % (k, ", ".join(moved)))
    if not controllers["read_width"]:
        ev.append("  -> read width is moved by no knob, which is what makes it a "
                  "property of the flash array rather than of the accelerator")
    else:
        caveats.append(f"Read width moved with {controllers['read_width']}, which "
                       f"an array property should not do. Either those knobs "
                       f"enable a line-filling cache (check the fill_unit claim) "
                       f"or the width measurement is contaminated.")
    maskers = [k for k in device if matrix[k]["latch"]["verdict"] == "masks"]
    if not controllers["latch"]:
        ev.append("  -> no knob reaches the latch"
                  + (f"; {', '.join(maskers)} only masks it" if maskers else ""))
    if controllers["data_reuse"]:
        ev.append(f"  -> multi-line data reuse is controlled by "
                  f"{', '.join(controllers['data_reuse'])} and by nothing else")
    for k in reindexers:
        ev.append("  -> %s does not change how much the cache holds, it changes "
                  "how the cache is indexed: %s. A scalar reuse metric reports "
                  "this knob as having no effect"
                  % (k, matrix[k]["data_reuse"]["why"]))
    # A cache-enable knob that reaches nothing is far more likely to be a
    # classifier problem than a part with an inert enable bit.
    for k in device:
        inert = all(matrix[k][m]["verdict"] in ("no effect", "unknown")
                    for m in _METRIC_NAMES)
        if not inert:
            continue
        if k in ("dcache", "unified"):
            # A knob that enables a cache the data-side probe CAN see, reaching
            # nothing, is far likelier to be a classifier problem than a part
            # with an inert enable bit - that is exactly what a pooled
            # miss-cost threshold did to the G474 once.
            caveats.append(
                "`%s` is a canonical enable knob for a structure this probe can "
                "see, and it moved none of the three metrics. Treat that as a "
                "measurement or classification failure until it is explained "
                "rather than as an inert register." % k)
        elif k == "icache":
            # NOT a failure: every probe in `memmap/1` is a data access, so an
            # instruction cache that is not unified with the data path is
            # invisible to all three metrics by construction. On the F429 and
            # the G474 this is the published result; on the L552, whose ICACHE
            # is unified, the same knob comes out controlling data reuse, and
            # the tool measures the difference rather than assuming either.
            ev.append("  -> `icache` moved none of the three metrics. Every "
                      "primitive here is a data access, so an instruction cache "
                      "that does not share a structure with the data path is "
                      "invisible to this probe by construction - this is the "
                      "expected reading for a separate I-cache, and it is not "
                      "evidence that the register is inert. The instruction side "
                      "is not measured: see the cache claim's caveats.")
    return Claim("knob_map", matrix, HIGH if len(configs) >= 4 else LOW,
                 "the full cross-product: for each knob, every pair of measured "
                 "configurations that differ in that knob alone is compared on "
                 "three metrics (walk saturation, the fitted latch model, and "
                 "the fitted cache geometry (ways, conflict period, capacity)). "
                 "A knob 'controls' a structure when a matched pair moves it, "
                 "'re-indexes' it when the geometry moves at constant capacity, "
                 "and 'masks' it when the probe stops being able to see it",
                 ev, caveats, {"controllers": controllers,
                               "reindexers": reindexers})


# ==========================================================================
# 6. wait-state scaling
# ==========================================================================

def _linfit(xs: Sequence[float], ys: Sequence[float]):
    n = len(xs)
    if n < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    a = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    b = my - a * mx
    ss_res = sum((y - (a * x + b)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    r2 = 1.0 if ss_tot == 0 else 1.0 - ss_res / ss_tot
    worst = max(abs(y - (a * x + b)) for x, y in zip(xs, ys))
    return {"slope": a, "intercept": b, "r2": r2, "max_resid": worst, "n": n}


def infer_waitstate_scaling(ms: MeasurementSet, latch: Claim, width: Claim) -> Claim:
    if "waitstates" not in ms.knob_names():
        return Claim("waitstate_scaling", UNKNOWN, NONE_,
                     "per-access cost fitted against the `waitstates` knob", [],
                     ["This part exposes no wait-state knob."])
    ev, caveats = [], []
    g = (latch.value["granularity_bytes"]
         if (latch.known and latch.value.get("present")) else None)
    k_ent = (latch.value.get("entries", 1)
             if (latch.known and latch.value.get("present")) else 1)
    align = (latch.data or {}).get("align", 0)

    # Group configs by their non-waitstate part.
    groups: Dict[Tuple, List[Config]] = {}
    for cfg in ms.configs():
        rest = tuple(sorted((k, v) for k, v in cfg.items() if k != "waitstates"))
        groups.setdefault(rest, []).append(cfg)

    results = {}
    for rest, cfgs in groups.items():
        if len(cfgs) < 3:
            continue
        label = " ".join(f"{k}={v}" for k, v in rest) or "(no other knobs)"
        xs_d, ys_d, xs_w, ys_w = [], [], [], []
        for cfg in sorted(cfgs, key=lambda c: c["waitstates"]):
            ws = cfg["waitstates"]
            rr = _reread_series(ms, cfg)
            if g and rr:
                # Which offsets are hits is decided by the FITTED latch model,
                # not by `off >= g`.  With two entries indexed on A[3] the
                # offsets in [g, 2g) land in the OTHER entry and are hits, and
                # calling them misses mixes a hit level into the slow median.
                fast = [v for off, v in rr.items()
                        if not _latch_predict(off, g, k_ent, align)]
                slow = [v for off, v in rr.items()
                        if _latch_predict(off, g, k_ent, align)]
                if fast and slow:
                    xs_d.append(ws)
                    ys_d.append(_median(slow) - _median(fast))
            s = _walk_series(ms, cfg)
            sat = _saturation(s, 0)
            if sat:
                xs_w.append(ws)
                ys_w.append(sat[1])
            elif s:
                # LATENCY 0 legitimately gives a flat, ~zero cost.
                cand = [v[0] for v in s.values() if v[0] is not None]
                if cand and max(cand) < 0.5:
                    xs_w.append(ws)
                    ys_w.append(max(cand))
        results[label] = {"latch": _linfit(xs_d, ys_d) if len(xs_d) >= 3 else None,
                          "walk": _linfit(xs_w, ys_w) if len(xs_w) >= 3 else None,
                          "latch_points": list(zip(xs_d, ys_d)),
                          "walk_points": list(zip(xs_w, ys_w))}

    fits = [(lab, r) for lab, r in results.items() if r["latch"] or r["walk"]]
    if not fits:
        return Claim("waitstate_scaling", UNKNOWN, NONE_,
                     "per-access cost fitted against the `waitstates` knob", [],
                     ["No configuration was measured at three or more wait-state "
                      "settings."])

    for lab, r in fits:
        if r["latch"]:
            f = r["latch"]
            ev.append(f"  {lab}: latch differential = {f['slope']:.3f} x WS "
                      f"{'+' if f['intercept'] >= 0 else '-'} {abs(f['intercept']):.3f}, "
                      f"R2={f['r2']:.4f}, worst residual {f['max_resid']:.2f} cyc "
                      f"(n={f['n']})")
            ev.append("      points: " + " ".join(f"{int(x)}:{y:g}"
                                                   for x, y in r["latch_points"]))
        if r["walk"]:
            f = r["walk"]
            ev.append(f"  {lab}: cold per-word cost = {f['slope']:.3f} x WS "
                      f"{'+' if f['intercept'] >= 0 else '-'} {abs(f['intercept']):.3f}, "
                      f"R2={f['r2']:.4f} (n={f['n']})")

    # The headline coefficient: the latch differential where it was measurable,
    # otherwise the cold per-word cost.
    chosen = None
    for lab, r in fits:
        if r["latch"] and r["latch"]["n"] >= 4:
            chosen = (lab, "latch differential", r["latch"])
            break
    if chosen is None:
        lab, r = fits[0]
        chosen = (lab, "cold per-word cost", r["walk"] or r["latch"])

    lab, what, f = chosen
    caveats.append(
        "A wait-state setting of 0 contributes a legitimate zero to this fit and "
        "must not be read as an absent structure: at LATENCY = 0 a hit and a miss "
        "cost the same cycle, so the structure is still there and simply worth "
        "nothing (MEASURING_CHANNELS B3).")
    if any(r["latch"] and r["latch"]["slope"] < 0.05 for _, r in fits):
        caveats.append("At least one configuration shows a flat-zero differential "
                       "at every wait state. That is the masking configuration "
                       "(a cache holding both probe addresses), not evidence "
                       "against the scaling.")
    conf = HIGH if f and f["r2"] > 0.99 and f["max_resid"] < 0.6 else \
        (MED if f and f["r2"] > 0.9 else LOW)
    return Claim("waitstate_scaling", round(f["slope"], 4) if f else UNKNOWN, conf,
                 "linear fit of the per-access cost against the `waitstates` knob, "
                 "in each configuration separately; the headline coefficient is "
                 f"the {what} in configuration '{lab}'",
                 ev, caveats, {"fits": {k: {kk: vv for kk, vv in v.items()}
                                        for k, v in results.items()}})


def infer_twin_calibration(ms: MeasurementSet, width: Claim) -> Claim:
    """Is `flash - twin` actually zero when the flash costs nothing?

    The twin rule says every flash measurement is subtracted against the same
    probe function over an identically shaped buffer.  That cancels the loop's
    framing only if the twin's buffer stands in the same relationship to the
    loop's own instruction fetch as the flash buffer does - and on a part where
    the two buffers sit on different bus ports, it does not.  At `waitstates = 0`
    a flash access costs no more than an SRAM one, so whatever `flash - twin`
    reads there is the instrument, not the silicon.

    The offset is **per configuration and per loop body**, and it is never
    pooled across either.  On the L552 the `walk` body reads -1.000 cyc/access
    with the probe loop in SRAM and +2 to +3 with the loop in flash, because
    `loopmem` is precisely the knob that decides which memory shares a port
    with instruction fetch: the mean of the two is a number with the wrong
    sign, which tells the reader to correct in the wrong direction.

    Reported rather than silently subtracted, because the fix is a caveat on
    every derived number, not a correction that can be applied blind.
    """
    ev: List[str] = []
    if "waitstates" not in ms.knob_names():
        return Claim("twin_calibration", UNKNOWN, NONE_,
                     "flash minus twin at zero wait states", [],
                     ["This part exposes no wait-state knob, so there is no "
                      "setting at which a flash access is known to be free and "
                      "the twin cannot be calibrated this way."])
    zero = [c for c in ms.configs() if c.get("waitstates") == 0]
    if not zero:
        return Claim("twin_calibration", UNKNOWN, NONE_,
                     "flash minus twin at zero wait states", [],
                     ["No configuration was measured at `waitstates = 0`."])
    w = width.value if width.known else None

    # ---- one number per (configuration, loop body) ----------------------
    per: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for cfg in zero:
        rows = []
        for st, tup in sorted(_walk_series(ms, cfg).items()):
            if tup[0] is None or (w is not None and st < w):
                continue
            rows.append((st, tup[0]))
        if rows:
            per[(cfgname(cfg), "walk")] = {
                "cfg": cfg, "body": "walk", "value": _median([v for _, v in rows]),
                "spread": max(v for _, v in rows) - min(v for _, v in rows),
                "n": len(rows), "isolated": _is_isolated(ms, cfg)}
        rr = sorted(_reread_deltas(ms, cfg).items())
        if rr:
            per[(cfgname(cfg), "reread")] = {
                "cfg": cfg, "body": "reread", "value": _median([d for _, d in rr]),
                "spread": max(d for _, d in rr) - min(d for _, d in rr),
                "n": len(rr), "isolated": _is_isolated(ms, cfg)}
    if not per:
        return Claim("twin_calibration", UNKNOWN, NONE_,
                     "flash minus twin at zero wait states", [],
                     ["No usable walk at `waitstates = 0`."])

    for (name, body), r in sorted(per.items()):
        ev.append("  %s: `%s` body over %d point(s) -> flash-twin = %+.3f "
                  "cyc/access%s"
                  % (name, body, r["n"], r["value"],
                     "" if r["isolated"] else
                     "   [probe loop in flash: deliberately confounded]"))

    # ---- the headline: the walk body in an isolated configuration -------
    walks = [r for (_, body), r in per.items() if body == "walk"]
    iso = [r for r in walks if r["isolated"]]
    pool = iso or walks
    caveats: List[str] = []
    values = [r["value"] for r in pool]
    data = {"per_config": dict(("%s/%s" % k,
                                dict((kk, vv) for kk, vv in r.items() if kk != "cfg"))
                               for k, r in per.items())}
    if max(values) - min(values) > 0.25:
        caveats.append(
            "The `flash - twin` offset is not one number even within the "
            "configurations it is quoted for: "
            + ", ".join("%s %+.3f" % (cfgname(r["cfg"]), r["value"]) for r in pool)
            + ". It is reported as unresolved rather than averaged, because a "
              "mean over configurations whose bias has different signs is a "
              "correction in the wrong direction for at least one of them.")
        return Claim("twin_calibration", UNKNOWN, NONE_,
                     "the cold walk's `flash - twin` per-access cost at "
                     "`waitstates = 0`, computed per configuration",
                     ev, caveats, data)
    chosen = min(pool, key=lambda r: cfgname(r["cfg"]))
    per_access = _median(values)

    confounded = [r for r in walks if not r["isolated"]]
    if iso and confounded:
        cvals = [r["value"] for r in confounded]
        if (min(cvals) - max(values) > 0.25) or (min(values) - max(cvals) > 0.25):
            caveats.append(
                "The offset has the OPPOSITE sense with the probe loop resident "
                "in flash (%s cyc/access) from the one it has with the loop in "
                "RAM (%s). That is not noise: `loopmem` decides which memory "
                "shares a bus port with instruction fetch, so averaging over it "
                "averages a quantity with its own negation. The figure above is "
                "the isolated configuration alone - the one every structural "
                "claim in this report is measured in - and the confounded value "
                "is listed in the evidence, never mixed in."
                % (", ".join("%+.3f" % v
                             for v in sorted(set(round(x, 3) for x in cvals))),
                   ", ".join("%+.3f" % v
                             for v in sorted(set(round(x, 3) for x in values)))))
    # The `reread` figure must come from the SAME configuration as the
    # headline, not from a median over every isolated cell: on the H723 the
    # two `waitstates = 0` cells read +3.000 and +1.000, whose median is a
    # +2.000 that is measured nowhere and disagrees with this claim's own
    # evidence list.  One number per (configuration, loop body) is the rule
    # this claim exists to enforce; pooling here broke it inside the fix.
    rr_rows = [r for (name, body), r in per.items()
               if body == "reread" and name == cfgname(chosen["cfg"])]
    if rr_rows:
        rrv = _median([r["value"] for r in rr_rows])
        if abs(rrv - per_access) > 0.25:
            caveats.append(
                "The single-`reread` body reads %+.3f cycles in the same "
                "configuration, against %+.3f for the `walk` body. One number "
                "per (configuration, loop body) is the smallest honest unit: a "
                "longer loop body has idle cycles for an extra bus beat to hide "
                "in, so the two bodies are not interchangeable and are not "
                "averaged into one figure." % (rrv, per_access))
    elif not rr_rows:
        caveats.append(
            "No `reread` row was measured at `waitstates = 0` in %s, so the "
            "offset quoted here is the `walk` body's alone. The two bodies "
            "differ on some parts and are never averaged."
            % cfgname(chosen["cfg"]))

    if abs(per_access) < 0.1:
        ev.append("  -> the twin is a clean zero on this part: with no wait "
                  "states to pay, the flash walk and the identically shaped "
                  "SRAM walk agree to better than 0.1 cycles per access, so "
                  "`flash - twin` is an unbiased estimator of the flash penalty")
    else:
        # The sign is explained for the sign actually measured, and the twin
        # is named by the kind the shim declared.  Emitting the negative-value
        # mechanism (the L552's: an SRAM twin contending with a probe loop
        # that also runs from SRAM) beside a POSITIVE figure on a part whose
        # twin is DTCM and whose loop is in ITCM describes a different board.
        tkind = ms.twin_kind() or "twin"
        why = ("A NEGATIVE value means the flash buffer measures CHEAPER than "
               "its own %s twin, which is the bus-port signature: the probe "
               "loop shares a port with the twin's data loads while flash "
               "data loads sit on another."
               % tkind
               if per_access < 0 else
               "A POSITIVE value means the flash path costs more than the %s "
               "twin even where the flash is free of wait states - a fixed "
               "access cost that is not a flash structure. It is what a "
               "tightly-coupled twin looks like: a DTCM or similar zero-wait "
               "memory is not on the same fabric as the flash, so the "
               "subtraction leaves a constant behind rather than cancelling. "
               "It is large enough to matter: on this part it swallowed a "
               "one- and two-cycle latch differential whole, until the "
               "classification was moved inside the flash column."
               % tkind)
        caveats.insert(0,
                       "The twin is NOT a zero here: at `waitstates = 0`, where "
                       "a flash access cannot cost more than an SRAM one, "
                       "`flash - twin` still reads %+.3f cycles per access in "
                       "%s. %s Every "
                       "figure derived by subtracting the twin in this "
                       "configuration carries that bias, and correcting means "
                       "subtracting it. The instrument-neutral quantity is "
                       "`flash(LATENCY) - flash(0)` at the same stride, which "
                       "cancels the loop entirely."
                       % (per_access, cfgname(chosen["cfg"]), why))
    if not iso and confounded:
        caveats.append(
            "No isolated configuration was measured at zero wait states (every "
            "`waitstates = 0` cell has the probe loop in flash), so this figure "
            "is the confounded one and is NOT the bias carried by the "
            "structural claims.")
    data["per_access"] = per_access
    return Claim("twin_calibration",
                 {"cyc_per_access": round(per_access, 4),
                  "config": cfgname(chosen["cfg"]),
                  "body": "walk",
                  "isolated": bool(iso)},
                 HIGH,
                 "the cold walk's `flash - twin` per-access cost measured at "
                 "`waitstates = 0`, where a flash access is known to cost no "
                 "more than an SRAM one, so anything left over is the harness. "
                 "Computed per configuration and per loop body and never pooled "
                 "across either; the headline is the isolated configuration, "
                 "which is the one the structural claims are measured in",
                 ev, caveats, data)


# ==========================================================================
# entry point
# ==========================================================================

def infer_all(ms: MeasurementSet) -> Structure:
    part = ms.meta.get("part", "unknown-part")
    st = Structure(part=part, meta=dict(ms.meta))

    width, fill = infer_read_width(ms)
    st.add(width)
    st.add(fill)
    latch = st.add(infer_latch(ms))
    cache = st.add(infer_cache(ms, latch, width, fill))
    st.add(infer_policy(ms, cache, width))
    st.add(infer_knob_map(ms, width, fill))
    st.add(infer_waitstate_scaling(ms, latch, width))
    calib = st.add(infer_twin_calibration(ms, width))

    # Cross-checks between claims, reported rather than silently reconciled.
    if cache.known and cache.value.get("present"):
        cv = cache.value
        if cv.get("ways") is None:
            cands = "/".join(str(w) for w in cv.get("ways_candidates", []))
            if cv.get("capacity_bytes") is not None:
                st.notes.append(
                    "UNDETERMINED: capacity is measured at %d B, but the split "
                    "between ways and sets is not - candidates %s way. See the "
                    "cache caveats for the measurement that would settle it."
                    % (cv["capacity_bytes"], cands))
            elif not cv.get("threshold_model_holds", True):
                st.notes.append(
                    "UNDETERMINED: the eviction surface in the configuration "
                    "with the most reuse is not a step function in the "
                    "working-set size, so no (ways, sets, line) geometry is "
                    "fitted from it%s. See the cache caveats: the threshold "
                    "model is what `N_evict` means, and this capture falsifies "
                    "it."
                    % ("" if cv.get("capacity_bytes_min") is None else
                       ", and only a floor of >= %d B survives"
                       % cv["capacity_bytes_min"]))
            else:
                st.notes.append(
                    "UNDETERMINED: through this probe region the cache is only "
                    "bounded below, at >= %s B. Neither its capacity nor its "
                    "associativity (candidates %s way) is resolved; the region "
                    "is too small to reach the conflict spacing."
                    % (cv.get("capacity_bytes_min"), cands))
        elif not cv.get("geometry_unique"):
            st.notes.append(
                "UNDETERMINED: the cache's %d B conflict period is consistent with "
                "several (sets, line) splits, including '%d fully-associative %d B "
                "tags'. Capacity (%d B) and associativity-in-ways (%d) are measured; "
                "the line size is not."
                % (cv["conflict_period_bytes"], cv["ways"],
                   cv["conflict_period_bytes"], cv["capacity_bytes"], cv["ways"]))
        if fill.known and cv["line_bytes"] == fill.value and width.known                 and fill.value != width.value:
            st.notes.append(
                "Cross-check: the cache's fill unit (%d B) is confirmed twice - "
                "by the stride at which a warm walk saturates and by the eviction "
                "surface." % fill.value)
    if latch.known and latch.value.get("present") and width.known:
        if latch.value["granularity_bytes"] != width.value:
            st.notes.append(
                "NOTE: the latch granularity (%d B) is not the flash read width "
                "(%d B). On every part characterised in this repository they are "
                "equal; a difference means either the latch holds a fraction of a "
                "read or the width measurement saturated early."
                % (latch.value["granularity_bytes"], width.value))
        else:
            st.notes.append(
                "Cross-check: the latch granularity equals the flash read width "
                "(%d B), as it does on every part in this repository."
                % width.value)
    if calib.known and abs(calib.value["cyc_per_access"]) >= 0.1:
        st.notes.append(
            "INSTRUMENT: in %s the %s twin is offset by %+.3f cycles per "
            "access at zero wait states, so every twin-subtracted figure "
            "measured in that configuration carries that bias - correcting "
            "means subtracting it. The offset is NOT the same in every "
            "configuration and is not pooled; see the twin_calibration claim "
            "for the per-configuration table."
            % (calib.value["config"], ms.twin_kind() or "twin",
               calib.value["cyc_per_access"]))
    # Capture integrity, reported whatever the claims say.  Both of these are
    # statements about the INSTRUMENT, and both were found by an independent
    # re-derivation of these captures rather than by the tool that made them.
    dup = []
    for mode in ("walk", "reread", "evict", "chase", "alt"):
        dup += [(mode,) + d for d in _replay_disagreements(ms, mode)]
    if dup:
        st.notes.append(
            "INSTRUMENT: %d measurement(s) taken twice in this capture with the "
            "same configuration and arguments did not come back the same "
            "number (e.g. %s %s%s: %g then %g). A probe whose result is not a "
            "function of its arguments cannot be read as a property of the "
            "part; see the cache claim, which refuses a geometry when the rows "
            "it would be fitted to are among them."
            % (len(dup), cfgname(dup[0][1]), dup[0][0], dup[0][2],
               dup[0][3], dup[0][4]))
    warmup = [w for w in (ms.meta.get("warnings") or []) if "warm-up outlier" in w]
    if warmup:
        st.notes.append(
            "INSTRUMENT: %d warning(s) record the DISCARDED warm-up repetition "
            "disagreeing with the kept ones. That reading is not in `obs[].raw`, "
            "so `min == max` over the stored repeats is not evidence that those "
            "rows are reproducible - the disagreeing sample is the one that was "
            "filtered out. A shim capture should carry the warm-up reading in "
            "`obs[]` rather than in prose." % len(warmup))
    if ms.meta.get("warnings"):
        st.notes.append("Capture warnings: " + "; ".join(ms.meta["warnings"][:8]))
    if "counters" in (ms.meta.get("caps") or []) and not any(
            o.mode == "counters" for o in ms.obs):
        st.notes.append(
            "GAP: this part advertises `counters` - hardware hit/miss "
            "registers that `PROTOCOL.md` calls an independent instrument - "
            "and the capture contains no counter reading. Every claim here "
            "rests on timing alone, with a cross-check available and unused.")
    ws_vals = ms.knob_values("waitstates")
    if len(ws_vals) > 1:
        ev_ws = {o.config.get("waitstates") for o in ms.rows("evict", "flash")}
        ev_ws |= {o.config.get("waitstates") for o in ms.rows("chase", "flash")}
        if len(ev_ws) == 1:
            st.notes.append(
                "SCOPE: every `evict` and `chase` row in this capture was taken "
                "at `waitstates = %s`, so the cache claim is a claim about that "
                "one setting. Nothing here suggests the geometry moves with the "
                "latency, and nothing here tests it either."
                % next(iter(ev_ws)))
    return st
