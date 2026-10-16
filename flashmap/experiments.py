"""flashmap.experiments - the probe primitives, and the discipline around them.

Everything in this module exists to stop one of the traps in
`MEASURING_CHANNELS.md` from being re-paid:

* **The SRAM-twin rule (A5).**  `Bench.paired()` never measures flash alone.  It
  measures the *same mode with the same arguments* over the twin region, and the
  pair travels together into the `MeasurementSet`.  Comparing two different
  probe functions once produced a spurious 2-cycle effect that survived into
  SRAM; the twin here is the same shim code over an identically shaped buffer,
  which is the only comparison that licenses reading a delta as a flash effect.
* **The twin can eat the effect (nRF52 §1a).**  So the twin is recorded as a
  first-class observation rather than folded into a difference at capture time.
  `infer.py` can then also use *within-column* references (stride 0 against
  stride N on flash), which is build-stable where the subtraction is not.
* **The warm-up rule (PROTOCOL.md rule 2).**  Enforced in the shim, but the host
  checks it: the first sample after a knob change is compared against the rest,
  and a systematic outlier is reported.
* **Repeat statistics.**  Every number downstream is a median of `reps`, with
  min/max and the raw values kept.  A single-shot `reread` sits at the counter's
  resolution floor; `alt` with many reps is what gives sub-cycle resolution.
* **Checksums.**  A probe whose checksum does not move when the arguments move
  read nothing.  `Bench` cross-checks this and raises rather than recording a
  fast zero.

The output is a `MeasurementSet`: a flat list of `(config, region, kind, mode,
args, cycles)` observations.  That - and only that - is what `infer.py`
consumes, which is why `tests/test_flashmap.py` can exercise the whole inference
without a board.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .device import (CANONICAL_KNOBS, Device, DeviceError, DeviceReset, Ident,
                     Knob, Region, Sample)

Config = Dict[str, int]
Args = Tuple[int, ...]


def cfgkey(cfg: Config) -> Tuple[Tuple[str, int], ...]:
    """A hashable, canonically ordered key for a knob setting."""
    order = {k: i for i, k in enumerate(CANONICAL_KNOBS)}
    return tuple(sorted(cfg.items(), key=lambda kv: (order.get(kv[0], 99), kv[0])))


def cfgname(cfg: Config) -> str:
    return " ".join(f"{k}={v}" for k, v in cfgkey(cfg)) or "(no knobs)"


# --------------------------------------------------------------------------

@dataclass
class Obs:
    """One repeated measurement, tagged with everything needed to interpret it."""
    config: Config
    region: str
    kind: str
    mode: str
    args: Args
    cycles: float           # median over `n` repeats
    lo: float = 0.0
    hi: float = 0.0
    n: int = 1
    checksum: Optional[int] = None
    raw: Tuple[float, ...] = ()

    @property
    def key(self):
        return (cfgkey(self.config), self.kind, self.mode, tuple(self.args))

    @property
    def stable(self) -> bool:
        return self.hi == self.lo

    def to_dict(self) -> dict:
        d = asdict(self)
        d["args"] = list(self.args)
        d["raw"] = list(self.raw)
        return d

    @staticmethod
    def from_dict(d: dict) -> "Obs":
        return Obs(config=dict(d["config"]), region=d["region"], kind=d["kind"],
                   mode=d["mode"], args=tuple(d["args"]), cycles=float(d["cycles"]),
                   lo=float(d.get("lo", d["cycles"])), hi=float(d.get("hi", d["cycles"])),
                   n=int(d.get("n", 1)), checksum=d.get("checksum"),
                   raw=tuple(d.get("raw", ())))


class MeasurementSet:
    """A flat, queryable bag of `Obs`, plus the metadata needed to read them.

    Constructed either by `Bench.run()` (from a board) or by hand (from
    published tables, or from a synthetic model - which is how the inference is
    tested without hardware).
    """

    def __init__(self, meta: Optional[dict] = None, obs: Optional[Iterable[Obs]] = None):
        self.meta: dict = dict(meta or {})
        self.obs: List[Obs] = list(obs or [])
        self._index: Optional[dict] = None

    # - building ---------------------------------------------------------
    def add(self, config: Config, kind: str, mode: str, args: Sequence[int],
            cycles: float, region: str = "", **kw) -> Obs:
        o = Obs(config=dict(config), region=region or kind, kind=kind, mode=mode,
                args=tuple(args), cycles=float(cycles),
                lo=float(kw.pop("lo", cycles)), hi=float(kw.pop("hi", cycles)),
                n=int(kw.pop("n", 1)), checksum=kw.pop("checksum", None),
                raw=tuple(kw.pop("raw", ())))
        self.obs.append(o)
        self._index = None
        return o

    def extend(self, others: Iterable[Obs]) -> None:
        self.obs.extend(others)
        self._index = None

    # - querying ---------------------------------------------------------
    def _idx(self) -> dict:
        if self._index is None:
            self._index = {}
            for o in self.obs:
                self._index[o.key] = o
        return self._index

    def get(self, config: Config, mode: str, args: Sequence[int],
            kind: str = "flash") -> Optional[Obs]:
        return self._idx().get((cfgkey(config), kind, mode, tuple(args)))

    def cycles(self, config: Config, mode: str, args: Sequence[int],
               kind: str = "flash") -> Optional[float]:
        o = self.get(config, mode, args, kind)
        return None if o is None else o.cycles

    def twin_kind(self) -> Optional[str]:
        for o in self.obs:
            if o.kind != "flash":
                return o.kind
        return None

    def delta(self, config: Config, mode: str, args: Sequence[int]) -> Optional[float]:
        """Flash minus its own twin.  None if either half is missing."""
        f = self.cycles(config, mode, args, "flash")
        tk = self.twin_kind()
        t = self.cycles(config, mode, args, tk) if tk else None
        if f is None or t is None:
            return None
        return f - t

    def rows(self, mode: Optional[str] = None, kind: Optional[str] = None,
             config: Optional[Config] = None) -> List[Obs]:
        ck = cfgkey(config) if config is not None else None
        return [o for o in self.obs
                if (mode is None or o.mode == mode)
                and (kind is None or o.kind == kind)
                and (ck is None or cfgkey(o.config) == ck)]

    def configs(self) -> List[Config]:
        seen, out = set(), []
        for o in self.obs:
            k = cfgkey(o.config)
            if k not in seen:
                seen.add(k)
                out.append(dict(o.config))
        return out

    def knob_names(self) -> List[str]:
        names: List[str] = []
        for o in self.obs:
            for k in o.config:
                if k not in names:
                    names.append(k)
        order = {k: i for i, k in enumerate(CANONICAL_KNOBS)}
        return sorted(names, key=lambda k: (order.get(k, 99), k))

    def knob_values(self, knob: str) -> List[int]:
        return sorted({o.config[knob] for o in self.obs if knob in o.config})

    def args_for(self, mode: str, kind: str = "flash",
                 config: Optional[Config] = None) -> List[Args]:
        seen = {tuple(o.args) for o in self.rows(mode, kind, config)}
        return sorted(seen)

    # - serialisation ----------------------------------------------------
    def to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"meta": self.meta, "obs": [o.to_dict() for o in self.obs]},
                      fh, indent=1)
            fh.write("\n")

    @staticmethod
    def from_json(path: str) -> "MeasurementSet":
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        return MeasurementSet(d.get("meta", {}), [Obs.from_dict(x) for x in d.get("obs", [])])

    def __len__(self) -> int:
        return len(self.obs)

    def __repr__(self) -> str:
        return (f"<MeasurementSet {self.meta.get('part','?')} "
                f"{len(self.obs)} obs, {len(self.configs())} configs>")


# --------------------------------------------------------------------------
# the plan
# --------------------------------------------------------------------------

#: The granularity ladder the latch model family is drawn from.  The plan
#: builds its `reread` and `alt` offsets from it and `infer.py` fits over it, so
#: there is exactly one place where "what sizes might a flash read latch be"
#: is written down.  It is a statement about flash arrays in general (4 to 128
#: bytes, powers of two), not about any part.
LATCH_GRANULARITIES = (4, 8, 16, 32, 64, 128)


@dataclass
class Step:
    config: Config
    mode: str
    args: Args
    why: str = ""


def _binary_knobs(knobs: Sequence[Knob]) -> List[Knob]:
    return [k for k in knobs if k.name != "waitstates" and len(k.values) <= 4]


#: How many cycles a missed flash access must cost before hit and miss are
#: separable at all.  This is a property of the INSTRUMENT - the counter is
#: integer-valued and the twin can be offset by a cycle - not of any part, and
#: `Bench.calibrate_waitstates` measures which wait-state setting delivers it
#: rather than assuming which number does.
_MIN_MISS_CYCLES = 4.0


def _reference_waitstates(knobs: Sequence[Knob]) -> Optional[int]:
    """Fallback reference `LATENCY` when nothing has been measured yet.

    At `LATENCY = 0` a flash hit and a miss cost the same cycle, so every flash
    structure reads flat - not because it is absent but because it is worth
    nothing (MEASURING_CHANNELS B3).  The structural grid therefore runs
    over-programmed.

    This function is the offline fallback and assumes the usual 1 cycle per
    wait state, which is an assumption about the part.  `map` does not use it:
    `Bench.calibrate_waitstates` MEASURES the penalty each advertised setting
    actually delivers and picks the cheapest setting that clears
    `_MIN_MISS_CYCLES`, so nothing in the plan depends on a wait state being
    worth a cycle on this particular silicon.
    """
    for k in knobs:
        if k.name == "waitstates":
            cands = [v for v in k.values if v >= int(_MIN_MISS_CYCLES)]
            return min(cands) if cands else max(k.values)
    return None


def _grid(binary: Sequence[Knob], ws: Optional[int]) -> List[Config]:
    """Full cross-product of the binary knobs at the reference wait state.

    The cross-product is the point: "which knob controls which structure" is a
    claim about the whole matrix, and a one-knob-at-a-time sweep cannot see an
    interaction (`ICEN` alone does nothing on the F4; `ICEN`+`DCEN` behaves like
    `DCEN`).
    """
    combos: List[Config] = [{}]
    for k in binary:
        combos = [dict(c, **{k.name: v}) for c in combos for v in k.values]
    if ws is not None:
        combos = [dict(c, waitstates=ws) for c in combos]
    return combos


def default_plan(knobs: Sequence[Knob], region_size: int,
                 walk_count: int = 64, alt_reps: int = 200,
                 depth: str = "full", ws_ref: Optional[int] = None) -> List[Step]:
    """The measurement programme.

    `depth`:
      * `full`  - everything (the default for `map`)
      * `quick` - enough to name the structures, not enough to bound them

    The programme is generated from the *knobs the shim advertises*, never from
    a part number, so a new shim gets the same treatment without touching this
    file.
    """
    if ws_ref is None:
        ws_ref = _reference_waitstates(knobs)
    binary = _binary_knobs(knobs)
    grid = _grid(binary, ws_ref)
    steps: List[Step] = []

    # Shim address map (see rigs/fw_map_f4/main.c):
    #   scratch  = base + size - 16   (the fixed warm-up access)
    #   walk     = base + 0           (walks upward)
    #   target   = base + size/8      (room below it for negative reread offsets)
    # so a walk may use size-4096 bytes and an `evict` walk 7/8 of the region.
    walk_span = max(4096, region_size - 4096)
    evict_span = max(4096, (region_size * 7) // 8 - 4096)

    strides = [1, 2, 4, 8, 16, 32, 64, 128]
    if walk_span >= walk_count * 256:
        strides.append(256)
    if depth == "quick":
        strides = [1, 4, 8, 16, 32, 64]

    # `reread` offsets, GENERATED from the model family `infer.py` fits rather
    # than hand-listed.  What the sweep has to do is straddle every boundary any
    # candidate model draws: for a granularity g the models disagree around
    # +/- g, 2g, 3g, 4g, and a sweep that lands only on one side of a boundary
    # cannot tell "one aligned 2g block" from "two g blocks indexed on the next
    # address bit" - which is the L552 latch, and exactly the distinction a
    # six-offset sweep misses.
    #
    # Signed on both sides, because an aligned block and a "within +/- g bytes"
    # proximity rule make the SAME prediction at every non-negative offset; the
    # H7's aligned-block result exists only because the sweep went negative.
    # And deliberately unaligned (odd, and 4k+/-1) offsets, because a probe that
    # only ever lands on a word boundary cannot see a sub-word granularity.
    offs = set()
    for g in LATCH_GRANULARITIES:
        for m in (1, 2, 3, 4):
            for d in (-4, 0, 4):
                offs.add(m * g + d)
                offs.add(-(m * g) + d)
    offs |= set(range(-40, 41, 4))
    offs |= {o + d for o in (-32, -16, -8, 0, 8, 16, 32) for d in (-1, 1)}
    offs |= {3, 7, 9, 23, 25, 39}
    offs |= {1024, 4096}
    offs = sorted(o for o in offs if abs(o) <= region_size // 8)
    if depth == "quick":
        offs = [0, 4, 8, 12, 15, 16, 24, 32, 64, 128]

    # `evict` N values, GENERATED rather than listed.  The hand-written list
    # this replaces contained 29 and 513 - the G474's and the L552's published
    # transition points - which is a fact about two chips smuggled into the
    # plan.  `N_evict` has to be located exactly (the geometry fit compares
    # predicted and measured n, not a bracket), so the schedule is contiguous
    # through the small numbers, where a cache's capacity in lines lives, and
    # then brackets every octave from both sides.
    n_cap = max(64, evict_span // 32)
    ns = set(range(0, 33))
    m = 32
    while m < n_cap:
        m *= 2
        ns.update((m - 1, m, m + 1, m + m // 2))
    ns = sorted(n for n in ns if n <= n_cap)
    if depth == "quick":
        ns = [0, 1, 2, 4, 7, 8, 9, 16, 32, 64]

    # Spacings: every power of two the probe region admits, from the smallest
    # granularity the latch model family contains upward. Starting at 8 would
    # assume no part has a 4-byte fetch unit.
    spacings = [1 << i for i in range(2, 18)]
    spacings = [s for s in spacings if s * 4 <= evict_span]
    if depth == "quick":
        spacings = [8, 16, 32, 64, 256, 4096]

    for cfg in grid:
        steps.append(Step(cfg, "nop", (walk_count,), "instrument floor"))
        steps.append(Step(cfg, "nop", (alt_reps,), "instrument floor, long"))
        for st in strides:
            if st * walk_count <= walk_span:
                steps.append(Step(cfg, "walk", (st, walk_count), "read width"))
        # stride 0 is the within-column reference the nRF52 correction demands:
        # identical loop, identical bus, only the reuse changed.
        steps.append(Step(cfg, "walk", (0, walk_count), "within-column reference"))

        for off in offs:
            steps.append(Step(cfg, "reread", (off,), "latch granularity"))
        # `alt` gives 1/reps-cycle resolution on the same question, so it is
        # swept over the same granularity ladder the model family admits - the
        # inference picks whichever of these its fitted model calls a miss.
        for off in (0,) + tuple(LATCH_GRANULARITIES):
            steps.append(Step(cfg, "alt", (off, alt_reps), "latch, sub-cycle"))

        for sp in spacings:
            for n in ns:
                if n * sp + sp <= evict_span:
                    steps.append(Step(cfg, "evict", (n, sp), "capacity / index"))

        # A cyclic working set, at the three smallest spacings the probe
        # region admits.  These are NOT the spacings the replacement-policy
        # discriminator needs: whether a chase conflicts at all depends on the
        # conflict period, which is not known until the eviction surface has
        # been fitted, so `Bench.policy_plan` emits the chase that matters in a
        # second pass at the MEASURED period.  What these rows provide is the
        # general "how much cyclic reuse is there at a near-line stride"
        # evidence, and `infer.py` will not read a policy out of a chase whose
        # stride does not divide into the measured conflict period.
        for n in (1, 2, 4, 8, 9, 16, 17, 32, 33, 64, 65):
            for sp in spacings[:3]:
                if n * sp * 4 <= evict_span:
                    steps.append(Step(cfg, "chase", (n, sp, 8), "cyclic reuse"))

    # Wait-state sweep.  Only the two extreme binary configs and only the cheap
    # probes - this axis is about a coefficient, not a structure.
    if ws_ref is not None:
        wsk = next(k for k in knobs if k.name == "waitstates")
        ws_vals = [v for v in wsk.values if v in (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 15)]
        allon = {k.name: max(k.values) for k in binary}
        alloff = {k.name: min(k.values) for k in binary}
        for base in ([alloff, allon] if binary else [{}]):
            for ws in ws_vals:
                cfg = dict(base, waitstates=ws)
                steps.append(Step(cfg, "nop", (walk_count,), "floor vs waitstates"))
                for st in (8, 16, 32, 64):
                    steps.append(Step(cfg, "walk", (st, walk_count), "cost vs waitstates"))
                for off in (0, 4, 8, 16, 32, 64):
                    steps.append(Step(cfg, "reread", (off,), "latch vs waitstates"))
                    steps.append(Step(cfg, "alt", (off, alt_reps), "latch vs waitstates"))
    return steps


# --------------------------------------------------------------------------
# the bench
# --------------------------------------------------------------------------

class BenchError(RuntimeError):
    pass


class Bench:
    """Drives a `Device` through a plan, enforcing the twin rule throughout."""

    def __init__(self, dev: Device, reps: int = 7, warm_discard: int = 1,
                 progress=None):
        self.dev = dev
        self.reps = reps
        self.warm_discard = warm_discard
        self.progress = progress
        self.ident: Ident = dev.ident()
        self.regions: List[Region] = dev.regions()
        self.flash: Region = dev.flash_region()
        self.twin: Region = dev.twin_region(self.flash)
        self.knobs: List[Knob] = dev.knobs()
        self._cur: Config = {}
        self.warnings: List[str] = []

        if not self.ident.timer_live:
            raise BenchError(
                "shim reports timer=none: its counter does not advance. "
                "Every probe would be identical and every structure would look "
                "absent - the archetypal silent pass. Fix the shim first.")

    # - configuration ----------------------------------------------------
    def apply(self, cfg: Config) -> Config:
        """Set every knob and return the **readbacks**.

        A knob that does not move is recorded as it actually is, so a whole
        column of the cross-product cannot be silently mislabelled.  This is the
        L552 `WAYSEL` lesson: the register was written and did not take.
        """
        actual: Config = {}
        for name, want in cfg.items():
            got = self.dev.set_knob(name, want)
            actual[name] = got
            if got != want:
                msg = f"knob {name}: asked {want}, read back {got}"
                if msg not in self.warnings:
                    self.warnings.append(msg)
        self._cur = actual
        return actual

    # - measurement ------------------------------------------------------
    def measure(self, region: Region, mode: str, args: Sequence[int]) -> Sample:
        n = self.reps + self.warm_discard
        try:
            s = self.dev.sample(region.name, mode, args, reps=n)
        except DeviceReset as e:
            # The shim faulted and reset, so its knobs are at power-on values.
            # Re-apply the configuration the host believes it set and retry
            # once; a second fault is recorded rather than papered over.
            self.warnings.append(f"{mode}{tuple(args)} on {region.name}: {e}")
            self.apply(dict(self._cur))
            s = self.dev.sample(region.name, mode, args, reps=n)
        if self.warm_discard and s.raw:
            # PROTOCOL rule 2: the shim warms up internally, but the first
            # sample after a knob change can still be dear.  Drop it and say so
            # if it was an outlier, rather than letting it move a median.
            kept = sorted(s.raw[self.warm_discard:])
            if kept:
                first = s.raw[0]
                med = kept[len(kept) // 2]
                if abs(first - med) > max(2.0, 0.05 * max(1.0, med)):
                    self.warnings.append(
                        f"warm-up outlier: {mode}{tuple(args)} on {region.name} "
                        f"first={first:g} median-of-rest={med:g}")
                s = Sample(cycles=med, lo=kept[0], hi=kept[-1], n=len(kept),
                           raw=tuple(kept), checksum=s.checksum)
        return s

    def paired(self, mode: str, args: Sequence[int]) -> Tuple[Sample, Sample]:
        """The rule: every flash measurement carries its own twin.

        Same mode, same arguments, same shim code, identically shaped buffer.
        """
        f = self.measure(self.flash, mode, args)
        t = self.measure(self.twin, mode, args)
        return f, t

    # - running a plan ---------------------------------------------------
    def calibrate_waitstates(self) -> Optional[int]:
        """Measure which wait-state setting makes a miss resolvable, not assume.

        The structural grid has to run over-programmed: at `LATENCY = 0` a hit
        and a miss cost the same cycle and every flash structure reads flat
        (MEASURING_CHANNELS B3).  The question is which setting to pick, and
        "the smallest advertised value >= 4" answers it only on a part where one
        wait state is worth one cycle - an assumption about the silicon, made
        before anything has been measured.

        So measure it.  For each advertised setting, ascending, take the
        within-column quantity `flash(stride) - flash(stride 0)` per access:
        same loop, same bus, same buffer, only the reuse changed, so it carries
        neither the twin's bus-port offset nor the loop's framing.  The first
        setting whose penalty clears `_MIN_MISS_CYCLES` is the reference; if
        none does, the largest advertised setting is, and the caller is warned.
        """
        wsk = next((k for k in self.knobs if k.name == "waitstates"), None)
        if wsk is None:
            return None
        saved = dict(self._cur)
        best = None
        table = []
        # Calibrate in the configuration that gets the LEAST help: every other
        # knob at its minimum, which is caches off and the probe loop in RAM.
        # Measured with a cache on, the penalty is the cache's and the chosen
        # setting can be one at which the bare array is still unresolvable --
        # and it is the bare array every structural claim is compared against.
        floorcfg = {k.name: min(k.values) for k in self.knobs
                    if k.name != "waitstates"}
        try:
            self.apply(floorcfg)
            for v in sorted(wsk.values):
                got = self.dev.set_knob("waitstates", v)
                if got != v:
                    continue
                base, _ = self.dev.timed(self.flash.name, "walk", 0, 64)
                far, _ = self.dev.timed(self.flash.name, "walk", 256, 64)
                # Divide by 63, not 64: `walk 0 64` is one cold access and 63
                # re-reads of it, so the difference is the cost of 63 EXTRA
                # distinct reads. Dividing by 64 reports 63/64 of the real
                # penalty, which is enough to push the choice a whole wait
                # state higher for no reason.
                pen = (far - base) / 63.0
                table.append((v, round(pen, 3)))
                if best is None and pen >= _MIN_MISS_CYCLES:
                    best = v
                    break
        except DeviceError as e:
            self.warnings.append(f"wait-state calibration failed: {e}")
        finally:
            if saved:
                self.apply(saved)
        self.ws_table = table
        if best is None:
            best = max(wsk.values)
            self.warnings.append(
                "no advertised wait-state setting delivered a %g-cycle flash "
                "penalty (measured %s); the structural grid runs at the largest "
                "advertised setting (%d) and hit/miss separation may be marginal"
                % (_MIN_MISS_CYCLES,
                   " ".join("%d:%g" % t for t in table) or "nothing", best))
        return best

    def supports_evict_start(self, spacing: int = 16) -> bool:
        """Does this shim honour the optional third `evict` argument?

        Probed by the checksum, not by the cycle count: a shim that ignores the
        argument runs the default walk and returns the SAME checksum, and its
        timing would then be read as a FIFO result. A capability that fails
        closed matters here, because the wrong answer is a plausible one.
        """
        try:
            a = self.dev.timed(self.flash.name, "evict", 4, spacing)
            b = self.dev.timed(self.flash.name, "evict", 4, spacing, -2 * spacing)
        except DeviceError:
            return False
        return a[1] != b[1]

    def replay_plan(self, cfg: Config, capacity_bytes: int,
                    spacings: Sequence[int], width: int = 2) -> List[Step]:
        """Re-measure the rows nearest the capacity threshold, in REVERSE order.

        The replay control, and it has to be sized from the first pass for the
        same reason the policy probes do: the rows where retention is marginal
        are the ones at a working-set span near the capacity, and where that is
        is not known until the capacity has been measured.

        What it tests is whether the probe's result is a function of its
        arguments at all.  `PROTOCOL.md` rule 2 says a fixed warm-up access
        precedes every timed access so that each probe enters from the same
        state - and one warm-up access cannot restore tens of kilobytes of L1
        data cache.  On the H723, `evict n 8192` measured twice in the same
        order is bit-identical and measured in the opposite order moves, which
        no number of repeats of a single row can reveal: repeats of one command
        leave the same residue behind each time, so they agree while the
        surface as a whole does not.

        Emitted whether or not a geometry was fitted - on the part that needs
        it most, no geometry is.
        """
        steps: List[Step] = []
        span = max(4096, (self.flash.size * 7) // 8 - 4096)
        for sp in sorted(set(spacings), reverse=True):
            if sp <= 0:
                continue
            n0 = max(1, capacity_bytes // sp)
            for n in range(max(1, n0 - width), n0 + width + 1):
                if n * sp + sp <= span:
                    steps.append(Step(cfg, "evict", (n, sp), "replay control"))
        return list(reversed(steps))

    def policy_plan(self, cfg: Config, ways: int, spacing: int,
                    margin: int = 4, retouch: bool = True) -> List[Step]:
        """The replacement-policy probes, sized ENTIRELY from measured geometry.

        `evict n spacing -k*spacing` walks THROUGH the target: k conflicting
        lines, then the target itself, then the rest. That one re-touch is a hit,
        which promotes the line under LRU and is invisible under FIFO, so

            LRU  loses the target at n >= ways + k + 1
            FIFO loses it at         n >= ways + 1

        and the two differ by k. Every other primitive in `memmap/1` leaves the
        target most-recently-used when the interference starts, which is exactly
        why the policy is otherwise undecidable.

        Both the **spacing** and the **re-touch positions** come from the first
        pass.  The spacing must be a multiple of the measured conflict period or
        the walk never reaches the target's set at all - a fixed 16/32/64 B
        spacing reaches it on a fully-associative 32 B ART and never on a part
        whose period is 4 KB, which is how the L552 came to have no re-touch row
        in its evidence.  And `k` must be strictly below the measured
        associativity, or the target is already gone before the re-touch: a
        fixed `ks = (2, 4)` produces no usable row at all on a 1- or 2-way
        cache, which is the other half of the same failure.

        The cyclic `chase` is emitted here for the same reason: at a stride
        below the conflict period it can never conflict, however large the
        working set, so its size is not something the first pass can choose.
        """
        steps: List[Step] = []
        span = max(4096, (self.flash.size * 7) // 8 - 4096)
        ks = sorted({k for k in (1, ways // 2, ways - 1) if 1 <= k < ways})
        # Two spacings, both multiples of the conflict period, so the verdict
        # rests on more than one address pattern.  At ways = 2 only k = 1 is
        # available (k must be below the associativity) and LRU and FIFO then
        # predict adjacent n, which is exactly when a second independent row is
        # worth having.
        sps = [sp for sp in (spacing, 2 * spacing)
               if (ways + max(ks or [0]) + margin + 1) * sp <= span]
        for sp in (sps or [spacing]):
            for k in (ks if retouch else ()):
                for n in range(1, ways + k + margin + 1):
                    if n * sp + sp > span:
                        break
                    steps.append(Step(cfg, "evict", (n, sp, -k * sp),
                                      f"LRU vs FIFO, re-touch at k={k}"))
        # A cyclic set of `m` lines that all land in ONE set: thrashes under
        # LRU and FIFO as soon as m > ways, only partially under a random
        # victim. Adjacent sizes, because "one line over the knee" is the claim.
        # ways-1 .. ways+2 brackets the knee; 2*(ways+1) and 4*(ways+1) are the
        # far-past-the-knee reference `infer.py` normalises against, sized from
        # the knee rather than from `ways` so a random victim's inflated
        # associativity cannot move it.
        sizes = sorted({max(1, ways - 1), ways, ways + 1, ways + 2,
                        2 * (ways + 1), 2 * (ways + 1) + 1, 4 * (ways + 1)})
        for m in sizes:
            if m * spacing > span:
                continue
            steps.append(Step(cfg, "chase", (m, spacing, 8),
                              "cyclic chase at the measured conflict period"))
        return steps

    def run(self, plan: Sequence[Step], into: Optional[MeasurementSet] = None) -> MeasurementSet:
        ms = into if into is not None else MeasurementSet(meta=self.metadata())
        last_key: Optional[tuple] = None
        checks: Dict[Tuple[str, str], set] = {}
        t0 = time.time()
        for i, st in enumerate(plan):
            key = cfgkey(st.config)
            if key != last_key:
                actual = self.apply(st.config)
                last_key = key
            else:
                actual = self._cur
            try:
                fs, ts = self.paired(st.mode, st.args)
            except DeviceError as e:
                msg = str(e)
                if "range" in msg:
                    # "the probe's addresses would leave the region" is "not
                    # measurable here", not a failure - record it once.
                    tag = f"{st.mode}: some arguments out of region range"
                    if tag not in self.warnings:
                        self.warnings.append(tag)
                else:
                    self.warnings.append(f"{st.mode}{tuple(st.args)}: {e}")
                continue
            ms.add(actual, "flash", st.mode, st.args, fs.cycles, region=self.flash.name,
                   lo=fs.lo, hi=fs.hi, n=fs.n, checksum=fs.checksum, raw=fs.raw)
            ms.add(actual, self.twin.kind, st.mode, st.args, ts.cycles, region=self.twin.name,
                   lo=ts.lo, hi=ts.hi, n=ts.n, checksum=ts.checksum, raw=ts.raw)
            if fs.checksum is not None and st.mode != "nop":
                checks.setdefault((st.mode, "flash"), set()).add(fs.checksum)
            if self.progress and (i % 25 == 0 or i == len(plan) - 1):
                self.progress(i + 1, len(plan), time.time() - t0)

        # A probe whose checksum never moves across an entire argument sweep is
        # not reading what it claims to read.
        for (mode, kind), vals in checks.items():
            if len(vals) == 1 and mode in ("walk", "reread", "evict", "chase", "alt"):
                self.warnings.append(
                    f"checksum for {mode} on {kind} took one value "
                    f"(0x{next(iter(vals)):x}) across the whole sweep - the "
                    f"probe may not be varying its addresses")
        ms.meta["warnings"] = list(self.warnings)
        ms.meta["elapsed_s"] = round(ms.meta.get("elapsed_s", 0) + time.time() - t0, 1)
        return ms

    # - metadata ---------------------------------------------------------
    def metadata(self) -> dict:
        return {
            "protocol": "memmap/1",
            "part": self.ident.part,
            "core": self.ident.core,
            "clk_hz": self.ident.clk_hz,
            "timer": self.ident.timer,
            "timer_hz": self.ident.timer_hz,
            "caps": list(self.ident.caps),
            "banner": self.ident.raw,
            "regions": [{"name": r.name, "base": r.base, "size": r.size, "kind": r.kind}
                        for r in self.regions],
            "flash_region": self.flash.name,
            "twin_region": self.twin.name,
            "twin_kind": self.twin.kind,
            "knobs": [{"name": k.name, "values": list(k.values), "reset": k.current}
                      for k in self.knobs],
            "reps": self.reps,
            "captured": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }


# --------------------------------------------------------------------------
# host-side self-test
# --------------------------------------------------------------------------

def selftest(dev: Device, verbose=print) -> Tuple[bool, List[str]]:
    """Exercise every command and fail loudly on the known silent passes.

    This is what a new shim is held to.  It deliberately checks the things that
    *look* like a working measurement: a frozen counter, an uncopied
    `.ramfunc`, an optimised-away loop and a missing twin all produce clean,
    plausible, entirely meaningless numbers.
    """
    problems: List[str] = []

    def ok(msg):
        verbose(f"  ok    {msg}")

    def bad(msg):
        problems.append(msg)
        verbose(f"  FAIL  {msg}")

    ident = dev.ident()
    verbose(f"V  {ident}")
    if not ident.timer_live:
        bad("timer=none - the shim's counter does not advance")
    if ident.timer_hz <= 0:
        bad(f"timer_hz={ident.timer_hz}")
    if ident.clk_hz <= 0:
        bad(f"clk_hz={ident.clk_hz}")
    if not ident.ramfunc:
        verbose("  note  shim does not claim `ramfunc`: the probe loop runs from "
                "flash, so I-side and D-side are conflated (MEASURING_CHANNELS B4)")

    regions = dev.regions()
    for r in regions:
        verbose(f"R  {r}")
    flash = dev.flash_region()
    try:
        twin = dev.twin_region(flash)
        ok(f"twin for {flash.name} is {twin.name} ({twin.kind}, {twin.size} B)")
    except Exception as e:
        bad(str(e))
        return False, problems
    if flash.base % 32 or twin.base % 32:
        bad(f"buffers not 32-byte aligned: flash=0x{flash.base:x} twin=0x{twin.base:x}")
    else:
        ok("buffers aligned to >= 32 bytes")

    knobs = dev.knobs()
    for k in knobs:
        verbose(f"K  {k}")

    # X - the shim's own checks.
    try:
        good, detail = dev.device_selftest()
        (ok if good else bad)(f"X: {detail}")
    except Exception as e:
        bad(f"X: {e}")

    # The counter must advance, measured here and not only claimed.
    c1, _ = dev.timed(flash.name, "nop", 16)
    c2, _ = dev.timed(flash.name, "nop", 4096)
    if c2 <= c1:
        bad(f"nop(4096)={c2} <= nop(16)={c1}: the counter is frozen or wrapping")
    else:
        ok(f"counter advances: nop 16 -> {c1}, 4096 -> {c2}")

    # nop must cost less than walk (PROTOCOL X requirement), on flash.
    w, _ = dev.timed(flash.name, "walk", 64, 64)
    npc, _ = dev.timed(flash.name, "nop", 64)
    if npc >= w:
        bad(f"nop(64)={npc} >= walk(stride 64, 64)={w}: the probe loop is not "
            f"touching memory (optimised away? volatile missing?)")
    else:
        ok(f"walk costs more than nop: {w} vs {npc}")

    # Checksums must move with the arguments.
    _, k1 = dev.timed(flash.name, "walk", 4, 64)
    _, k2 = dev.timed(flash.name, "walk", 64, 64)
    if k1 == k2:
        bad(f"walk checksum identical at stride 4 and 64 (0x{k1:x}): the probe "
            f"is not reading the addresses it says it is")
    else:
        ok(f"checksum moves with the arguments: 0x{k1:x} -> 0x{k2:x}")

    # ... and must be reproducible for identical arguments.
    _, k3 = dev.timed(flash.name, "walk", 4, 64)
    if k3 != k1:
        bad(f"walk checksum not reproducible: 0x{k1:x} then 0x{k3:x}")
    else:
        ok("checksum reproducible across repeats")

    # The twin must be a real, distinct memory: same probe, different region.
    tw, kt = dev.timed(twin.name, "walk", 64, 64)
    if kt == k2 and tw == w:
        bad(f"twin {twin.name} returns the same cycles AND checksum as flash - "
            f"is it actually a different region?")
    else:
        ok(f"twin distinguishable: flash {w}/0x{k2:x} vs twin {tw}/0x{kt:x}")
    if tw > w:
        verbose(f"  note  twin ({tw}) is slower than flash ({w}) at stride 64; "
                f"the subtraction will understate the flash penalty "
                f"(NRF52_GEOMETRY §1a)")

    # Knob readback.
    for k in knobs:
        for v in k.values[:2]:
            got = dev.set_knob(k.name, v)
            if got != v:
                bad(f"knob {k.name}: set {v}, read back {got}")
        dev.set_knob(k.name, k.current)
    if knobs and not problems:
        ok("every knob reads back what was written")

    # Counters, where the part has them, are an independent instrument.
    try:
        ctr = dev.counters()
        if ctr is None:
            verbose("C  unsupported (no hardware counters on this part)")
        else:
            verbose(f"C  {ctr}")
            dev.timed(flash.name, "walk", 16, 64)
            ctr2 = dev.counters() or {}
            if all(ctr2.get(k, 0) == 0 for k in ctr2):
                verbose("  note  counters read all-zero after a walk; if this part "
                        "has an I-cache only, that is the correct answer "
                        "(nRF52: a data walk moves neither counter)")
            else:
                ok(f"counters move: {ctr2}")
    except Exception as e:
        bad(f"C: {e}")

    return (not problems), problems
