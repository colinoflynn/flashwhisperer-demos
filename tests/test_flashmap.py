"""Host-only tests for `flashmap.infer` - no hardware, no serial port.

Two kinds of test, and the distinction matters:

1. **Synthetic parts.**  A small, explicit model of a memory system
   (`MemModel`) generates exactly the measurement set a shim would produce for a
   known geometry, and the inference is asserted to recover that geometry.  The
   model is written from the *mechanism* (a latch is an address-tagged register;
   a cache is tags with per-word validity), not from the inference, so a bug that
   makes `infer.py` agree with itself does not pass.

2. **Published numbers.**  The literal tables from `research/targets/stm32f4_latch.md`,
   `research/targets/stm32g474_art_geometry.md`, `research/targets/stm32l552.md`,
   `research/targets/stm32h723.md` and `research/targets/nrf52840.md` are fed in as
   measurements, and the inference must reproduce what those documents concluded
   by hand.  This is what lets the two other shim authors trust the inference
   without a board: if their part behaves like one of the five already
   characterised, the tool already gets that part right.

Run: `pytest tests/test_flashmap.py -q`
"""
from __future__ import annotations

import os as _os, sys as _sys
# The five packages live under flashwhisperer/ (REORG_PLAN D2).  Walk up to the
# .git marker rather than assume a depth: importers of these packages sit at the
# repository root, in hardware/, results/<campaign>/, demo/<stack>/ and
# research/<area>/ - four different depths.  `.git` is a FILE in a worktree, so
# test existence, not isdir.
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))

import pathlib
import sys

import pytest

from flashmap.experiments import MeasurementSet
from flashmap.infer import UNKNOWN, _fit_cache, _fit_latch, _levels, infer_all


# ==========================================================================
# the model
# ==========================================================================

class MemModel:
    """An explicit, mechanism-level model of a flash memory system.

    * The **array** returns `width` bytes per read and costs `miss_cost` cycles.
    * The **latch** is `entries` address-tagged registers of `gran` bytes each,
      indexed by `(addr >> log2 gran) % entries`.  Depth is one per entry, which
      is what a register is.
    * The **cache**, when enabled, is `(ways, sets, line)` with per-word validity:
      a miss allocates the whole line *tag* but only marks the `fill` bytes it
      actually fetched as valid.  That split is the G474's behaviour and is what
      makes "capacity in tags" different from "capacity in bytes".
    * A cache hit never reaches the flash controller, so it does not touch the
      latch - which is why a large enough cache *masks* the latch rather than
      removing it.
    """

    BASE = 0x08000000
    SIZE = 0x10000

    def __init__(self, width=16, gran=None, entries=1, latch=True,
                 cache=None, fill=None, miss_cost=None, waitstates=5,
                 policy="lru", seed=1, size=None):
        self.size = size or MemModel.SIZE
        self.width = width
        self.gran = gran if gran is not None else width
        self.entries = entries
        self.latch_on = latch
        self.cache = cache                     # (ways, sets, line) or None
        self.fill = fill if fill is not None else width
        self.ws = waitstates
        self.policy = policy
        self.seed = seed
        self._rng = seed
        if miss_cost is not None:
            self._miss = miss_cost
        elif cache:
            self._miss = waitstates * (self.fill // width)
        else:
            self._miss = waitstates
        self.reset_all()

    # - state ------------------------------------------------------------
    def reset_all(self):
        self._latch = {}        # entry index -> block tag
        self._tags = {}         # set -> list of [tag, {valid word offsets}]
        self._clock = 0
        # NOTE: the PRNG is deliberately NOT reseeded here. A hardware
        # pseudo-random victim selector free-runs; reseeding it per probe would
        # make "random" replacement perfectly repeatable and the eviction step
        # would come out as sharp as LRU's, which is not what silicon does.

    def flush_cache(self):
        """What `S` does: invalidate the caches.  Nothing reaches the latch."""
        self._tags = {}

    def _rand(self, n):
        self._rng = (1103515245 * self._rng + 12345) & 0x7FFFFFFF
        return self._rng % n

    # - one access -------------------------------------------------------
    def access(self, addr):
        self._clock += 1
        wordblk = addr // self.width
        if self.cache:
            ways, sets, line = self.cache
            tag = addr // line
            s = tag % sets
            entry_list = self._tags.setdefault(s, [])
            for e in entry_list:
                if e[0] == tag:
                    if wordblk in e[1]:
                        # A hit renews the line under LRU and is invisible under
                        # FIFO - which is the only difference between the two
                        # and the thing the 3-argument `evict` probe exploits.
                        if self.policy == "lru":
                            e[2] = self._clock
                        return 0                    # served by the cache
                    # tag resident, this word not fetched yet: the array is read
                    e[1].add(wordblk)
                    if self.policy == "lru":
                        e[2] = self._clock
                    self._fill_latch(addr)
                    return self._miss
            # tag not resident
            if len(entry_list) >= ways:
                if self.policy == "random":
                    victim = self._rand(len(entry_list))
                else:  # lru and fifo are indistinguishable on these patterns
                    victim = min(range(len(entry_list)),
                                 key=lambda i: entry_list[i][2])
                entry_list.pop(victim)
            entry_list.append([tag, self._valid_words(addr), self._clock])
            self._fill_latch(addr)
            return self._miss
        # no cache: the latch is the only structure
        if self.latch_on:
            idx = wordblk % self.entries
            if self._latch.get(idx) == wordblk:
                return 0
            self._latch[idx] = wordblk
        return self._miss

    def _valid_words(self, addr):
        start = (addr // self.fill) * self.fill
        return {(start + i * self.width) // self.width
                for i in range(self.fill // self.width)}

    def _fill_latch(self, addr):
        if not self.latch_on:
            return
        blk = addr // self.gran
        self._latch[blk % self.entries] = blk

    def _latch_hit(self, addr):
        if not self.latch_on:
            return False
        blk = addr // self.gran
        return self._latch.get(blk % self.entries) == blk

    # - probes, exactly as the shim defines them -------------------------
    @property
    def scratch(self):
        return self.BASE + self.size - 16

    @property
    def target(self):
        return self.BASE + self.size // 8

    def _warm_then_reset(self):
        self.access(self.scratch)                   # fixed warm-up access
        self.flush_cache()                          # `S` invalidation semantics

    def probe(self, mode, args):
        """Returns (timed_access_count, summed miss cost inside the window)."""
        self.reset_all()
        self._warm_then_reset()
        T = self.target
        if mode == "nop":
            return int(args[0]), 0
        if mode == "walk":
            stride, count = args
            cost = sum(self.access(self.BASE + i * stride) for i in range(count))
            return count, cost
        if mode == "reread":
            off = args[0]
            self.access(T)
            self.access(T + off)
            return 1, self.access(T)
        if mode == "evict":
            n, sp = args[0], args[1]
            start = args[2] if len(args) > 2 else sp
            self.access(T)
            for i in range(n):
                self.access(T + start + i * sp)
            return 1, self.access(T)
        if mode == "chase":
            n, stride, reps = args
            cost = 0
            for _ in range(reps):
                for i in range(n):
                    cost += self.access(T + i * stride)
            return n * reps, cost
        if mode == "alt":
            off, reps = args
            cost = 0
            for _ in range(reps):
                cost += self.access(T)
                cost += self.access(T + off)
            return 2 * reps, cost
        raise ValueError(mode)


# Fixed loop costs, so the twin is the same probe function over the same shape.
_FIXED = {"walk": 7, "reread": 10, "evict": 10, "chase": 8, "alt": 8, "nop": 5}
_LOOP = {"walk": 7, "reread": 0, "evict": 0, "chase": 8, "alt": 13, "nop": 1}


def cycles(model, mode, args, flash=True, twin_bias=0.0):
    """`twin_bias` models a twin that is NOT a clean zero: on a part where the
    probe loop's instruction fetch shares a bus port with SRAM data loads but
    not with flash ones, the SRAM twin costs more per access and
    `flash - twin` under-reports by exactly that."""
    n, cost = model.probe(mode, args)
    base = _FIXED[mode] + _LOOP[mode] * n
    return base + (cost if flash else twin_bias * n)


# ==========================================================================
# building a measurement set
# ==========================================================================

STRIDES = [1, 2, 4, 8, 16, 32, 64, 128, 256]
OFFS = sorted(set(list(range(-40, 41, 4)) + [-33, -31, -17, -15, -9, -7, -1,
                                             1, 3, 7, 9, 15, 17, 23, 25, 31, 33,
                                             39, 48, 56, 64, 96, 128, 256, 4096]))
NS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 28, 29, 30, 31, 32,
      33, 36, 48, 64, 96, 128, 192, 256, 384, 512, 513, 640, 768, 1024]
SPACINGS = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
            32768, 65536]


def build(part, factory, grid, walk_count=64, alt_reps=200, size=None,
          chase_sizes=(), chase_line=None, twin_bias=0.0):
    """Run the model over a knob grid and package it as a `MeasurementSet`."""
    size = size or MemModel.SIZE
    walk_span = size - 4096
    evict_span = (size * 7) // 8 - 4096
    ms = MeasurementSet(meta={"part": part, "core": "test", "clk_hz": 16_000_000,
                              "timer": "systick", "timer_hz": 16_000_000,
                              "twin_kind": "sram"})
    for cfg in grid:
        m = factory(cfg)
        steps = [("nop", (walk_count,)), ("walk", (0, walk_count))]
        steps += [("walk", (st, walk_count)) for st in STRIDES
                  if st * walk_count <= walk_span]
        steps += [("reread", (o,)) for o in OFFS]
        steps += [("alt", (o, alt_reps)) for o in (0, 4, 8, 16, 32, 64)]
        steps += [("evict", (n, sp)) for sp in SPACINGS for n in NS
                  if n * sp + sp <= evict_span]
        if chase_line:
            steps += [("chase", (n, chase_line, 8)) for n in chase_sizes]
        for mode, args in steps:
            ms.add(cfg, "flash", mode, args, cycles(m, mode, args, True))
            ms.add(cfg, "sram", mode, args,
                   cycles(m, mode, args, False, twin_bias))
    return ms


def _grid(**knobs):
    combos = [{}]
    for name, vals in knobs.items():
        combos = [dict(c, **{name: v}) for c in combos for v in vals]
    return combos


# ==========================================================================
# the five real parts, as models
# ==========================================================================

def f429_factory(cfg):
    """STM32F429ZI: 128-bit flash, 1-entry 16 B latch, 8 x 16 B D-cache."""
    return MemModel(width=16, gran=16, entries=1,
                    cache=(8, 1, 16) if cfg.get("dcache") else None,
                    fill=16, waitstates=cfg.get("waitstates", 5))


def g474_factory(cfg):
    """STM32G474RE: 64-bit flash, 1-entry 8 B latch, 8 x 32 B fully-assoc ART,
    filled one 64-bit doubleword at a time."""
    return MemModel(width=8, gran=8, entries=1,
                    cache=(8, 1, 32) if cfg.get("dcache") else None,
                    fill=8, waitstates=cfg.get("waitstates", 4))


def l552_factory(cfg):
    """STM32L552ZE: 64-bit flash, TWO 8 B latch entries indexed on A[3],
    8 KB unified ICACHE whose WAYSEL trades associativity for index width."""
    if cfg.get("icache"):
        cache = (1, 512, 16) if cfg.get("waysel", 0) == 0 else (2, 256, 16)
    else:
        cache = None
    return MemModel(width=8, gran=8, entries=2, cache=cache, fill=16,
                    waitstates=cfg.get("waitstates", 4))


def h723_factory(cfg):
    """STM32H723: 32-byte flash reads, 1-entry 32 B latch, 32 KB 4-way L1 D."""
    return MemModel(width=32, gran=32, entries=1,
                    cache=(4, 256, 32) if cfg.get("dcache") else None,
                    fill=32, waitstates=cfg.get("waitstates", 7))


def h723_factory_sz(cfg, size):
    m = h723_factory(cfg)
    m.size = size
    return m


def nrf52_factory(cfg):
    """nRF52840: 16-byte flash reads, 1-entry 16 B latch, NO data cache.
    No wait-state axis at all; the miss costs ~3 cycles."""
    return MemModel(width=16, gran=16, entries=1, cache=None, miss_cost=3)


def f303_factory(cfg):
    """STM32F303: 64-bit flash whose D-Code path is NOT wired to the row
    register - no data-side reuse of any kind."""
    return MemModel(width=8, gran=8, entries=1, latch=False, cache=None,
                    waitstates=cfg.get("waitstates", 4))


# ==========================================================================
# tests - synthetic parts
# ==========================================================================

def test_f429_recovered():
    grid = _grid(icache=[0, 1], dcache=[0, 1], prefetch=[0, 1], waitstates=[5])
    ms = build("STM32F429ZI", f429_factory, grid,
               chase_sizes=(4, 8, 9, 16), chase_line=16)
    st = infer_all(ms)

    assert st.value("read_width") == 16
    latch = st.value("latch")
    assert latch["present"] and latch["granularity_bytes"] == 16
    assert latch["entries"] == 1
    assert latch["depth"] == 1
    assert latch["knob_reaches_it"] is False
    assert latch["differential_cycles"] == pytest.approx(5, abs=0.01)

    cache = st.value("cache")
    assert cache["present"]
    assert cache["line_bytes"] == 16
    assert cache["capacity_entries"] == 8
    assert cache["capacity_bytes"] == 128
    assert cache["ways"] == 8
    assert cache["conflict_period_bytes"] == 16
    # period == fetch granularity, so this one IS pinned as fully associative
    assert cache["fully_associative"] is True
    assert cache["geometry_unique"] is True

    km = st.value("knob_map")
    assert km["dcache"]["data_reuse"]["verdict"] == "controls"
    assert km["icache"]["data_reuse"]["verdict"] == "no effect"
    assert km["prefetch"]["data_reuse"]["verdict"] == "no effect"
    assert km["icache"]["latch"]["verdict"] == "no effect"
    assert km["dcache"]["read_width"]["verdict"] == "no effect"
    # DCEN does not switch the latch off, it hides it - a different claim, and
    # the one stm32f4_latch.md makes ("no register reaches it").
    assert km["dcache"]["latch"]["verdict"] == "masks"


def test_g474_recovered_including_tags_not_bytes():
    grid = _grid(icache=[0, 1], dcache=[0, 1], prefetch=[0, 1], waitstates=[4])
    ms = build("STM32G474RE", g474_factory, grid)
    st = infer_all(ms)

    assert st.value("read_width") == 8
    latch = st.value("latch")
    assert latch["granularity_bytes"] == 8 and latch["entries"] == 1
    assert latch["depth"] == 1
    assert latch["differential_cycles"] == pytest.approx(4, abs=0.01)

    cache = st.value("cache")
    assert cache["ways"] == 8
    assert cache["conflict_period_bytes"] == 32
    assert cache["capacity_bytes"] == 256
    # The whole point: 8 conflicting tags, not 32 independent doubleword slots.
    assert cache["capacity_unit"] == "tags"
    ev = " ".join(st.get("cache").evidence)
    assert "32 independent word slots" in ev
    # ... and the honest half: with an 8 B fetch and a 32 B conflict period, the
    # tool CANNOT tell "8 fully-associative 32 B tags" from "8-way x 4 sets x
    # 8 B".  It must say so rather than pick one.
    assert cache["fully_associative"] is None
    assert cache["geometry_unique"] is False
    assert any("fully-associative 32 B tags" in c for c in st.get("cache").caveats)


def test_l552_two_indexed_latch_entries():
    """The L552 latch is the case a 'one 16-byte latch' reading gets wrong."""
    grid = _grid(icache=[0, 1], waysel=[0, 1], waitstates=[4])
    ms = build("STM32L552ZE", l552_factory, grid)
    st = infer_all(ms)

    assert st.value("read_width") == 8
    latch = st.value("latch")
    assert latch["granularity_bytes"] == 8
    assert latch["entries"] == 2, "must not be read as one 16-byte latch"
    assert latch["depth"] == 1
    assert latch["indexed_on"] is not None

    cache = st.value("cache")
    assert cache["present"]
    assert cache["line_bytes"] == 16
    assert cache["capacity_bytes"] == 8192
    assert cache["fully_associative"] is False
    assert cache["capacity_unit"] == "tags"


def test_l552_waysel_reindexes_rather_than_resizes():
    """8 KB in both modes: WAYSEL trades associativity for index width."""
    for waysel, ways, sets in ((0, 1, 512), (1, 2, 256)):
        grid = [{"icache": 1, "waysel": waysel, "waitstates": 4}]
        ms = build("STM32L552ZE", l552_factory, grid)
        st = infer_all(ms)
        c = st.value("cache")
        assert c["ways"] == ways, (waysel, c)
        assert c["sets"] == sets, (waysel, c)
        assert c["capacity_bytes"] == 8192


def test_h723_wide_reads_and_four_way():
    """With a probe region large enough to reach the conflict spacing, the
    4-way / 256-set / 32 B geometry comes out."""
    grid = _grid(icache=[0, 1], dcache=[0, 1], waitstates=[7])
    ms = build("STM32H723", lambda c: h723_factory_sz(c, 1 << 19), grid,
               size=1 << 19)
    st = infer_all(ms)
    assert st.value("read_width") == 32
    latch = st.value("latch")
    assert latch["granularity_bytes"] == 32 and latch["entries"] == 1
    assert latch["differential_cycles"] == pytest.approx(7, abs=0.01)
    c = st.value("cache")
    assert c["ways"] == 4, c
    assert c["conflict_period_bytes"] == 8192
    assert c["sets"] == 256 and c["line_bytes"] == 32
    assert c["capacity_bytes"] == 32768
    assert c["fully_associative"] is False


def test_h723_associativity_is_unknown_when_the_region_is_too_small():
    """A 32 KB cache probed through a 64 KB window: capacity is measurable,
    associativity is not, and the tool must say which is which rather than
    printing the first geometry that fits."""
    grid = _grid(icache=[0, 1], dcache=[0, 1], waitstates=[7])
    ms = build("STM32H723", lambda c: h723_factory_sz(c, 1 << 15), grid,
               size=1 << 15)
    st = infer_all(ms)
    c = st.value("cache")
    assert c["ways"] is None, "associativity is not determined"
    assert c["capacity_bytes"] is None, "nor, through this window, is capacity"
    # ... but a floor on the capacity survives every ambiguity
    assert c["capacity_bytes_min"] >= 16384
    joined = " ".join(st.get("cache").caveats)
    assert "Associativity is NOT determined" in joined
    assert "probe region of at least" in joined
    assert "bounded only below" in joined
    # and the floor must be a floor: never above the true capacity
    assert c["capacity_bytes_min"] <= 32768


def test_nrf52_latch_but_no_data_cache():
    ms = build("nRF52840", nrf52_factory, [{}])
    st = infer_all(ms)
    assert st.value("read_width") == 16
    latch = st.value("latch")
    assert latch["present"] and latch["granularity_bytes"] == 16
    assert latch["depth"] == 1
    c = st.value("cache")
    assert c["present"] is False, "there is no data cache on this part"
    # and with no cache there is no replacement policy to claim
    assert st.get("replacement_policy").value is UNKNOWN


def test_f303_no_data_side_reuse_at_all():
    ms = build("STM32F303", f303_factory, [{"waitstates": 4}])
    st = infer_all(ms)
    latch = st.value("latch")
    assert latch == {"present": False}
    assert st.get("latch").confidence == "high"
    assert st.value("cache")["present"] is False


# ==========================================================================
# tests - honesty: what must come out `unknown`
# ==========================================================================

def test_zero_wait_states_yields_unknown_not_a_guess():
    """MEASURING_CHANNELS B3: at LATENCY = 0 a hit and a miss cost the same."""
    grid = [{"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": 0}]
    ms = build("STM32F429ZI", f429_factory, grid)
    st = infer_all(ms)
    assert st.get("read_width").value is UNKNOWN
    assert st.get("latch").value is UNKNOWN
    assert any("LATENCY = 0" in c or "wait state" in c.lower()
               for c in st.get("read_width").caveats)


def test_masking_is_not_reported_as_absence():
    """With the cache on, both probe addresses fit: the latch is hidden."""
    grid = [{"icache": 0, "dcache": 1, "prefetch": 0, "waitstates": 5}]
    ms = build("STM32F429ZI", f429_factory, grid)
    st = infer_all(ms)
    latch = st.get("latch")
    # Only a masking configuration was measured, so no latch claim is made --
    # but it must NOT be claimed absent either.
    assert latch.value is UNKNOWN
    assert any("masking" in c for c in latch.caveats)


def test_unknown_survives_json_round_trip():
    ms = build("STM32F429ZI", f429_factory,
               [{"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": 0}])
    st = infer_all(ms)
    d = st.to_dict()
    assert d["claims"]["read_width"]["value"] is None
    assert d["claims"]["read_width"]["known"] is False


def test_replacement_policy_reports_the_wall():
    """LRU vs FIFO is not decidable with these primitives - and must say so."""
    grid = [{"icache": 0, "dcache": 1, "prefetch": 0, "waitstates": 5}]
    ms = build("STM32F429ZI", f429_factory, grid,
               chase_sizes=(4, 8, 9, 16), chase_line=16)
    st = infer_all(ms)
    pol = st.get("replacement_policy")
    assert pol.value == "lru_or_fifo"
    joined = " ".join(pol.caveats)
    assert "LRU and FIFO are NOT separable" in joined
    assert "re-touches" in joined


def test_replacement_policy_detects_pseudo_random():
    def rnd(cfg):
        return MemModel(width=16, gran=16, entries=1, cache=(8, 1, 16), fill=16,
                        waitstates=5, policy="random")
    grid = [{"dcache": 1, "waitstates": 5}]
    ms = build("synthetic-random", rnd, grid,
               chase_sizes=(4, 8, 9, 16, 17), chase_line=16)
    st = infer_all(ms)
    pol = st.get("replacement_policy")
    assert pol.value == "pseudo_random", pol.evidence
    # and it must warn that the same blur inflates the capacity estimate
    assert any("upper bound" in c for c in pol.caveats)


# ==========================================================================
# tests - the published numbers, fed in literally
# ==========================================================================

def _ms_from_tables(part, walk_row, reread_rows, evict_rows, twin_walk=None,
                    count=64, twin_level=10):
    """Build a MeasurementSet straight out of a document's tables.

    `walk_row`      : {stride: delta_cycles_vs_twin}
    `reread_rows`   : {config: {off: cycles}}
    `evict_rows`    : {config: {(n, spacing): cycles}}
    """
    ms = MeasurementSet(meta={"part": part, "twin_kind": "sram"})
    for cfg, row in reread_rows.items():
        cfg = dict(cfg)
        for st, d in walk_row.items():
            ms.add(cfg, "flash", "walk", (st, count), 500 + d)
            ms.add(cfg, "sram", "walk", (st, count), 500)
        ms.add(cfg, "flash", "walk", (0, count), 500)
        ms.add(cfg, "sram", "walk", (0, count), 500)
        for off, cyc in row.items():
            ms.add(cfg, "flash", "reread", (off,), cyc)
            ms.add(cfg, "sram", "reread", (off,), twin_level)
        for (n, sp), cyc in evict_rows.get(tuple(sorted(cfg.items())), {}).items():
            ms.add(cfg, "flash", "evict", (n, sp), cyc)
            ms.add(cfg, "sram", "evict", (n, sp), twin_level)
    return ms


def test_published_f429_tables():
    """research/targets/stm32f4_latch.md sections 1, 2 and 3, verbatim."""
    walk = {1: 20, 2: 40, 4: 80, 8: 160, 16: 320, 32: 320, 64: 320, 128: 320}
    # section 3: read target, read one other address at `off`, re-read target
    off_all_off = {0: 10, 1: 10, 4: 10, 8: 10, 12: 10, 15: 10,
                   16: 15, 20: 15, 32: 15, 64: 15}
    off_all_on = {o: 10 for o in off_all_off}
    # section 2: 8 line tags of 16 B, and DCEN is its only switch
    ev_on = {(n, 16): (10 if n < 8 else 15)
             for n in (0, 1, 2, 4, 6, 7, 8, 9, 12, 16)}
    ev_off = {(n, 16): (10 if n == 0 else 15)
              for n in (0, 1, 2, 4, 6, 7, 8, 9, 12, 16)}
    for sp in (32, 64, 128, 256):
        ev_on.update({(n, sp): (10 if n < 8 else 15)
                      for n in (0, 1, 2, 4, 6, 7, 8, 9, 12, 16)})
        ev_off.update({(n, sp): (10 if n == 0 else 15)
                       for n in (0, 1, 2, 4, 6, 7, 8, 9, 12, 16)})

    c_off = {"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": 5}
    c_on = {"icache": 1, "dcache": 1, "prefetch": 1, "waitstates": 5}
    ms = _ms_from_tables(
        "STM32F429ZI", walk,
        {tuple(sorted(c_off.items())): off_all_off,
         tuple(sorted(c_on.items())): off_all_on},
        {tuple(sorted(c_off.items())): ev_off,
         tuple(sorted(c_on.items())): ev_on})
    # keys of reread_rows are tuples; rebuild with dicts
    ms = _ms_from_tables(
        "STM32F429ZI", walk,
        {tuple(sorted(c_off.items())): off_all_off,
         tuple(sorted(c_on.items())): off_all_on},
        {tuple(sorted(c_off.items())): ev_off,
         tuple(sorted(c_on.items())): ev_on})
    st = infer_all(ms)
    assert st.value("read_width") == 16, "stm32f4_latch.md section 1: 128-bit"
    latch = st.value("latch")
    assert latch["granularity_bytes"] == 16 and latch["entries"] == 1
    assert latch["differential_cycles"] == 5
    assert latch["knob_reaches_it"] is False
    c = st.value("cache")
    assert c["capacity_entries"] == 8 and c["line_bytes"] == 16


def test_published_g474_eviction_surface_is_fully_associative():
    """stm32g474_art_geometry.md section 2: 8 tags, and the spacing sweep that shows
    there is no address-derived index."""
    measured = {sp: (8, True) for sp in (8, 16, 32, 64, 128, 256, 512)}
    measured[8] = (32, True)     # sub-line spacing: four words share one tag
    measured[16] = (16, True)
    fit = _fit_cache(measured, 8, cap=256)
    assert fit["ways"] == 8
    assert fit["period"] == 32, "the conflict period is one 32 B line"
    assert fit["capacity_bytes"] == 256


def test_published_l552_index_sweep():
    """stm32l552.md section 3b: the 1-way and 2-way conflict spacings."""
    one_way = {16: (512, True), 1024: (8, True), 2048: (4, True),
               4096: (2, True), 8192: (1, True), 16384: (1, True)}
    f1 = _fit_cache(one_way, 16, cap=2048)
    assert (f1["ways"], f1["sets"], f1["line"]) == (1, 512, 16)
    assert f1["capacity_bytes"] == 8192

    two_way = {16: (512, True), 1024: (8, True), 2048: (4, True),
               4096: (2, True), 8192: (2, True), 16384: (2, True)}
    f2 = _fit_cache(two_way, 16, cap=2048)
    assert (f2["ways"], f2["sets"], f2["line"]) == (2, 256, 16)
    assert f2["capacity_bytes"] == 8192


def test_published_nrf52_icache_is_direct_mapped():
    """nrf52840.md section 4b/4c: 2 KB, 16 B lines, one-way."""
    measured = {16: (128, True), 32: (64, True), 64: (32, True),
                128: (16, True), 256: (8, True), 512: (4, True),
                1024: (2, True), 2048: (1, True), 4096: (1, True)}
    fit = _fit_cache(measured, 16, cap=512)
    assert fit["ways"] == 1, "direct-mapped: one aliasing access suffices"
    assert fit["sets"] == 128
    assert fit["line"] == 16
    assert fit["capacity_bytes"] == 2048


def test_published_h723_probe_disagrees_with_ccsidr():
    """stm32h723.md section 3: `CCSIDR` says 4-way, the conflict probe says a
    single 8192-byte-away access evicts.  The tool must report what it measured
    (1-way) rather than the register value - the disagreement is the result."""
    measured = {32: (256, True), 8192: (1, True), 16384: (1, True)}
    fit = _fit_cache(measured, 32, cap=2048)
    assert fit["ways"] == 1
    assert fit["period"] == 8192


def test_published_l552_latch_offset_sweep_fits_two_entries():
    """stm32l552.md section 2a, the 81-offset sweep collapsed to its rule."""
    obs = {}
    for off in range(-32, 48):
        blk_same = (off // 8) == 0
        same_half = ((off // 8) % 2) == 0
        obs[off] = "slow" if (same_half and not blk_same) else "fast"
    fit = _fit_latch(obs)
    assert fit["score"] == 1.0
    assert fit["granularity"] == 8
    assert fit["entries"] == 2


def test_published_h7_aligned_block_not_a_distance():
    """stm32h723.md section 2: the fast window is the aligned 32 B block.
    An aligned-block model and a proximity model differ on negative offsets,
    which is why the sweep is signed."""
    obs = {off: ("fast" if 0 <= off < 32 else "slow")
           for off in range(-64, 96, 4)}
    fit = _fit_latch(obs)
    assert fit["score"] == 1.0 and fit["granularity"] == 32 and fit["entries"] == 1
    from flashmap.infer import _fit_latch_distance
    rival = _fit_latch_distance(obs)
    assert rival["score"] < 1.0, "a +/- distance model must NOT fit this sweep"


# ==========================================================================
# tests - machinery
# ==========================================================================

def test_levels_refuses_to_split_noise():
    assert _levels([10, 10, 10, 10]) is None
    assert _levels([10, 10.2, 10.1]) is None
    lv = _levels([10, 10, 15, 15, 15])
    assert lv is not None and lv[0] == 10 and lv[1] == 15


def test_fit_latch_prefers_the_simplest_model_that_fits():
    obs = {off: ("fast" if 0 <= off < 16 else "slow") for off in range(-32, 48)}
    fit = _fit_latch(obs)
    assert (fit["granularity"], fit["entries"], fit["score"]) == (16, 1, 1.0)


def test_flashmap_is_standalone():
    """It must not import the crypto packages, even transitively."""
    for mod in list(sys.modules):
        if mod.startswith(("flashsim", "flashattack", "flashleak")):
            del sys.modules[mod]
    import importlib
    for name in ("flashmap", "flashmap.device", "flashmap.experiments",
                 "flashmap.infer", "flashmap.report", "flashmap.__main__"):
        importlib.import_module(name)
    bad = [m for m in sys.modules
           if m.startswith(("flashsim", "flashattack", "flashleak"))]
    assert not bad, f"flashmap pulled in {bad}"


def test_measurement_set_json_round_trip(tmp_path):
    ms = build("STM32F429ZI", f429_factory,
               [{"icache": 0, "dcache": 1, "prefetch": 0, "waitstates": 5}])
    p = tmp_path / "raw.json"
    ms.to_json(str(p))
    back = MeasurementSet.from_json(str(p))
    assert len(back) == len(ms)
    a, b = infer_all(ms), infer_all(back)
    assert a.to_dict()["claims"].keys() == b.to_dict()["claims"].keys()


def test_report_renders_without_hardware():
    from flashmap import report
    ms = build("STM32F429ZI", f429_factory,
               _grid(dcache=[0, 1], waitstates=[5]))
    st = infer_all(ms)
    text = report.render(st)
    assert "MEASURED DATASHEET" in text and "read_width" in text
    md = report.markdown(st)
    assert "| property | measured | confidence |" in md
    assert report.compare(st, st).count("=") > 10


# ==========================================================================
# tests - regressions
# ==========================================================================

def test_miss_cost_is_per_configuration_not_pooled():
    """A pooled miss-cost threshold is set by the highest wait-state cell, and
    then a 4-cycle miss at LATENCY 4 classifies as a *hit* and a whole capacity
    sweep silently reports "no eviction at any spacing".

    Diagnosed from a G474 capture whose raw data shows a crisp 8-tag
    transition; this reproduces the shape that broke it.
    """
    grid = _grid(icache=[0, 1], dcache=[0, 1], prefetch=[0, 1], waitstates=[4])
    ms = build("STM32F429ZI", f429_factory, grid)
    # ... plus a wait-state sweep reaching 15, exactly as `default_plan` emits
    sweep = build("STM32F429ZI", f429_factory,
                  [{"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": w}
                   for w in (0, 1, 2, 4, 8, 15)])
    ms.extend(sweep.obs)

    st = infer_all(ms)
    c = st.value("cache")
    assert c["present"], "the 8-tag cache must survive a 0..15 wait-state sweep"
    assert c["capacity_entries"] == 8
    assert c["capacity_bytes"] == 128
    latch = st.value("latch")
    assert latch["granularity_bytes"] == 16
    km = st.value("knob_map")
    assert km["dcache"]["data_reuse"]["verdict"] == "controls"


def test_lru_and_fifo_are_separated_by_the_evict_walk_start():
    """The 3-argument `evict` walks THROUGH the target, so one access in the
    middle of the interference is a hit. LRU promotes the line; FIFO does not."""
    for policy, expect in (("lru", "lru"), ("fifo", "fifo")):
        def fac(cfg, policy=policy):
            return MemModel(width=16, gran=16, entries=1, cache=(8, 1, 16),
                            fill=16, waitstates=5, policy=policy)
        grid = [{"dcache": 1, "waitstates": 5}]
        ms = build("synthetic-" + policy, fac, grid,
                   chase_sizes=(4, 8, 9, 16), chase_line=16)
        # the phase-2 probe, sized from the (correctly inferred) geometry
        m = fac(grid[0])
        for k in (2, 4):
            for n in range(1, 8 + k + 5):
                args = (n, 16, -k * 16)
                ms.add(grid[0], "flash", "evict", args, cycles(m, "evict", args, True))
                ms.add(grid[0], "sram", "evict", args, cycles(m, "evict", args, False))
        st = infer_all(ms)
        pol = st.get("replacement_policy")
        assert pol.value == expect, (policy, pol.value, pol.evidence)
        assert pol.confidence == "high"
        joined = " ".join(pol.evidence)
        assert "LRU predicts" in joined and "FIFO predicts" in joined


def test_three_argument_evict_does_not_pollute_the_capacity_sweep():
    """The policy probe's rows must not be read as ordinary eviction data."""
    grid = [{"dcache": 1, "waitstates": 5}]
    ms = build("STM32F429ZI", f429_factory, grid)
    before = infer_all(ms).value("cache")["capacity_entries"]
    m = f429_factory(grid[0])
    for k in (2, 4):
        for n in range(1, 16):
            args = (n, 16, -k * 16)
            ms.add(grid[0], "flash", "evict", args, cycles(m, "evict", args, True))
            ms.add(grid[0], "sram", "evict", args, cycles(m, "evict", args, False))
    assert infer_all(ms).value("cache")["capacity_entries"] == before


def test_twin_calibration_is_clean_on_a_well_behaved_part():
    ws = [{"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": w}
          for w in (0, 1, 2, 4)]
    ms = build("STM32F429ZI", f429_factory, ws)
    st = infer_all(ms)
    c = st.get("twin_calibration")
    assert c.known and abs(c.value["cyc_per_access"]) < 0.1
    # the value names the configuration and the loop body it was measured in,
    # because the offset is a property of both and is never pooled over either
    assert c.value["body"] == "walk" and c.value["isolated"] is True
    assert "waitstates=0" in c.value["config"]
    assert any("clean zero" in e for e in c.evidence)
    assert not c.caveats


def test_twin_calibration_catches_a_biased_twin():
    """The L552 shape: SRAM data loads share a bus port with the probe loop's
    own instruction fetch and flash data loads do not, so `flash - twin`
    under-reports by a fixed amount per access."""
    ws = [{"icache": 0, "dcache": 0, "prefetch": 0, "waitstates": w}
          for w in (0, 1, 2, 4)]
    ms = build("STM32L552ZE", f429_factory, ws, twin_bias=1.0)
    st = infer_all(ms)
    c = st.get("twin_calibration")
    assert c.known and c.value["cyc_per_access"] == pytest.approx(-1.0, abs=0.05)
    assert any("NOT a zero here" in cv for cv in c.caveats)
    assert any("flash(LATENCY) - flash(0)" in cv for cv in c.caveats)
    assert any("INSTRUMENT" in n for n in st.notes)


def test_one_waitstate_sweep_cell_cannot_set_the_read_width():
    """The STM32H723 defect, in miniature.

    `flashmap/h723.json` reported `read_width = 8` against a published 32, on
    evidence of 37 configurations saturating at stride 32 and exactly one
    saturating at stride 8 - and that one was `waitstates = 0`, a cell the plan
    emits to fit a slope, not to resolve a structure. `min(widths)` then took
    the outlier as the array's width and filed the real answer as a "fill unit".

    The structural claim belongs to the cross-product grid at the reference wait
    state. The wait-state cells still carry the scaling fit; they do not vote on
    geometry.
    """
    def wide(cfg):
        return MemModel(width=32, gran=32, entries=1, cache=None, fill=32,
                        waitstates=cfg.get("waitstates", 7))

    def degenerate(cfg):
        # what LATENCY 0 actually looked like on the H7: still a few cycles,
        # but saturating at the bus beat rather than at the flash read
        return MemModel(width=8, gran=8, entries=1, cache=None, fill=8,
                        waitstates=1, miss_cost=4)

    grid = _grid(icache=[0, 1], dcache=[0, 1], waitstates=[7])
    ms = build("STM32H723", wide, grid, size=1 << 19)
    sweep = build("STM32H723", degenerate,
                  [{"icache": 0, "dcache": 0, "waitstates": 0}], size=1 << 19)
    ms.extend(sweep.obs)

    st = infer_all(ms)
    assert st.value("read_width") == 32, (
        "one wait-state-sweep cell must not outvote the grid")
    ev = " ".join(st.get("read_width").evidence)
    assert "wait-state-sweep cell" in ev


def test_an_unexplained_split_is_not_reported_as_a_fill_unit():
    """Two saturation strides are a fill unit only if a KNOB separates them.

    Where no knob does, the tool must say so and drop its confidence rather
    than printing a tidy two-number answer.
    """
    def odd(cfg):
        # the split tracks nothing: one arbitrary corner of the grid differs
        if cfg.get("icache") == 1 and cfg.get("dcache") == 1:
            return MemModel(width=8, gran=8, entries=1, cache=None, fill=8,
                            waitstates=5)
        return MemModel(width=16, gran=16, entries=1, cache=None, fill=16,
                        waitstates=5)

    grid = _grid(icache=[0, 1], dcache=[0, 1], waitstates=[5])
    st = infer_all(build("synthetic-split", odd, grid))
    w = st.get("read_width")
    assert w.confidence == "low"
    assert any("NO knob explains the split" in c for c in w.caveats)


# ==========================================================================
# tests - the REAL captures, re-inferred
# ==========================================================================
#
# The synthetic tests above check that the inference can recover a geometry it
# is given cleanly.  These check that it recovers the geometry of three actual
# boards from the bytes those boards actually sent, which is a different
# question: a real capture carries the twin's bus-port offset, the wait-state
# sweep's six-offset cells, the configurations where the probe loop is
# deliberately in flash, and every other confound a model does not have.
#
# They are what stops a fix for one part from silently breaking another, and
# they cost nothing to run: `--raw` re-inference touches no hardware.

_ROOT = pathlib.Path(__file__).resolve().parent.parent  # tests/ is one below the root


def _capture(name):
    p = _ROOT / name
    if not p.exists():
        pytest.skip(f"{name} not present (capture it with `flashmap map --rawout`)")
    return infer_all(MeasurementSet.from_json(str(p)))


def test_real_f429_capture():
    """NUCLEO-F429ZI against research/targets/stm32f4_latch.md."""
    st = _capture("results/flashmap/f429.raw.json")
    assert st.value("read_width") == 16
    latch = st.value("latch")
    assert (latch["granularity_bytes"], latch["entries"]) == (16, 1)
    assert latch["depth"] == 1
    assert latch["knob_reaches_it"] is False
    assert latch["model_determined"] is True
    c = st.value("cache")
    assert c["present"] and c["capacity_bytes"] == 128
    assert c["capacity_entries"] == 8 and c["line_bytes"] == 16
    assert c["fully_associative"] is True
    km = st.value("knob_map")
    assert km["dcache"]["data_reuse"]["verdict"] == "controls"
    assert km["dcache"]["latch"]["verdict"] == "masks"
    assert st.value("replacement_policy") == "lru"
    assert st.value("waitstate_scaling") == pytest.approx(1.0, abs=0.05)
    tc = st.value("twin_calibration")
    assert abs(tc["cyc_per_access"]) < 0.1, "the F4 twin is a clean zero"


def test_real_g474_capture():
    """NUCLEO-G474RE against research/targets/stm32g474_art_geometry.md."""
    st = _capture("results/flashmap/map_g4.raw.json")
    assert st.value("read_width") == 8
    latch = st.value("latch")
    assert (latch["granularity_bytes"], latch["entries"]) == (8, 1)
    assert latch["depth"] == 1
    assert latch["knob_reaches_it"] is False
    c = st.value("cache")
    assert c["ways"] == 8
    assert c["conflict_period_bytes"] == 32
    assert c["capacity_bytes"] == 256
    assert c["capacity_unit"] == "tags", "8 tags, not 32 doubleword slots"
    # ... and the honest half: an 8 B fetch with a 32 B period does not
    # separate "8 fully-associative 32 B tags" from "8-way x 4 sets x 8 B".
    assert c["fully_associative"] is None
    assert c["geometry_unique"] is False
    km = st.value("knob_map")
    assert km["dcache"]["data_reuse"]["verdict"] == "controls"
    assert km["icache"]["data_reuse"]["verdict"] == "no effect"
    # `loopmem` is the probe loop's residence, never a device register
    assert km["loopmem"]["data_reuse"]["verdict"] in ("no effect", "confounds")
    assert st.value("replacement_policy") == "lru"
    tc = st.value("twin_calibration")
    assert abs(tc["cyc_per_access"]) < 0.1, "the G4 twin is a clean zero"


def test_real_l552_capture():
    """NUCLEO-L552ZE-Q against research/targets/stm32l552.md.

    This is the part that produced four wrong claims, and every assertion here
    is one of them.
    """
    st = _capture("results/flashmap/map_l5.raw.json")
    assert st.value("read_width") == 8
    assert st.value("fill_unit") == 16

    # 1. two 8-byte entries indexed on A[3] - NOT one 16-byte latch. The right
    #    fit is in the dense sweep and used to be outvoted by five six-offset
    #    wait-state cells that cannot tell the two models apart.
    latch = st.value("latch")
    assert (latch["granularity_bytes"], latch["entries"]) == (8, 2)
    assert latch["depth"] == 1
    assert latch["indexed_on"] is not None
    assert latch["model_determined"] is True
    joined = " ".join(st.get("latch").evidence)
    assert "does not discriminate" in joined
    assert "intersecting what each configuration is consistent with" in joined

    c = st.value("cache")
    assert c["present"] and c["capacity_bytes"] == 8192 and c["line_bytes"] == 16

    # 2. WAYSEL re-indexes at constant capacity; a scalar `max N_evict` calls
    #    that "no effect".
    km = st.value("knob_map")
    assert km["waysel"]["data_reuse"]["verdict"] == "re-indexes"
    assert "capacity" in km["waysel"]["data_reuse"]["why"]
    assert km["icache"]["data_reuse"]["verdict"] == "controls"

    # 3. `loopmem` is the instrument, not a register that reaches the latch.
    assert km["loopmem"]["latch"]["verdict"] == "confounds"
    assert latch["knob_reaches_it"] is False

    # 4. the twin offset is per configuration: -1.000 with the probe loop in
    #    RAM, positive with it in flash, and their mean has the wrong sign.
    tc = st.value("twin_calibration")
    assert tc["cyc_per_access"] == pytest.approx(-1.0, abs=0.05)
    assert tc["isolated"] is True
    assert "loopmem=0" in tc["config"]

    # 5. the replacement policy is LRU, and it is MEASURED: the old
    #    `pseudo_random` came from a cyclic chase in the confounded
    #    configuration at a stride 256x smaller than the conflict period, and
    #    the re-touch probe that decides it never ran at all because `k` was
    #    fixed at (2, 4) with the part's associativity measured as 2.
    assert st.value("replacement_policy") == "lru"
    ev = " ".join(st.get("replacement_policy").evidence)
    assert "re-touching the target" in ev, "the discriminator must have run"
    assert "spacing 4096" in ev, "at the MEASURED conflict period, not 16/32/64"


def test_real_captures_never_claim_more_than_they_measured():
    """Whatever each capture resolves, no claim may be `high` confidence and
    wrong-by-construction: an ambiguous model family or a contradiction between
    configurations must cost confidence, not be hidden."""
    for name in ("results/flashmap/f429.raw.json", "results/flashmap/map_g4.raw.json",
                 "results/flashmap/map_l5.raw.json"):
        st = _capture(name)
        latch = st.get("latch")
        if latch.known and latch.value.get("present"):
            if not latch.value.get("model_determined", True):
                assert latch.confidence == "low", name
                assert any("does not separate" in c or "No single model" in c
                           for c in latch.caveats), name
        pol = st.get("replacement_policy")
        if pol.value == "pseudo_random":
            # only ever from an ISOLATED configuration at a conflicting stride
            assert any("isolated configuration at a conflicting stride" in e
                       for e in pol.evidence), name


def test_real_h723_capture():
    """NUCLEO-H723ZG against research/targets/stm32h723.md and the CCSIDR read over
    SWD: L1-D is 32 B lines x 4 ways x 256 sets = 32768 B.

    Three of this repository's four "confident and wrong" claims were on this
    part, and each has an assertion here.
    """
    st = _capture("results/flashmap/h723.raw.json")
    assert st.value("read_width") == 32

    # 1. the latch is one 32-byte entry, and NO knob reaches it.  The three
    #    wait-state cells that used to say otherwise are the twin's +3 cycle
    #    `reread` offset, not a register: at LATENCY 1 the flash column reads
    #    13/13/13/13/14/14 and resolves perfectly once it is read against
    #    itself instead of against an absolute threshold.
    latch = st.value("latch")
    assert (latch["granularity_bytes"], latch["entries"]) == (32, 1)
    assert latch["depth"] == 1
    assert latch["knob_reaches_it"] is False, "no register reaches the H7 latch"
    assert latch["model_determined"] is True
    assert latch["equivalent_models"] == ["32Bx1"]
    assert st.get("latch").confidence == "high"

    c = st.value("cache")
    assert c["present"]
    assert c["line_bytes"] == 32
    # 2. the capacity is MEASURED, and it is the CCSIDR number.
    assert c["capacity_bytes"] == 32768, "L1-D is 32 KB (CCSIDR 0xF01FE019)"
    assert c["capacity_bytes_min"] <= 32768, "a floor must be a floor"
    # ... and the (ways, sets) split is NOT, so it is a family - which must
    # contain the register truth rather than sit beside it.
    assert c["ways"] is None and c["sets"] is None
    assert "4-way x 256 sets x 32 B line" in c["geometry_candidates"]
    assert 4 in c["ways_candidates"]
    joined = " ".join(st.get("cache").caveats)
    assert "probe region of at least" in joined
    assert "NOT a step function" in joined

    # 3. `not_applicable` ("every configuration is direct-mapped") was read off
    #    four dcache=0 cells - the cache switched OFF, where the only thing
    #    left is the 1-entry latch, which of course fits 1-way.  A claim about
    #    a victim may not be taken from a configuration that has no victim.
    pol = st.get("replacement_policy")
    assert pol.value is UNKNOWN
    assert pol.confidence == "none"

    # the knob map still attributes reuse to `dcache`, without pretending to a
    # geometry the surface does not support
    km = st.value("knob_map")
    assert km["dcache"]["data_reuse"]["verdict"] == "controls"
    assert km["dcache"]["latch"]["verdict"] == "masks"
    assert km["icache"]["latch"]["verdict"] == "no effect"


def test_real_nrf52840_capture():
    """nRF52840-DK against research/targets/nrf52840.md: one 16-byte latch
    tracking the aligned word, and no data-side cache."""
    st = _capture("results/flashmap/nrf52840.raw.json")
    assert st.value("read_width") == 16
    latch = st.value("latch")
    assert (latch["granularity_bytes"], latch["entries"]) == (16, 1)
    assert latch["depth"] == 1
    assert latch["knob_reaches_it"] is False
    # the defect: `model_determined: False` beside an EMPTY family, which
    # asserts both that the answer is undecided and that nothing is a
    # candidate.  Whatever the verdict, the two must agree.
    assert latch["model_determined"] is True
    assert latch["equivalent_models"] == ["16Bx1"]
    assert st.value("cache")["present"] is False
    assert st.get("replacement_policy").value is UNKNOWN


@pytest.mark.parametrize("name", ["results/flashmap/f429.raw.json",
                                  "results/flashmap/map_g4.raw.json",
                                  "results/flashmap/map_l5.raw.json",
                                  "results/flashmap/h723.raw.json",
                                  "results/flashmap/nrf52840.raw.json"])
def test_every_real_capture_keeps_its_claims_self_consistent(name):
    """Invariants that must hold on every part, for any future fix.

    Each one is a defect that shipped: a family that is empty while the model
    is undetermined, a capacity floor above the capacity it bounds, a
    `not_applicable` policy taken from a `ways` the tool did not determine,
    and a configuration voting on a structure it could not have resolved.
    """
    st = _capture(name)

    latch = st.get("latch")
    if latch.known and latch.value.get("present"):
        fam = latch.value.get("equivalent_models") or []
        assert fam, "an undetermined model family may be large, never empty"
        assert latch.value["model_determined"] == (len(fam) == 1)
        if len(fam) > 1:
            assert latch.confidence == "low"

    cache = st.get("cache")
    if cache.known and cache.value.get("present"):
        cv = cache.value
        lo, cap = cv.get("capacity_bytes_min"), cv.get("capacity_bytes")
        if lo is not None and cap is not None:
            assert lo <= cap, "a floor that exceeds the capacity is not a floor"
        if cv.get("ways") is None:
            # undetermined associativity must come with the family and with
            # what would settle it, not with a bare `null`
            assert cv.get("ways_candidates"), cv
            assert any("probe region of at least" in c or
                       "not determined" in c.lower()
                       for c in cache.caveats), cache.caveats

    pol = st.get("replacement_policy")
    if pol.value == "not_applicable":
        # only from a determined associativity, in a configuration that HAS a
        # cache to have a policy for
        assert st.value("cache") is not UNKNOWN
        assert st.value("cache").get("ways") == 1, pol.evidence


@pytest.mark.parametrize("name", ["results/flashmap/f429.raw.json",
                                  "results/flashmap/map_g4.raw.json",
                                  "results/flashmap/map_l5.raw.json",
                                  "results/flashmap/h723.raw.json",
                                  "results/flashmap/nrf52840.raw.json"])
def test_no_claim_rests_on_a_cell_that_could_not_discriminate(name):
    """The general rule, checked against every capture.

    A configuration may only contribute a NEGATIVE finding - "no structure
    here" - once it is established that it could have shown a positive one.
    Every `waitstates = 0` cell fails that test by construction, so none of
    them may appear in the evidence or the caveats as a knob setting that
    removed something.
    """
    from flashmap.infer import _discriminating_power
    from flashmap.experiments import cfgname
    if not (_ROOT / name).exists():
        pytest.skip(f"{name} not present (capture it with `flashmap map --rawout`)")
    ms = MeasurementSet.from_json(str(_ROOT / name))
    st = infer_all(ms)
    blind = [cfgname(c) for c in ms.configs()
             if not _discriminating_power(ms, c).ok]
    if "waitstates" in ms.knob_names() and 0 in ms.knob_values("waitstates"):
        assert blind, "a waitstates=0 cell cannot resolve a hit from a miss"
        assert any("waitstates=0" in b for b in blind)
    latch = st.get("latch")
    for cav in latch.caveats:
        if "show no data-side reuse" in cav:
            for b in blind:
                assert b not in cav, (name, cav)


def test_replay_control_refuses_a_geometry_when_a_row_does_not_reproduce():
    """A probe whose result depends on what ran before it is not a measurement
    of a structure, and the tool must say so instead of fitting the surface.

    The plan's third pass re-measures the `evict` rows nearest the measured
    capacity in the opposite order; this builds that disagreement by hand.
    """
    grid = [{"icache": 0, "dcache": 1, "prefetch": 0, "waitstates": 5}]
    ms = build("STM32F429ZI", f429_factory, grid)
    clean = infer_all(ms)
    assert clean.value("cache")["capacity_bytes"] == 128
    assert clean.value("cache")["threshold_model_holds"] is True

    # replay one row with a different answer - the same (config, mode, args)
    row = [o for o in ms.rows("evict", "flash")
           if len(o.args) == 2 and o.args[1] == 16][3]
    ms.add(row.config, "flash", "evict", row.args, row.cycles + 6.0,
           lo=row.cycles + 6.0, hi=row.cycles + 6.0, n=7)
    st = infer_all(ms)
    c = st.value("cache")
    assert c["present"], "reuse is still there; what is gone is the geometry"
    assert c["threshold_model_holds"] is False
    assert c["ways"] is None
    joined = " ".join(st.get("cache").caveats)
    assert "REPLAY CONTROL failed" in joined
    assert "not a function of its arguments" in joined


def test_kept_repeats_are_not_evidence_when_the_capture_reported_outliers():
    """`Bench` discards a warm-up repetition before taking the median, and the
    discarded value is not in `obs[].raw`.  So `min == max` over the kept
    sample is not a statement about reproducibility on a row the instrument
    itself flagged, and nothing may be inferred from it."""
    from flashmap.infer import _repeats_agree
    grid = [{"icache": 0, "dcache": 1, "prefetch": 0, "waitstates": 5}]
    ms = build("STM32F429ZI", f429_factory, grid)
    for o in ms.obs:
        o.n = 7
    assert _repeats_agree(ms) is True
    ms.meta["warnings"] = ["warm-up outlier: evict(4, 16) on flash "
                           "first=18 median-of-rest=11"]
    assert _repeats_agree(ms) is None, "a filtered sample proves nothing"
