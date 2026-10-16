"""
A vectorized flash-accelerator timing model.

THREE DISTINCT MECHANISMS, often conflated as "the cache"
=========================================================
Microcontroller flash is wider than the CPU word (commonly 64 or 128 bits) and
slower than the core at speed, so it needs wait states. Three *different* things
reduce that cost, and they are not the same:

1. FLASH DATA WIDTH  +  ROW LATCH  (fundamental where it exists - NOT universal)
   The flash array physically reads a whole row at once - e.g. 128 bits = 16
   bytes - into a single output register. A subsequent access whose address
   falls in that *same row* is returned straight from the register with no new
   array read, so it is fast; an access to a different row triggers a fresh
   flash read and pays wait states. It holds exactly ONE row - only reuse of
   the *immediately preceding* row is caught. In this model:
   `FlashModel.row_latch(...)` == ways=1, sets=1.
   -> Where it exists, this alone is enough for the S-box adjacent-collision
      channel, and it CANNOT BE TURNED OFF.

   !! CORRECTED 2026-09-17 - this block used to say "universal", and that
   "every wide flash has one current-row register". Both halves were wrong, and
   they were wrong in opposite directions on two parts measured on this bench
   (see research/targets/stm32g474_art_geometry.md and rigs/fw_f3_cache/):

     * STM32G474 HAS it, and no FLASH_ACR bit removes it. With prefetch,
       I-cache and D-cache ALL disabled, a re-read is still free iff the
       intervening access hit the same 64-bit word. The differential is
       *exactly* LATENCY cycles at every wait-state setting (1..15 measured).
       So "accelerator disabled" is NOT "no channel", and the per-collision
       signal is LATENCY cycles - the number that sets trace counts.

     * STM32F303 does NOT have it, on the data path. Reading the SAME address
       64 times costs exactly what 64 distinct addresses cost (2.00 cyc/access
       at LATENCY=2); a re-read of the address just fetched pays full latency.
       Its flash IS 64-bit wide - a model fit on the *instruction* path gives
       W=8 bytes with PRFTBE=1 - so the row register exists but the D-Code
       path is not wired to it. That is a design choice, not a consequence of
       width. Positive control: the same PRFTBE bit speeds instruction fetch
       33-89% in the same session it moves the data side by exactly zero.

   CONSEQUENCE FOR USING THIS MODEL: whether a given part gets `row_latch(...)`
   or no data-side reuse at all is an EMPIRICAL question per family, and the
   probe is one command - read A, read B, re-read A, sweep B-A across the word
   boundary. Do not infer it from flash width, from the presence of a prefetch
   buffer, or from the absence of ICEN/DCEN bits. `experiments/real_parts.py`
   still assigns `row_latch` to several parts on datasheet wording alone; those
   rows are predictions, and the one that has been tested (STM32F3) was wrong.

2. PREFETCH BUFFER  (sequential, instruction-side)
   Speculatively reads the *next* sequential row (row+1) while the CPU works on
   the current one, to hide latency for LINEAR fetch. It helps sequential
   instruction streaming; it does essentially nothing for data-dependent
   (random) table lookups. Its security-relevant effect is indirect: by serving
   instructions from a separate buffer it stops instruction fetches from
   evicting the data-side row latch (mechanism 1). In this model: `prefetch=True`
   for the sequential load, and "no Contention" (timing.py) for the offload.

3. DATA CACHE  (tagged, multi-line - the only real "cache")
   A tagged store holding several recently-used rows at once; a hit may come
   from ANY held line, so it catches reuse that is NOT adjacent in time (e.g. the
   four same-Te-table lookups spread across a T-table round). This is what a
   STM32F4 ART data cache (8 lines), SAM4E CMCC (2 KB, 4-way), Kinetis FMC, etc.
   add on top of the row latch. In this model: ways>1 and/or sets>1
   (`FlashModel.data_cache(...)`).

The side channel: when a table (S-box / T-table) lives in flash, the hit/miss
pattern - and thus the total time - depends on the looked-up values, i.e. on
key XOR plaintext.

`FlashModel.run(lines)` takes an (N, L) array of flash *row* numbers (the ordered
data accesses of one encryption per row of the array) and returns per-access hit
masks and per-trace cycle totals. Fully vectorized over N traces in pure numpy.
"""

from __future__ import annotations

from dataclasses import dataclass
import numpy as np


@dataclass
class FlashModel:
    """
    Data-path model of a flash. See the module docstring for the three
    mechanisms; the parameters below select which are present.

    Parameters
    ----------
    line_bytes : int
        Flash ROW width in bytes = mechanism 1. 8 = 64-bit flash, 16 = 128-bit
        (the common case), 32 = 256-bit. This is a property of the *flash*, and
        it sets the leakage granularity: a row holds line_bytes S-box entries, so
        a hit reveals the top (8 - log2(line_bytes)) bits of the index. Narrower
        flash therefore leaks MORE per collision. Used by the trace builder to
        turn table addresses into row numbers (aes.line_sequence / timing.py).
    ways : int
        Rows held per set. ways=1 & sets=1 is the pure ROW LATCH (mechanism 1),
        which holds only the immediately-preceding row. ways>1 (or sets>1) is a
        real DATA CACHE (mechanism 3) that also catches non-adjacent reuse.
    hit_cycles : int
        Cost of an access served from a held row (same-row hit / cache hit).
    miss_cycles : int
        Cost of an access that must read a new flash row (hit_cycles + wait
        states, essentially).
    sets : int
        Number of cache sets. 1 (default) = fully associative (the small
        line-buffer / literal-cache case). >1 = set-associative: a line maps to
        set (line_number % sets), and only `ways` lines can coexist per set.
        Total lines held = sets * ways. Real flash caches are set-associative
        (SAM4E CMCC 4-way, Kinetis FMC 4-way, RP2040 XIP 2-way, ESP32 2/8-way),
        which changes whether a table stays resident - so it matters.
    prefetch : bool
        If True, a *miss* also loads the sequential next line (line+1) into the
        buffer set, modelling a linear prefetcher. Rarely helps random table
        access, but included for completeness.
    """

    ways: int = 1
    hit_cycles: int = 1
    miss_cycles: int = 7
    prefetch: bool = False
    sets: int = 1
    line_bytes: int = 16          # flash ROW width in bytes (mechanism 1)

    # ---- named constructors, one per mechanism ---------------------------

    @classmethod
    def row_latch(cls, line_bytes: int = 16, wait: int = 6, hit: int = 1):
        """Mechanism 1 only: a single current-row register (no data cache).
        `wait` is the extra wait-state cycles on a new-row read."""
        return cls(ways=1, sets=1, prefetch=False, line_bytes=line_bytes,
                   hit_cycles=hit, miss_cycles=hit + wait)

    @classmethod
    def data_cache(cls, ways: int, sets: int = 1, line_bytes: int = 16,
                   wait: int = 6, hit: int = 1, prefetch: bool = False):
        """Mechanism 3: a tagged multi-line data cache (sets*ways rows), on top
        of the row latch. sets=1 is fully associative."""
        return cls(ways=ways, sets=sets, prefetch=prefetch, line_bytes=line_bytes,
                   hit_cycles=hit, miss_cycles=hit + wait)

    @property
    def total_lines(self) -> int:
        """Rows the data path can hold at once (1 = pure row latch)."""
        return self.ways * self.sets

    # ---- core simulation -------------------------------------------------

    def run(self, lines: np.ndarray):
        """
        lines : (N, L) int   ordered flash-line numbers of the data accesses.

        Returns
        -------
        hits   : (N, L) bool   whether each access hit a held line
        cycles : (N,)   int64  total data-access cycles per trace
        """
        lines = np.asarray(lines)
        N, L = lines.shape
        if self.ways == 1 and self.sets == 1 and not self.prefetch:
            # fast path: single line buffer -> hit iff same line as previous.
            hits = np.zeros((N, L), dtype=bool)
            hits[:, 1:] = lines[:, 1:] == lines[:, :-1]
            cyc = np.where(hits, self.hit_cycles, self.miss_cycles)
            return hits, cyc.sum(axis=1, dtype=np.int64)

        # general set-associative LRU, vectorized over N traces.
        # buf/age shape (N, sets, ways); a line maps to set (line % sets).
        nsets, ways = self.sets, self.ways
        buf = np.full((N, nsets, ways), np.int64(-1), dtype=np.int64)
        age = np.zeros((N, nsets, ways), dtype=np.int64)
        hits = np.zeros((N, L), dtype=bool)
        clock = np.int64(1)
        rows = np.arange(N)

        def _install(line_ids):
            """Insert/refresh line_ids (N,) into their sets, LRU-evicting."""
            nonlocal clock
            s = np.mod(line_ids, nsets)
            bufs = buf[rows, s]                                  # (N, ways)
            match = bufs == line_ids[:, None]
            present = match.any(axis=1)
            lru = np.argmin(age[rows, s], axis=1)
            slot = np.where(present, np.argmax(match, axis=1), lru)
            buf[rows, s, slot] = line_ids
            age[rows, s, slot] = clock
            clock += 1
            return present

        for i in range(L):
            cur = lines[:, i].astype(np.int64)
            s = np.mod(cur, nsets)
            match = buf[rows, s] == cur[:, None]                 # (N, ways)
            hits[:, i] = match.any(axis=1)
            _install(cur)                                        # update LRU/fill
            if self.prefetch:
                _install(cur + 1)                                # linear prefetch

        cyc = np.where(hits, self.hit_cycles, self.miss_cycles)
        return hits, cyc.sum(axis=1, dtype=np.int64)


# --------------------------------------------------------------------------
# Presets.
#
# IMPORTANT: a FlashModel describes only the *data* (D-Code) path - the flash
# line latch/cache that services table LDRs. It is NOT the whole accelerator.
# A real STM32 "ART Accelerator" is mostly an *instruction*-side feature:
#   * a 128-bit prefetch buffer (sequential, for the instruction stream),
#   * an instruction cache (e.g. 64 x 128-bit lines on F4),
#   * plus a *small* literal/data cache (e.g. 8 x 128-bit lines on F4).
# The prefetch buffer and I-cache do nothing for random table *data*. What they
# do - and this is the security-relevant part - is serve instruction fetches
# from a separate path so they no longer evict the D-Code data latch. In this
# model that is expressed by running WITHOUT a Contention stream (see timing.py
# and the PARTS table in experiments/run_experiments.py), not by a bigger cache.
#
# So the data-side geometry (`ways`) and the instruction-contention setting are
# two independent knobs; a given silicon part is a *pairing* of the two.
PRESETS = {
    # Data path only: a single 128-bit line latch. NOT a universal minimum --
    # STM32F303 measured with no data-side reuse at all (see module docstring).
    "latch": FlashModel(ways=1, hit_cycles=1, miss_cycles=7, prefetch=False),
    # ART literal/data cache: small, ~4 or ~8 128-bit lines. Too small to hold a
    # 4 KB T-table; only partially holds a 256 B S-box.
    "art_dcache4": FlashModel(ways=4, hit_cycles=1, miss_cycles=7, prefetch=False),
    "art_dcache8": FlashModel(ways=8, hit_cycles=1, miss_cycles=7, prefetch=False),
    # Cortex-M7 (F7/H7) real L1 data cache: a proper, larger set-associative
    # cache (approximated here as a bigger fully-associative LRU). Large enough
    # to make a 256 B S-box fully resident -> S-box channel can *vanish*.
    "m7_l1_dcache": FlashModel(ways=32, hit_cycles=1, miss_cycles=7, prefetch=False),
    # Very wide, high wait-state part (e.g. 168 MHz F4, ~5 WS), data latch only.
    "highspeed_5ws": FlashModel(ways=1, hit_cycles=1, miss_cycles=6, prefetch=False),
    # Backwards-compatible alias.
    "latch_only": FlashModel(ways=1, hit_cycles=1, miss_cycles=7, prefetch=False),
}
