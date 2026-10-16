# `flashmap` on the STM32G474 and STM32L552

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Measured through the generic [`memmap/1`](PROTOCOL.md) protocol - the host knew nothing
about either part beyond what `V`, `R` and `K` reported. Shims
[`../rigs/fw_map_g4/`](../../rigs/fw_map_g4) and
[`../rigs/fw_map_l5/`](../../rigs/fw_map_l5); captures `map_g4_geometry.npz`,
`map_l5_geometry.npz`, `map_l5_counters.npz`.

Ground truth: [`../../research/targets/stm32g474_art_geometry.md`](../../research/targets/stm32g474_art_geometry.md) and
[`../../research/targets/stm32l552.md`](../../research/targets/stm32l552.md), both established by bespoke
hand-written probes. The point of the exercise is whether a generic tool rediscovers
them without being told.

## 1. Ground truth: reproduced on both parts

G474 - 64-bit read width saturating at stride 8, identical at every `FLASH_ACR` bit.
Latch free iff the intervening access falls in `[0,7]`, depth 1, differential exactly
`LATENCY` for 0–15. Cache: 8 tags, transition at N=8 at spacings 32…1024 (fully
associative). The doubleword walk starting one line above A evicts at N=29 - the
published number exactly, and the one that distinguishes capacity in *tags* from
capacity in *bytes*.

L552 - the `reread` sweep comes out byte-for-byte as §2a (`+16` lost, `+24` free,
identical at all four `A mod 16` parities) → two 8-byte entries indexed on `A[3]`,
not one 16-byte latch. Depth 1 within a half, never lost across halves. 16-byte line
counted off the miss counter; 512 lines = 8192 B in both associativities; conflict
spacing 8192 B at 1-way and 4096 B at 2-way, so `WAYSEL` re-indexes rather than resizing.

A separation the published document does not make explicit falls out of sweeping the
knob and the stride together (`map_l5_geometry.npz`, `e1`):

| ICACHE | saturates at | delta at saturation | what it measures |
|---|---:|---:|---|
| off | stride 8 | 192 / 64 acc = 3.0 | the 64-bit read width |
| 1-way | stride 16 | 382 / 64 acc = 6.0 | the 16-byte cache line |
| 2-way | stride 16 | 382 / 64 acc = 6.0 | same |

Turning the cache off is what separates the read width from the line size. On the G474
the same sweep is flat across all five knob settings - the control saying the width
belongs to the flash array, not the accelerator.

## 2. Three things neither ground-truth document had

### 2a. Both caches are LRU; FIFO is excluded

`stm32l552.md` §8 records that its data "does not separate LRU from FIFO". One
optional argument on `evict` settles it: start the walk *below* A so it passes through A
once mid-walk - a hit LRU promotes and FIFO ignores.

- G474, re-touch at position k = 2, 4, 6 → eviction moves to N = 11, 13, 15 = k+9.
  FIFO predicts 9, flat, at every k.
- L552, 2-way → zero counted misses where three distinct lines have crossed a
  two-way set and FIFO would have to evict A.

### 2b. The G474's latch survives an intervening instruction fetch; the L552's does not

With the probe loop resident in flash rather than SRAM:

- G474 - signature bit-identical; free offsets still 0–7, costs shift 8/12 → 10/14.
- L552 - completely flat, 17 cycles at every offset. A tool run this way reports
  *"no read latch"*, the exact negation of the truth, and nothing in its output looks
  anomalous.

This is the sharpest methodological result of the pair, and it is why the "run the probe
from SRAM" rule in [`research/mechanism/MEASURING_CHANNELS.md`](../../research/mechanism/MEASURING_CHANNELS.md) is
load-bearing rather than hygienic. It also explains the L552's unified-cache behaviour
from the other side: on that part the instruction stream and the data under test share
one structure.

### 2c. The SRAM twin is not a zero on the L552

The subtraction `flash − twin` is used throughout this repository. On the G474 it is
clean - the twin reads 775 in all five knob configurations. On the L552 it is not
(`e1`, ICACHE off):

| stride | flash | twin | delta |
|---:|---:|---:|---:|
| 1 | 423 | 455 | −32 |
| 2 | 455 | 455 | 0 |
| 4 | 519 | 455 | +64 |
| 8+ | 647 | 455 | +192 |

At stride 1 the flash walk is cheaper than SRAM, by half a cycle per access. Moving
the loop into flash mirrors it exactly (455 / 392): the loop's own fetches and the twin's
loads contend on S-AHB while flash sits on C-AHB. So `flash − twin` reads `LATENCY − 1`
with the tight `walk` body and `LATENCY` with the longer `chase` body.

Re-flashing the older bespoke `fw_l5_cache` gives an identical twin column (455) and a
flash column one cycle per access dearer, which is not explained - the loops are
instruction-identical. The invariant both firmwares agree on exactly is
`flash(LATENCY) − flash(0) = LATENCY`. The published conclusion is right; the
twin-subtraction route to it is not sound on this part, and a one-cycle systematic bias
is invisible to repetition - every `A` reply had `min == max`.

## 3. The counters, and where they go silent

The L552's `ICACHE_HMONR`/`MMONR` confirmed every timing-derived cache claim - line size,
capacity, both conflict spacings, the LRU result - and contradicted none.

But with `icache 0` both monitors read exactly zero, and that is the only
configuration in which the latch is visible at all; with the cache on, a `reread` is
`1 hit, 0 misses` at every offset. The entire two-entry-latch result is timing-only  - 
the part's own independent instrument cannot check one bit of it. A hardware counter is
a control only where its structure is the one under test.

## 4. What the tool got wrong

> All four of the L552 claims below have since been fixed, together with an H723 read-width defect of the same shape and every part-specific constant found in the plan. What each part reports now, what was changed and why, and an explicit list of what remains `unknown` and whether it is *unreachable* rather than merely unmeasured, is in [`FINDINGS_reliability.md`](FINDINGS_reliability.md). Every fix was on the host side; none of the shims changed. This section is kept as the record of what the failures looked like, because the shapes recur.

Scored against ground truth, the G474 maps correctly and completely: `cache = 8 ways,
256 B, period 32 B, unit "tags"`; `latch = 8 B × 1 entry, depth 1, no knob reaches it`;
`dcache → data_reuse: controls`; `dcache → latch: masks`; and - after the `evict start`
extension landed - `replacement_policy: LRU (measured against FIFO)`, high confidence,
matching the independent sweep in §2a.

The L552 produces four wrong claims, causes documented in
[`REQUESTS_g4_l5.md`](REQUESTS_g4_l5.md) §10–12:

| claim | truth | cause |
|---|---|---|
| `latch = 16 B × 1 entry` | 8 B × 2 entries on `A[3]` | the correct fit *is* in the evidence (47/47 offsets fit 8 B × 2), but five wait-state configs carrying only 6 offsets each - too few to discriminate - outvote it, and the tie-break prefers smaller `k` |
| `waysel → data_reuse: no effect` | re-indexes at equal capacity | the knob metric is the scalar `max N_evict`; this knob's effect is in the *shape* |
| `replacement_policy = pseudo_random` | LRU | the re-touch discriminator never ran on this part - the plan emits it at spacings 16/32/64 B while the L552's conflict period is 4096/8192 B. The verdict rests on one cyclic-chase row taken at `loopmem = 1`, i.e. the unified-cache confound of §2b reaching the tool's output |
| `twin_calibration = +0.516 cyc/access` | −1.000 in the isolated config | averages the −1.000 rows from the isolated configuration with +2/+3 rows from the confounded one. It tells the reader to correct in the wrong direction - the same pooling bug as `_miss_scale`, one layer up |

The `twin_calibration` defect is the one I would fix first. §2c is a real and useful
finding, but a tool that *quantifies* the twin bias by pooling across configurations where
the bias has opposite signs is worse than one that stays silent: it converts a caveat into
a confidently wrong correction factor.

Also `loopmem → latch: controls`, `knob_reaches_it: true` - the tool reads *the probe
loop's own residence* as a register that reaches the latch. It is not a register at all;
it is §2b showing up as a knob.

Two real bugs surfaced. A shim bug (`walk` with stride 0 rejected, which the host issues
as its within-column reference) cost a whole L552 run. And in `infer.py`, `_miss_scale`
was pooled over the entire knob grid, so a 4-cycle cache differential at `waitstates=4`
fell below a threshold set by the `waitstates=15` cell - making the G474's 8-tag cache
invisible while reporting `dcache → data_reuse: no effect` at *high* confidence. Fixed.

## 5. What this method cannot reach

Tested, not asserted.

- Replacement policy is reachable only with the `evict start` extension above, and
  even then only LRU vs FIFO. True LRU vs tree-PLRU is not separable by these
  primitives.
- The L552's two-entry latch cannot be distinguished from a two-line direct-mapped
  cache. Behaviourally they are the same object, and the counters are unavailable in
  the only state where either is visible. An identifiability limit, not a resolution
  limit - more traces cannot fix it.
- The instruction side cannot be measured independently of the probe loop. With the
  loop in flash, a walk over the *SRAM* twin - zero cacheable data accesses - still counts
  331 hits, all of them the loop fetching itself. Reaching it needs an
  `exec <n> <spacing>` mode executing flash-resident code at known addresses, which the
  protocol does not have.
- One die, one clock (16 MHz, `LATENCY` over-programmed). Zero jitter (`min == max` on
  every repeat) means repeatability, not accuracy - and §2c is exactly the kind of
  systematic error no number of repeats would reveal.
- `chase` is a data-dependent-stride walk, not a true pointer chase, so an
  address-predicting prefetcher would not be defeated by it. Neither part appears to have
  one; on a part that does, this mode would quietly under-report.
