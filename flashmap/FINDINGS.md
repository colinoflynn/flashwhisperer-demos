# What `flashmap` measured on the NUCLEO-F429ZI

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Board: NUCLEO-F429ZI, COM9, probe `0671FF353445503043081931`, SYSCLK = HSI16
(16 MHz). Shim [`rigs/fw_map_f4/`](../../rigs/fw_map_f4), probe loop in
`.ramfunc`, `FLASH_ACR.LATENCY` over-programmed to 4 for the structural grid
and swept 0-15 for the scaling. One run, 6 876 observations over 30
configurations in 200 s, 7 repeats each, zero capture warnings.

Raw data and provenance, all in this directory:

| file | what is in it |
|---|---|
| `f429.raw.json` | every `(config, region, mode, args, cycles, checksum)` tuple, flash and twin |
| `f429.json` | the inferred structure with confidences, evidence and caveats |
| `f429.md` | the same as a table |
| `f429.report.txt` | the rendered measured datasheet |
| `f429.transcript.log` | every protocol line in both directions, timestamped |

Reproduce, without hardware, from the raw file:

```
python -m flashmap map --raw results/flashmap/f429.raw.json
```

---

## 0. The headline

Everything [`../../research/targets/stm32f4_latch.md`](../../research/targets/stm32f4_latch.md) established by
hand, the tool rediscovered from timings alone, at a different wait-state
setting, with no part-specific knowledge anywhere in the host package.

| property | `stm32f4_latch.md` (by hand, `LATENCY = 5`) | `flashmap` (`LATENCY = 4`) | |
|---|---|---|---|
| flash read width | 16 B (128-bit) | 16 B, invariant across all 8 accelerator settings | agree |
| data cache | 8 tags x 16 B = 128 B, `DCEN` only | 128 B, 8 entries x 16 B, `DCEN` only | agree |
| associativity | not measured on the F4 | fully associative | new |
| read latch | 1 entry, 16 B, depth 1 | 1 entry x 16 B, depth 1 | agree |
| is the latch reachable? | "no register reaches it" | no knob reaches it; `DCEN` masks it | agree |
| per-collision signal | exactly `LATENCY`, at every WS | 1.000 x WS + 0.000, R2 = 1.0000 | agree |
| replacement policy | not measured anywhere in this repo | LRU, measured against FIFO | new |
| twin calibration | not measured | +0.000 cyc/access at WS 0 | new |

No disagreement on substance. Three refinements to published wording are in
section 6, and they are refinements rather than corrections: one of them ("the
per-collision signal is `LATENCY` cycles") turns out to be loop-dependent in
magnitude, by a cycle, in a direction that makes an amplified probe *less*
sensitive than a single-shot one at low wait states.

---

## 1. Read width: 16 bytes, and no knob moves it

Cold forward walk, 64 accesses, flash minus its own SRAM twin, `LATENCY = 4`:

| stride | 0 | 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| per access (cyc) | 0.0625 | 0.25 | 0.50 | 1.00 | 2.00 | 4.00 | 4.00 | 4.00 | 4.00 | 4.00 |

`cost = LATENCY x (distinct 16-byte words touched)`, exactly, saturating at
stride 16. `stm32f4_latch.md` section 1 measured 0.31 / 0.62 / 1.25 / 2.50 / 5.00
at `LATENCY = 5` - the same table scaled by 5/4, to the cycle.

The tool checked the thing the hand-written table asserts and does not test: it
ran the sweep at all eight `PRFTEN` x `ICEN` x `DCEN` settings and every one
saturates at stride 16 at 4.00 cyc/access. That is what licenses calling it a
property of the flash array rather than of the accelerator, and the `knob_map`
cross-product says the same thing from the other side - `read_width` reads
*no effect* for all three knobs, in every matched pair.

The stride-0 column is worth its own line: 64 reads of the same address cost
0.0625 cyc/access, i.e. 4 cycles total, i.e. one miss. There is data-side reuse
with the accelerator fully disabled, before any cache is involved. Section 2
says what kind.

---

## 2. The latch: one entry, 16 bytes, depth one, and nothing switches it off

Read A, read A+`off`, time a re-read of A. `LATENCY = 4`, `ACR` = everything
clear. Flash cycles; the SRAM twin is flat at 11 across all 47 offsets.

| `off` | -40 ... -1 | 0 ... 15 | 16 ... 4096 |
|---|---:|---:|---:|
| flash | 15 | 11 | 15 |

47 offsets, 17 of them negative, and the aligned-block model fits 47/47. The
sweep is signed on purpose: with A aligned to 4096, an "aligned 16-byte
block" and a "within +/-16 bytes" proximity rule agree on every non-negative
offset and disagree on every negative one. Measured, `off = -1` is slow --
so it is a latch holding one aligned flash word, not a neighbourhood. That test
existed in this repository only for the H723; it now exists for the F429.

Depth is one: `evict n 16` with the accelerator off reads 10 at n=0 and 14
at every n >= 1. At spacing 8 it reads 10 at n=1 (the intervening access was in
the same 16-byte word) and 14 from n=2 - the same structure seen from the other
side.

No knob reaches it. The latch resolved identically in all four `DCEN`-off
settings, including `PRFTEN = ICEN = DCEN = 0`. In the four `DCEN`-on settings
the probe reads 11 at *every* offset, and the tool reports that as masking,
not absence - a cache that holds both probe addresses hides a latch
underneath it, and the `knob_map` verdict for `dcache -> latch` is the separate
word `masks` rather than `controls`.

The differential against wait states, accelerator off:

| `LATENCY` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 10 | 12 | 15 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| single-shot `reread` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 10 | 12 | 15 |

Fitted: 1.000 x WS + 0.000, R2 = 1.0000, worst residual 0.00 cycles over 12
points. The `LATENCY = 0` column is a legitimate zero - there are no wait
states left to save - and the tool says so in the claim's caveats rather than
letting it read as an absent structure.

---

## 3. The cache: 128 bytes, 8 entries of 16 B, fully associative, `DCEN` only

`evict n spacing`: read the target, walk n addresses `spacing` apart, time a
re-read. `LATENCY = 4`, so 10 = hit and 14 = miss.

| spacing 16 | n=0 | 1 | ... | 7 | 8 | 9 | 10 | 12 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `DCEN` on | 10 | 10 | 10 | 10 | 14 | 14 | 14 | 14 |
| `DCEN` off | 10 | 14 | 14 | 14 | 14 | 14 | 14 | 14 |

Eight entries, and `DCEN` is the only switch - `stm32f4_latch.md` section 2 exactly.

What the tool adds is the spacing sweep, which is how associativity is
decided:

| spacing | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `N_evict`, `DCEN` on | 16 | 8 | 8 | 8 | 8 | 8 | 8 | 8 | 8 | 8 |
| `N_evict`, `DCEN` off | 2 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 |

Flat at 8 from one line upward, across a 256x range of spacings: there is no
address-derived index, so the cache is fully associative. The conflict
period is 16 B, which equals the fetch granularity, so a single line *is* the
whole index space - this is the one part of the geometry the tool can pin
without ambiguity (see 7.7 for when it cannot).

The `spacing 8` column is the fetch unit seen directly: a walk of n doublewords
from `T+8` reaches 8 distinct 16-byte lines at n=16, and that is where the
target goes.

An independent confirmation of the same 8 through a different mode - a cyclic
pointer chase, `DCEN` on, 16-byte stride:

| lines in the cycle | 1 | 2 | 4 | 8 | 9 | 16 | 32 | 64 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| miss rate per access | 0.12 | 0.12 | 0.12 | 0.12 | 1.00 | 1.00 | 1.00 | 1.00 |

Eight fit; nine thrash completely. (The 0.12 floor is the one compulsory miss
per line per 8 passes.)

---

## 4. Replacement policy: LRU, and this is new

Nothing in this repository measures a replacement policy. The tool's first
answer was the honest wall - *LRU or FIFO, not separable* - because every
primitive `memmap/1` defines produces a reference string that is monotone or
cyclic, and on a cyclic string over capacity+1 lines LRU and FIFO evict the same
line at every step.

The wall came down with one extra argument (section 8): `evict n spacing
[start]`, where a negative `start` makes the walk straddle the target and pass
through it once. That single re-touch is a hit, which promotes the line under
LRU and is invisible under FIFO:

```
LRU  loses the target at  n >= ways + k + 1
FIFO loses it at          n >= ways + 1
```

`ways = 8`, spacing 16, `DCEN` on. Cycles, 10 = the target survived:

| k | n=1..8 | 9 | 10 | 11 | 12 | 13 | 14 | FIFO predicts | LRU predicts | measured |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 2 | 10 | 10 | 10 | 14 | 14 | 14 | 14 | 9 | 11 | 11 |
| 4 | 10 | 10 | 10 | 10 | 10 | 14 | 14 | 9 | 13 | 13 |

Both re-touch positions land exactly on the LRU prediction and neither is
anywhere near the FIFO one; the step is sharp (`min == max` over 7 repeats at
every n). The STM32F4 ART data cache replaces least-recently-used.

The tool refuses to make this claim unless it has verified the shim actually
honours the third argument, and it verifies it by the checksum, not by the
timing: a shim that silently ignored the argument would run the default walk and
its timing would read as FIFO. A capability probe that fails closed matters when
the failure mode is a plausible answer.

---

## 5. The twin is a clean zero here

At `LATENCY = 0` a flash access cannot cost more than an SRAM one, so whatever
`flash - twin` reads there is the instrument rather than the silicon. Measured:
+0.000 cycles per access at strides 16, 32 and 64, with the accelerator both
fully on and fully off, and +0 on a single `reread`.

So on this part every twin-subtracted number above is unbiased. That is not
automatic - a part whose probe loop shares a bus port with its SRAM data loads
but not with its flash ones has a non-zero offset here, and every derived figure
inherits it. The tool measures it rather than assuming it, and says which
answer it got.

---

## 6. Three refinements to the published wording

None of these makes a published number wrong. All three are things the tool
measured that the wording does not cover.

### 6a. "The per-collision signal is `LATENCY` cycles" is loop-dependent, by one cycle

`stm32f4_latch.md` and `stm32g474_art_geometry.md` both state the differential as exactly
`LATENCY`. That is the single-access figure. Measured on the same board, in
the same configuration, at the same wait states, with the `alt` probe - the
same two addresses alternated 200 times inside one timed window:

| `LATENCY` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 10 | 12 | 15 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| single-shot `reread`, cyc/miss | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 10 | 12 | 15 |
| `alt` x200, cyc/miss | 0 | 0.000 | 1.000 | 1.998 | 2.995 | 3.993 | 4.990 | 5.987 | 6.985 | 8.980 | 10.975 | 13.967 |

The amplified loop measures `LATENCY - 1`, at every setting from 2 upward,
and it is not noise: the numbers are reproducible to three decimals over 200
accumulated iterations. The loop body issues the second load one instruction
after the first, so exactly one cycle of the stall hides in work the single-shot
probe does not have.

Two consequences worth carrying:

* A per-collision signal quoted from a tight loop and one quoted from an
  isolated access differ by a cycle, which at `LATENCY = 2` - `sboot_stm32`'s
  own setting - is half the signal. Trace-count estimates that cross
  between the two are off by up to 4x.
* Amplification can lose. At `LATENCY = 1` the single-shot probe resolves
  the latch (1 cycle) and the 200x-amplified probe reads 0.000. The usual
  reasoning - accumulate to get below the counter's resolution floor --
  silently assumes the effect survives being put in a longer loop. Here it does
  not.

This is the `nrf52840.md` section 1a lesson (the probe loop's schedule
changes the number) reproduced on a second vendor's part, and quantified.

### 6b. On the F429, "8 tags" and "128 bytes" are the same statement

`stm32g474_art_geometry.md`'s sharpest result is that the G474's capacity is a count of
line tags and not a byte budget: 8 tags of 32 B, so a walk at 32-byte
spacing dies at 8 and not at the 32 doubleword-slots a byte-budget model
predicts. The tool tests this explicitly - and on the F429 it declines to
claim it, because here the line is 16 B and the flash read is 16 B, so
"8 tags of 16 B" and "128 bytes allocated in 16-byte units" are literally the
same structure and the test has nothing to discriminate. The claim comes out
`capacity_unit: not applicable` rather than being inherited from the G4.

### 6c. `DCEN` off is "no *multi-line* reuse", not "no reuse"

`stm32f4_latch.md` section 2 reads "With `DCEN` clear there is no multi-line reuse at
any N", which is correct and is the table's spacing-16 row. At spacing 8 the
same probe with `DCEN` clear reads 10 at n=1 - the intervening access fell in
the target's own 16-byte word and the latch held. The two sections of that
document describe one mechanism from two angles; the tool measures both in one
sweep and the spacing-8 column is where they meet.

---

## 7. What this method cannot reach

Not an appendix. Each item was tested before being asserted, and the
instrument that would settle it is named.

### 7.1 LRU versus FIFO - reached, but only by extending the protocol

This was the expected wall and it is worth recording that it was a wall for a
reason. Every mode in `memmap/1` primes the target and then interferes with it,
so the target is always most-recently-used at the moment the interference
starts, and LRU and FIFO make the same prediction. `chase` does not help: on a
cyclic reference string over capacity+1 lines the two policies are identical
step for step. No amount of data from the frozen protocol decides it.

What decided it was one optional argument (section 8), not a better instrument
or more traces. That is the general shape: the limit was in the *reference
strings the protocol can express*, not in the timing resolution.

Still out of reach: LRU versus PLRU/tree-LRU, and LRU versus
"most-recently-used-protected" variants, on a cache with more ways than the
probe can enumerate. The k-sweep here distinguishes recency from insertion
order; it does not identify *which* recency approximation.

### 7.2 A sequential prefetch buffer versus a latch, when both have depth 1

Tested, and on this part they *are* separable: a prefetch buffer holds row+1, so
it would make `off = +16` cheap while `off = -16` stayed dear, and it would make
a stride-16 forward walk cheaper than `LATENCY` per access. Measured,
`off = +16` and `off = -16` both read 15, and the stride-16 walk pays exactly
`LATENCY`. So the F429 data path has a latch and no data-side prefetch, and
`PRFTEN` reads *no effect* on all three metrics in the cross-product.

The limitation is in `infer.py`, not in the instrument. Its latch model
family is symmetric - `slow(off) iff block(A+off) != block(A) and the entry
index matches` - and has no "hits on the next sequential block" member. On a
part that *does* have a data-side prefetch buffer, the fit would return a wrong
granularity rather than `unknown`. The fix is a fourth model member plus an
explicit asymmetry test (`+width` against `-width`), which is an afternoon of
work on the host and needs no new device support. It is not done here because
nothing on this bench has one to validate against.

### 7.3 Write policy - out of reach by construction

Every region the protocol exposes is read-only `const` flash, and every mode is
a read. Write-allocate versus write-through, write buffers, and the cost of a
program or erase against a resident line are all invisible. Reaching them needs
a shim that programs flash from the probe loop - a different instrument, a
destructive one (endurance is finite and the region is in the same bank as the
shim), and one that would have to run with the ART reconfigured mid-operation.
Not a gap worth closing for a memory-*structure* tool.

### 7.4 The instruction path - the instrument and the perturbation are the same object

Every mode is a data read. `ICEN` and `PRFTEN` read *no effect* on every metric
in the cross-product, and that is a correct statement about the data path
and says nothing at all about the instruction side: the probe loop runs from
SRAM precisely so that instruction fetch cannot contend with the reads being
measured, and that choice makes the I-side unobservable in the same breath.

This matters more than it sounds. `hardware/INSTRUCTION_PATH.md` and
`hardware/SCODE_BREAK.md` establish that on the F303 the instruction path
carries a channel the data path does not have, and `nrf52840.md` section 5
finds both a position and a collision channel there. A tool that reports
"`ICEN`: no effect" is, on those parts, reporting the absence of something it
cannot see.

What it needs is a seventh mode - `exec n spacing`, executing n instruction
lines `spacing` bytes apart over flash-resident stubs - which both
`rigs/fw_nrf_probe/` and `rigs/fw_l5_cache/` already implement as
bespoke firmware. It is a protocol change, not a host change, and it is the
single largest gap in `memmap/1` as frozen.

### 7.5 Effects that are not repeatable per-iteration

The counter resolves one core cycle, and `alt` accumulates: at 200 reps the
tool resolves 0.005 cycles per iteration, and it used that to read
`LATENCY - 1` to three decimals in 6a. So *repeatable* sub-cycle effects are
reachable.

What is not reachable is an effect that happens once. The warm-up rule
(`PROTOCOL.md` rule 2) exists because the first access after a knob change is
systematically dearer and would otherwise read as input dependence - and it
removes exactly the measurement that would quantify that first access. Anything
whose cost is paid once per state change rather than once per access is designed
out of this instrument. Accumulation makes it worse, not better: `reps` copies
of a once-only effect is still one effect divided by `reps`.

6a is the same trap from the other side: amplification changed the quantity
being measured. Both directions are why the tool reports the single-shot and the
amplified figure separately instead of picking one.

### 7.6 A structure worth zero cycles

At `LATENCY = 0` the tool reports `read_width: unknown` and `latch: unknown`,
with a caveat naming `MEASURING_CHANNELS.md` B3. That is correct and it is also
a hard limit: a hit and a miss cost the same cycle, so no amount of averaging
separates them. It bites whenever a part must be characterised at *its own*
reset configuration and that configuration is 0 wait states - the structure is
still there, and this instrument cannot see it. Nothing in the timing domain
can; it needs a different observable (a power trace, or a hardware hit/miss
counter, which the F4 ART does not have - the shim answers `C` with
`unsupported`).

### 7.7 Found empirically, and I expected to resolve it: the eviction surface pins `sets x line`, not `sets` and `line`

This one was a surprise, and the tool found it rather than me.

`N_evict(spacing)` for a uniform-stride walk depends on the geometry only
through the conflict period `sets x line` and the ways. Every geometry with
the same product predicts the same number at every spacing - so on the G474,
"8 fully-associative 32 B tags" and "8-way x 4 sets of 8 B lines whose fill unit
is 8 B" are *observationally identical* under every primitive `memmap/1` has. I
checked this against the specific experiments the published work used, including
the one that starts the walk one line above the target: both models predict the
documented `N_evict = 29`, so that experiment does not separate them either.

`infer.py` therefore fits at the measured fetch granularity and reports the
ambiguity rather than printing the first geometry that fits. On the F429 it does
not bite - the conflict period is 16 B and the fetch is 16 B, so `sets = 1` is
forced and "fully associative" is a measurement. On a part where the period is
larger the claim carries the family of equivalent geometries explicitly.

Separating them needs a probe that can distinguish *two words of one line* from
*two lines of one set*: prime several words of one line, evict, and ask about
each of them. `memmap/1` has one target per probe, so it cannot. The experiment
that does work is the G474 "tent" - a random-access working set the size of the
cache, swept across its alignment, where a line-granular cache thrashes at some
offsets and a word-granular one never does. That needs a `rand` or `table` mode.

### 7.8 Also found empirically: a cache bigger than the probe window loses its associativity too

To pin `ways`, the walk has to reach a spacing of `sets x line` and take
`ways` steps at it. Below that, `ways` and `sets` trade off against each other
the same way `sets` and `line` do in 7.7. `tests/test_flashmap.py` demonstrates
it deliberately: a 32 KB 4-way cache probed through a 32 KB window comes out as
`ways: unknown, candidates 1/2/4`, `capacity: unknown`, and a measured floor
of "the target survived N lines, so it holds at least N+1". The tool also prints
the region size that would settle it.

The fix is a bigger probe buffer, not a better instrument - which is a real
constraint on parts where the twin has to fit in RAM. The F429 can afford 64 KB
of each and its cache is 128 B, so it is nowhere near the limit; an H7 with a
32 KB L1 and a DTCM twin is.

### 7.9 `A` is not self-checking

`T` returns a checksum; `A` (the shim-side repeat) returns `min max mean n` and
no checksum, so a probe that read nothing cannot be detected on an `A` result.
The host therefore uses `T` for everything that matters and treats `A` as a
jitter estimate only. Worth fixing in the protocol as `min max mean n checksum`.

---

## 8. One protocol addendum, and why

`evict n spacing [start]`, `start` defaulting to `spacing`. With two
arguments the behaviour is exactly what `PROTOCOL.md` describes, so an existing
shim is unaffected and a host that never passes a third argument sees no change.
With a negative `start` the walk straddles the target, and section 4 is the
result.

I did not edit [`PROTOCOL.md`](PROTOCOL.md) - it is frozen and two other shims
are being written against it. The addendum is implemented in
`rigs/fw_map_f4/`, documented in [`README.md`](README.md) in the conventions
table, probed for at run time by checksum, and skipped silently on a shim that
does not have it (with a line saying so). It is the one thing in this
deliverable that needs a decision rather than a review: without it the
replacement policy is not merely unmeasured, it is unmeasurable, and section 4
is the demonstration.

The shim also returns `err range` when a probe's addresses would leave its
region, rather than wrapping into the shim's own code, and the host reads that
as "not measurable here" rather than as a failure. That is a shim behaviour the
protocol permits (`err <reason>`) and not a change.

---

## 9. Things the run checked that could have made all of this meaningless

Recorded because a silent pass here produces clean, plausible, wrong numbers,
and each of these has produced one on this bench before.

| check | result |
|---|---|
| SysTick advances (measured, not claimed) | `nop 16 -> 136`, `nop 4096 -> 32776` |
| `.ramfunc` copy landed (first word non-zero) | pass - zeros decode as `movs r0,r0` and return the first argument |
| probe loop not optimised away | `walk(64,64) = 1094` vs `nop(64) = 520` |
| checksum tracks the addresses | `0xcedc7e5c` at stride 4, `0x04155804` at stride 64 |
| checksum reproducible across repeats | pass, and constant across all 7 reps of every probe |
| flash and twin read the same bytes | identical checksums, every probe |
| twin is the same size and shape | 65 536 B each, both 4 KB-aligned, identical contents |
| every knob reads back what was written | pass, all four, `FLASH_ACR` read back not echoed |
| capture warnings | none |

The one check that failed on the first build is worth keeping: `nop` initially
cost *more* than `walk`, because the floor loop used a `volatile` stack
accumulator and paid a load and a store per iteration. A floor that is dearer
than the probe it bounds is not a floor. The self-test caught it before any
structural number was taken.
