# Making `flashmap` right on every board it can reach

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

The brief: *"a tool that produces reliable results on all current platforms,
without any hacks or results that require special knowledge. It may be some
cache artifacts cannot be easily determined."*

The standard held to throughout: a result must not depend on the operator
already knowing the answer. A number that is only correct because someone
chose the right sweep parameter for that part is a hack. `unknown` is a good
outcome. A confident wrong answer is not.

Every measurement below is a fresh capture taken today through
[`PROTOCOL.md`](PROTOCOL.md) on the three boards this work owns - NUCLEO-F429ZI,
NUCLEO-G474RE and NUCLEO-L552ZE-Q - with the shims unchanged. Every defect
turned out to be in the host inference or in the plan. Not one was a shim bug,
and no firmware under `rigs/fw_map_*` was modified.

The committed captures (`results/flashmap/f429.raw.json`, `results/flashmap/map_g4.raw.json`,
`results/flashmap/map_l5.raw.json`) were taken part-way through the work, and two plan
details moved after them: the wait-state calibration's divisor was corrected, so
those runs chose `LATENCY = 5` where a fresh run chooses 4, and the phase-2
chase ladder was widened. Neither changes a structural result - every number in
the table below is what `flashmap map --raw` produces from those captures under
the final code, which is exactly what the new regression tests re-check on every
run. Each capture is a complete, unmodified transcript of the board it names.

---

## 1. Where it stands

| | F429 | G474 | L552 |
|---|---|---|---|
| read width | 16 B | 8 B | 8 B |
| fill unit | unknown (see section 4) | unknown (see section 4) | 16 B |
| latch | 1 x 16 B, depth 1 | 1 x 8 B, depth 1 | 2 x 8 B on A[3], depth 1 |
| does a register reach the latch | no | no | no |
| cache | 128 B, 8 tags x 16 B, fully associative | 256 B, 8-way, 32 B conflict period, counted in tags | 8192 B, 16 B line, counted in tags; 1-way/8192 B or 2-way/4096 B by `WAYSEL` |
| replacement policy | LRU, measured against FIFO | LRU, measured against FIFO | LRU, measured against FIFO |
| wait-state scaling | 1.000 cyc/WS | 1.000 cyc/WS | 1.000 cyc/WS |
| twin calibration | +0.000 cyc/access | +0.000 cyc/access | -1.000 cyc/access (isolated config) |
| which knob does what | `dcache` controls reuse and masks the latch | `dcache` controls reuse | `icache` controls reuse; `waysel` re-indexes it at constant capacity |

All three match their ground-truth documents - `research/targets/stm32f4_latch.md`,
`research/targets/stm32g474_art_geometry.md`, `research/targets/stm32l552.md` - with no
part-specific tuning anywhere in the plan or the inference. The L552's four
wrong claims are gone, and the G474 and F429 did not regress.

---

## 2. The four defects, and what the fix actually was

### 2a. `latch = 16 B x 1 entry` on the L552 (truth: 8 B x 2 entries on `A[3]`)

The right fit was already in the evidence - 47/47 offsets fit `8 B x 2` - and
was outvoted by five wait-state cells carrying six offsets each. Six offsets
cannot separate `8 B x 2` from `16 B x 1`: at 0, 4, 8, 16, 32 and 64 the two
models make *identical* predictions. They were nevertheless casting a vote,
because the aggregation counted each configuration's *best fit* and
`_fit_latch`'s tie-break prefers the smaller entry count.

Fix: intersect consistency sets instead of counting best fits. Each resolved
configuration now contributes the *set* of models its own offsets are consistent
with, and the answer is the intersection. A configuration that cannot separate
two models is silent on that distinction rather than voting for one of them.

This is the right weighting and not merely a heavier one, because it is not a
weighting at all: it is the logical content of what each sweep measured.
Evidence density is a proxy for discriminating power and would have been wrong
here in a different way - a dense sweep of only non-negative offsets is no
better at separating an aligned block from a proximity rule than a sparse one.

The claim now also reports what it could *not* separate. If the intersection
holds more than one model the family is listed, the representative is the
*simplest* member of it (fewest entries, then smallest granularity) and the
confidence drops to `low`; if the intersection is empty the configurations
contradict each other, and that is reported as the finding rather than resolved
by preference. The published `research/targets/stm32f4_latch.md` table, fed in literally, is
exactly such an under-determined case - its ten offsets fit `16 B x 1` and
`8 B x 2` equally - and the tool now says so.

Two consequences fell out for free. The L552 latch's *depth* now resolves (1),
because the fit is taken from the dense sweep, which is in a configuration that
has `evict` rows at 16 B; and the aligned-block-versus-proximity comparison now
runs on a sweep that has negative offsets, so the caveat "this claim cannot tell
them apart" is replaced by a measurement (100% against 68%).

### 2b. `waysel -> data_reuse: no effect` on the L552

The knob-map metric was the scalar `max N_evict`, which is 1024 at spacing 8 in
both `WAYSEL` modes. The knob's entire effect is in the *shape*: 1-way = 512
sets with an 8192 B conflict period, 2-way = 256 sets with a 4096 B one, 8 KB
either way.

Fix: the metric is now the fitted `(ways, conflict period, capacity)`
triple, and there is a fourth verdict for what this knob does. A knob may:

* `control` a structure - a matched pair moves it, capacity included;
* `mask` it - the probe stops being able to see it (a cache holding both probe
  addresses hides the latch), which is not the same claim as switching it off;
* `re-index` it - associativity traded against index width at *constant
  capacity*. This is a real category and the tool had no vocabulary for it;
* `confound` it - see 2c.

`waysel` now reports `re-indexes: 1-way/period 8192 B/8192 B -> 2-way/period
4096 B/8192 B`, and the cache claim, which used to file the same fact as
`! Not every knob setting fits the same geometry`, now attributes it: it looks
for a knob that partitions the fitted geometries and says *"`waysel` selects
between them at constant capacity; neither is more true than the other"*.

### 2c. `replacement_policy = pseudo_random` on the L552 (truth: LRU)

Three causes, all of them constants that were secretly facts about one chip.

1. The re-touch discriminator never ran. `default_plan` emitted its `chase`
   at 16/32/64 B, and `Bench.policy_plan` emitted its re-touch walk with
   `ks = (2, 4)` hard-coded - but `k` must be strictly *below* the measured
   associativity, or the target is evicted before the re-touch happens. On a 1-
   or 2-way cache `(2, 4)` yields no rows at all. `ks` is now derived:
   `{1, ways//2, ways-1}` intersected with `[1, ways)`.
2. Phase 2 was sized from the wrong configuration. It used the headline
   geometry, which on the L552 is the `WAYSEL = 0` direct-mapped one - which has
   no victim to choose. It now picks the *isolated* configuration with the
   largest measured associativity and takes the spacing from that
   configuration's own conflict period.
3. The verdict rested on a cyclic chase at `loopmem = 1` - the deliberately
   confounded configuration, on the one part in the rig whose cache is unified --
   at a stride 256x smaller than the conflict period, so it could not have
   reached the knee however large the working set. The chase discriminator now
   requires the stride to be a multiple of the measured conflict period,
   requires adjacent working-set sizes, and refuses to run in a configuration
   where the probe loop shares the structure under test.

With that, phase 2 on the L552 emits `evict n 4096 -4096` in the 2-way
configuration and the answer comes out directly:

```
waitstates=5 icache=1 waysel=1 loopmem=0: evict walk re-touching the target
after k=1 conflicts (spacing 4096, 2-way) loses it at n=4;
LRU predicts 4, FIFO predicts 3   [step sharpness 1.000]
```

which is the hand-measurement in `REQUESTS_g4_l5.md` section 10c reproduced by the
generic tool. On the F429 the same machinery now fires at three re-touch
positions (k = 1, 4, 7 -> n = 10, 13, 16; LRU predicts 10, 13, 16 and FIFO
predicts 9 throughout).

A fourth fix under the same heading: the cyclic chase's "is it a full thrash?"
test compared an absolute miss rate against a miss cost taken from a *different
loop body*. On the L552 a genuinely thrashing 3-line set over a 2-way cache
normalised to 0.75 - close enough to the pseudo-random band that the verdict
would have been decided by the normalisation. The test is now relative: the
plan also emits a working set far past the knee, and the question is what
fraction of *that* the one-line-over case reaches. LRU and FIFO reach 100%; the
synthetic random victim reaches 34%. Every normalisation constant cancels.

### 2d. `twin_calibration = +0.516 cyc/access` on the L552

It averaged four `-1.000` rows from the isolated configuration with `+2`/`+3`
rows from the confounded one and a `+0.5` row from a different loop body. The
headline told the reader to correct in the wrong direction by 1.5 cycles per
access, for every structural claim in the report.

Fix: one number per (configuration, loop body), never pooled across either.
The headline is the isolated configuration - the one every structural claim is
measured in - and it is named in the claim's value, not only in its evidence.
Where the values within that pool disagree by more than 0.25 cyc/access the
claim is `unknown` rather than a mean. The sign is explained in the caveat
rather than flattened to the word "BIASED": a negative value means the flash
buffer measures *cheaper* than its own SRAM twin, which is the bus-port
signature, and correcting means subtracting it.

The L552 now reports `-1.000 cyc/access at 0 wait states in
waitstates=0 icache=0 waysel=0 loopmem=0 (walk body)`, with the confounded
`+2/+3` rows listed in the evidence and marked as such.

---

## 3. The audit: every constant in the plan that was a fact about one chip

This was the highest-value part of the work, and it found more than the brief
listed.

| constant | what it really was | what replaced it |
|---|---|---|
| `ns = [... 28, 29, 30, 31, 32, 33, ... 512, 513, ...]` | 29 is the G474's published transition point and 513 is the L552's. Two chips' answers, written into the sweep that is supposed to discover them | a generated schedule: contiguous 0..32, then every octave bracketed from both sides |
| `chase` at `sp in (16, 32, 64)` | works on a fully-associative 32 B ART, never fires on a part whose conflict period is 4 KB | phase 1 uses the three smallest spacings the region admits, for reuse evidence only; the policy chase is emitted in phase 2 at the measured conflict period, and the inference refuses any chase whose stride does not divide it |
| `policy_plan(ks=(2, 4))` | assumes at least a 5-way cache | `{1, ways//2, ways-1}` from the measured associativity |
| phase 2 sized from `cache.enabled_in` | the configuration with the most *reuse*, which can be the direct-mapped one | the isolated configuration with the largest measured associativity |
| `_reference_waitstates`: "smallest advertised value >= 4" | assumes one wait state is worth one cycle - true of every part in this repository, and not a property of the protocol | `Bench.calibrate_waitstates` measures the flash penalty each advertised setting delivers, with every other knob at its minimum, and picks the cheapest that clears 4 cycles. The old rule survives only as the offline fallback |
| `reread` offsets, hand-listed | a list that happened to straddle the boundaries of the parts on the bench | generated from `LATCH_GRANULARITIES`, the same ladder `infer.py` fits over, so the sweep is guaranteed to straddle every boundary any candidate model draws |
| `alt` offsets `(0, 4, 8, 16, 32, 64)` | the same | the same ladder |
| `spacings` starting at 8 | assumes no part has a 4-byte fetch unit | every power of two from 4 upward that the region admits |

Two further constants were left in place, deliberately, and are named here so
they are not mistaken for oversights:

* `MAX_PLAUSIBLE_LINE = 64` in `infer_cache`, used to decide that an
  8192-byte conflict period is an index period rather than a single cache line.
  This is a fact about cache design in general, not about a part; no
  microcontroller has a line above 64 bytes. It is an architectural prior and it
  is stated in the claim's evidence.
* `_MIN_MISS_CYCLES = 4.0`, the separation a miss must have before hit and
  miss can be told apart. This is a property of the *instrument* - an
  integer-valued counter and a twin that can be a cycle off - not of any part,
  and it is now what the wait-state calibration measures against rather than a
  wait-state number.

### What was NOT done, and why

`REQUESTS_h7_nrf.md` section 4a asks for the read-width aggregation to "take the modal
value across configurations". That would fix the H723 and break the L552: on
the L552's isolated grid the two saturation strides are 2 configurations each --
a tie - and on the full grid the majority (6 of 8) is the 16-byte *fill unit*,
not the 8-byte read width. Modal is a rule that happens to work on one part.

The rule adopted instead is the same one that fixed the latch: a structural
claim is decided on the isolated cross-product grid at the reference wait state,
and the wait-state sweep cells do not vote. They exist to fit a slope and they
include `LATENCY = 0`, where every flash structure reads flat by construction.
That single `waitstates = 0` cell was the one configuration in thirty-eight that
saturated early on the H723. And where the saturation stride still is not
invariant, the tool now checks whether a knob explains the split: a fill unit
is something a knob enables, so if no knob separates the early-saturating
configurations from the rest, the claim says so and drops to `low` confidence
instead of printing a tidy two-number answer.

I could not re-infer the H723 itself - there is no committed raw capture for it
and the board is another agent's - so the fix is carried by two regression tests
that reproduce the shape
(`test_one_waitstate_sweep_cell_cannot_set_the_read_width` and
`test_an_unexplained_split_is_not_reported_as_a_fill_unit`). Re-running
`flashmap map --raw` over an H723 capture is the check that remains outstanding.

---

## 4. What is still `unknown`, and whether that is reachable

Only the last of these is "merely unmeasured".

Unreachable with `memmap/1`'s primitives - more traces cannot fix them:

1. The G474's `sets` and `line` separately. A uniform-stride eviction surface
   pins the *conflict period* `sets x line` and the ways, and nothing in the
   protocol separates the two factors: "8 fully-associative 32 B tags" and
   "8-way x 4 sets x 8 B lines" predict the same number for every mode here.
   Capacity (256 B) and ways (8) are measured; the split is reported as a family,
   not chosen. Separating them needs a probe that distinguishes "two words of one
   line" from "two lines of one set" - a randomly addressed working set swept
   across its alignment - and there is no mode for that.
2. `ways` against `sets` when the cache is large relative to the probe
   window. `ways` conflicts in an S-set cache and `ways/2` in a 2S-set cache
   land at the same walk index, so the two are separable only by a spacing at or
   above the larger conflict period. Where the region is too small the tool
   reports a capacity floor and names the probe region size that would settle
   it. That is not the case on any of my three boards; it is on the H723 through
   a 64 KB window, which
   `test_h723_associativity_is_unknown_when_the_region_is_too_small` pins.
3. The L552's two latch entries against a two-line direct-mapped cache.
   Behaviourally the same object under every primitive here, and the part's own
   hit/miss counters read zero in the only configuration where either is visible.
   An identifiability limit, not a resolution limit.
4. True LRU against tree-PLRU. The re-touch walk separates LRU from FIFO and
   nothing more. Both are "recency", and the reference strings this protocol can
   build do not distinguish a true LRU stack from a tree approximation of one.
5. The instruction side, independently of the probe loop. With the loop in
   flash, a walk over the *SRAM* twin - zero cacheable data accesses - still
   counts hundreds of instruction-fetch hits on the L552. Reaching it needs an
   `exec <n> <spacing>` mode that executes flash-resident code at known
   addresses. `PROTOCOL.md` has no such mode and this work did not add one.
6. `fill_unit` on the F429 and the G474. Reported `unknown`, and that is the
   correct answer: on both parts every knob setting saturates at the same stride,
   so no fill unit is *distinguishable* from the read width. On the L552, where
   `icache` does move the saturation, it comes out at 16 B and is confirmed twice
   - by the warm walk and by the eviction surface.

Reachable, and a real caveat rather than a gap:

7. The L552's `flash - twin` is not an unbiased estimator. `-1.000
   cyc/access` with the probe loop in SRAM, positive with it in flash, and
   loop-body dependent. The instrument-neutral quantity
   `flash(LATENCY) - flash(0)` is unaffected, and the claim now says so and names
   the configuration. Why the older bespoke `fw_l5_cache` reads one cycle per
   access dearer on the flash column remains unexplained
   (`FINDINGS_g4_l5.md` section 2c).
8. One die, one clock, 16 MHz. Every repeat has `min == max`. That is
   repeatability, not accuracy, and item 7 is exactly the kind of systematic
   error no number of repeats would reveal.

### One false alarm removed on the way past

A guard requested in `REQUESTS_g4_l5.md` - "a cache-enable knob reported as
reaching nothing is more likely a classifier problem than an inert register" --
turned out to be wrong for `icache`, and it fired on the F429 and the G474 as a
`high`-confidence caveat saying *"treat this as a measurement or classification
failure"*. It is not one. Every primitive in `memmap/1` is a data access, so an
instruction cache that is not unified with the data path is invisible to all
three metrics by construction, and that is the published result for both
parts. The guard now covers only `dcache` and `unified`, whose structures the
probe can actually see; for `icache` the tool states the positive version
instead, and it does not need a special case for the L552, whose unified ICACHE
comes out controlling data reuse from the same measurement.

---

## 5. Protocol changes, proposed with their reasoning

Both are in [`PROTOCOL.md`](PROTOCOL.md), in the style the `evict start`
extension was adopted in.

* `loopmem` is now a canonical knob, with `0` = probe loop in RAM/ITCM
  (isolated) and `1` = in flash (deliberately confounded). It has to be canonical
  because the host must be able to tell an instrument control from a device
  register *by name*: a shim that called it `iloc` would have the host report
  "a register reaches the latch" on the L552, where the truth is that running the
  probe from flash destroys the measurement. With the name fixed, the host takes
  every structural claim from `loopmem = 0`, reports a difference across it as
  `confounds` rather than `controls`, refuses to read a replacement policy out of
  a `loopmem = 1` configuration, and never pools a twin calibration across it.
* The smallest advertised value of every knob is its least-accelerated
  state. Every shim already does this; it is now written down because the host
  relies on it in two places a transcript does not reveal - the wait-state
  calibration runs with every other knob at its minimum, and `min(values)` is
  taken as `loopmem`'s isolating value.

Two host behaviours are documented but change no wire format: the wait-state
calibration pass before the plan, and the second pass sized from the first pass's
geometry. A shim needs to do nothing for either beyond honouring `evict`'s
optional third argument; one that does not gets the cyclic chase alone and an
honest `LRU or FIFO`.

---

## 6. Regression tests

`tests/test_flashmap.py` now carries three layers.

* Synthetic parts (unchanged): a mechanism-level model of a memory system,
  configured as each of the six parts.
* Published tables (unchanged): the literal tables from the `hardware/*.md`
  write-ups.
* The real captures, re-inferred (new): `infer.py` is run over the committed
  `results/flashmap/f429.raw.json`, `results/flashmap/map_g4.raw.json` and
  `results/flashmap/map_l5.raw.json`, and the published structure is asserted. Every one
  of the L552's four wrong claims has an assertion, including the two that are
  about *how* the answer was reached: `does not discriminate` must appear in the
  latch evidence, and `waysel` must be `re-indexes` with a reason that mentions
  capacity. A fourth test asserts the honesty properties across all three
  captures - an under-determined latch model family must cost confidence, and
  `pseudo_random` may only ever be claimed from an isolated configuration at a
  conflicting stride.

These cost nothing to run - `--raw` re-inference touches no hardware - and they
are what stops a fix for one part from silently breaking another, which is how
three of the defects above reached the output in the first place.

`pytest tests/test_flashmap.py -q` and the whole-repository `pytest tests/ -q`
both pass.

Outstanding, and not mine to do. `flashmap/h723.json` and
`flashmap/nrf52840.json` are inferred structures with no committed raw capture
beside them, so they could not be re-inferred here and are now stale with
respect to `infer.py` - `h723.json` in particular still carries the
`read_width = 8` this work fixed the cause of. Whoever owns those boards should
re-run `flashmap map --raw` over their captures (or re-capture with `--rawout`,
which is what makes a structure file reproducible at all) and commit the raw
alongside, so the same real-capture regression test can cover them.

---

## 7. Bench notes, not tool defects

* The NUCLEO-F429ZI stopped answering on COM9 twice during this work, once
  between sessions and once immediately after a `map` run, and
  `boards.py reset` did not recover it - only a reflash did, after which three
  consecutive sessions passed. It also refused to open with
  `PermissionError: Access is denied` for a minute or so afterwards. It looks
  like the ST-LINK VCP wedging rather than the shim being damaged, and running
  three captures in parallel seems to make it likelier. Recorded because a future
  run that sees this should reach for `boards.py flash` rather than start
  debugging the shim.
* Long captures must be launched with an explicit tool timeout. A foreground
  command that overran its own 120 s budget took two running background captures
  down with it.

---

# Part 2 - the discriminating-power rule, and the defects it closed

A second pass, on the two boards the first one could not reach (NUCLEO-H723ZG
and nRF52840-DK) plus a re-derivation of all five committed captures. Three
defects were named going in; a fourth turned up on the way, and an independent
re-derivation of the same raw JSON - written without reading `infer.py` - found
a fifth and corrected one of my own fixes for being a step too pessimistic. All
of them are the same disease as Part 1's four.

Everything below is reproducible offline: `flashmap map --raw <capture>` over
`flashmap/{f429,h723,nrf52840}.raw.json` and `hardware/map_{g4,l5}.raw.json`.
One hardware run was taken, on the H723 (COM21), to settle a question the
committed capture could not.

---

## 8. The rule

> Before a configuration is allowed to contribute evidence for or against a
> claim, it must be established that the configuration could have shown the
> opposite. A cell with no discriminating power is silent; it is not a vote for
> the thing it happened to display.

This is a positive control, and it now lives in one place  - 
`_discriminating_power(ms, cfg)` in `infer.py` - that every claim consults,
rather than in five per-claim patches. Three properties make it work:

It is asymmetric, because the two directions are not equally demanding. A
configuration that *showed* a difference has demonstrated its own discriminating
power and needs no control. A configuration that showed *no* difference is
claiming an absence, and an absence is only a measurement if the presence would
have been visible. So the control is consulted for flat cells and nowhere else.
Getting this backwards costs a real result: the STM32F303's published "no
data-side reuse of any kind" is a flat cell, and a symmetric rule silences it.

The control is measured inside the flash column, never against the twin. It
is `flash(LATENCY) - flash(0)` at the same stride with every other knob equal  - 
both halves flash, so the twin and every instrument offset it carries cancel
exactly. Where a capture has no `waitstates = 0` cell to reference against, it
falls back to the twin and says so in the reason.

It is not the obvious control. The natural-looking one - compare a stride-0
walk against a saturated walk in the same cell - is *circular* for the latch: a
part with no latch reads zero there for exactly the reason the claim is trying to
establish. That is the F303 again, and it is why the control asks the narrower
question "does this cell resolve the flash array's own access cost at all?".

The resolution floor is one cycle: these counters are integer-valued, SysTick
runs at the core clock on every part here, and (outside the H723) every repeat in
every capture has `min == max`. That is a property of the instrument, not of a
part.

---

## 9. The defects

### 9a. `knob_reaches_it: True` on the H723's latch, which no register reaches

The caveat said it outright: three settings - `waitstates = 0, 1, 2` - showed "no
data-side reuse at any offset, including offset 0". Only one of those three is
actually blind, and the premise I was given for the other two was wrong in a way
worth recording, because it points at the real fix.

At `waitstates = 1` the flash `reread` column reads 13, 13, 13, 13, 14, 14
over offsets 0/4/8/16/32/64 - identical in all seven repeats, `hi == lo`. At
`waitstates = 2` it reads 13 against 15. That is a one- and two-cycle split with
zero variance on a counter whose tick is a core cycle: a measurement, and one
that resolves the latch perfectly at granularity 32. The `waitstate_scaling`
claim was already reading exactly those rows and getting 1 and 2 cycles out of
them.

What made them vanish was the twin. Classification compared `flash - twin`
against half the miss cost, and on this part the DTCM twin sits +3 cycles
under the flash `reread` body at every offset. A 1-cycle differential rides on a
3-cycle pedestal and lands on the wrong side of the cut. So the fix is not to
silence those cells - it is to stop classifying against an absolute threshold at
all:

> `_classify_reread` now splits each configuration's column at its own largest
> gap, and falls back to the twin-referenced test only when the column shows
> one level. A within-column split needs no calibration, because the pedestal is
> common to both levels and cancels.

Only `waitstates = 0` is genuinely blind, and there the control fails by
construction: `flash(0) - flash(0) = 0`. It is now silent, and the claim says
which cells were silenced and why.

Result: `knob_reaches_it: False`, `32 B x 1 entry`, depth 1, confidence
`high` - the published H7 result, with `dcache` correctly filed as `masks`.

### 9b. The H723 cache geometry

Reported `1-way / 2048 sets / 65536 B`, against a CCSIDR read over SWD of 4-way /
256 sets / 32768 B. Not merely unsupported: refuted. A 64 KB way size makes
eviction impossible inside a 64 KB probe region, and nine rows in that capture
evict.

Three things were wrong, and they compound.

1. `_n_evict` smoothed away a falsification. It returned "the smallest `n`
   that is slow *and stays slow*". At spacing 512 the target is lost at `n=64`
   and present again at `n=65`, so 64 was discarded and 96 reported; at spacing
   2048, 17 was discarded and 25 reported. The surface is not a step function
    -  and a threshold is precisely what `N_evict` means. `_evict_shape` now
   classifies each series as `threshold`, `uncorroborated` (the only slow reading
   is the largest `n` tested - a bound, not a value), `survived`, or
   `non_monotone`, and a `non_monotone` series is not fitted at all. This is the
   same rule applied to a *model* instead of a configuration: before the fit
   reads `N_evict` off a series, the series has to be the kind of thing
   `N_evict` describes.

2. The capacity was recoverable and I was a step too pessimistic. My first
   fix reported no geometry and no capacity. The independent re-derivation
   pointed out what the rows do support, sharply: for a uniform walk at any
   spacing that divides the conflict period, the target is lost after exactly
   `ways x sets x line` bytes of span, independent of how the capacity splits
   into sets and ways. So the *smallest loss span anywhere on the surface is the
   capacity*, read off directly with no fit - and it uses only the bottom edge of
   the surface, where every measurement agrees, so the non-monotonicity above it
   cannot touch it. `_span_capacity` implements it:

   | part | smallest loss span | published capacity |
   |---|---|---|
   | F429 | 128 B | 128 B |
   | G474 | 256 B | 256 B |
   | L552 | 8192 B | 8192 B |
   | H723 | 32768 B (417 rows below it, none lost) | 32768 B (CCSIDR) |

   Exact on every part, and it replaced the `(ways, sets)` fit as the capacity
   instrument rather than sitting beside it.

3. `capacity_bytes_min` was not a floor. It read 512 B on a part whose
   capacity it also reported as 128 B, and 49184 B on the H723's 32768. It
   counted *accesses* rather than lines (at a sub-line spacing four accesses
   share a line, and the first few are the target's own) and it took the *largest
   survival* at any spacing, which bounds nothing once retention is non-monotone.
   It is now the largest span below the first loss.

Result: `capacity 32768 B, 32 B line`, with the `(ways, sets)` split reported
as a family - `1-way x 1024 sets`, `2-way x 512 sets`, `4-way x 256 sets`,
`8-way x 128 sets`, …  -  that *contains* the register truth, where the old answer
sat outside it. Confidence `low`, and the caveat names what would settle it.

What probe size would settle it. Every spacing this capture used is at or
below the smallest candidate way size, and in that regime all the candidates
predict the same loss span. Separating them needs a spacing above the largest
candidate period (32768 B), where the loss lands at `n = ways` directly:
`evict n 65536` with `n` reaching 8 is a probe region of 589824 B, and the
H723 has 1 MB of flash against the 51200 B this shim's `evict` reaches. So
this one is closable, and by a shim change rather than by more traces. (Reaching
every member of the family, up to 64-way, would need 4259840 B; the tool quotes
both and names `<= 8-way` as the architectural prior it is.) The old answer's
64 KB way size was refuted precisely because it exceeded the window: no two
addresses in a 64 KB probe region can share a set under it, and nine rows evict.

### 9c. The nRF latch claim was internally inconsistent

`model_determined: False` beside an empty `equivalent_models: []` - which
asserts both that the answer is undecided and that nothing is a candidate.

The assembly bug was real and is fixed (the family now always contains at least
the model being reported, and `model_determined` is derived from its size rather
than computed alongside it, so the two cannot disagree). But the *cause* was
somewhere else entirely, and it is the most interesting thing in this pass.

`_latch_models()` searched the target's alignment within its block in steps of
4, on the reasoning that the probe reads 4-byte words. A 4-byte read at offset
`off` touches bytes `off … off+3`, so the boundary the sweep sees is set by the
last byte read - which puts the effective alignment at 3 modulo the
granularity on any part that latches the block of the last access. The H723 and
the nRF52840 both do: their fast window runs from `-1`, not from 0.

Every sweep whose offsets are all multiples of 4 cannot tell `a = 0` from `a = 3`
and never noticed. The two parts whose plans include *odd* offsets did notice,
and the consequence was not a slightly worse fit - it was that no model in the
family fitted their densest sweep exactly, so the 89-offset sweep was dropped
from the intersection entirely and the answer fell to the six-offset wait-state
cells. On the H723 that produced a family of six; on the nRF, which has only four
configurations and no wait-state knob, it left the intersection empty.

> The most informative measurement on each part was discarded for being two
> offsets short of a model family that was two offsets too narrow, and the
> conclusion was taken from the least informative cells. That is the Part 1
> disease exactly, arriving through the model grid instead of through the
> aggregation.

With alignment searched at byte resolution, exactly one `(granularity, entries)`
survives on every part: F429 `16B x 1`, G474 `8B x 1`, L552 `8B x 2`, H723
`32B x 1`, nRF `16B x 1`. Two boards moved from `low` to `high` confidence and
nothing else moved at all.

### 9d. A fourth defect: `replacement_policy = not_applicable` at `high`

Not in the brief, and the worst of the four. The whole evidence line was *"every
configuration fits 1-way"*  -  from four configurations that all have
`dcache = 0`, where the cache is switched off and the only structure left is
the 1-entry latch, which of course fits 1-way. A `high`-confidence positive claim
about the part, carried by cells with nothing to say, on top of a `ways = 1` the
same data refutes. It is also self-contradictory: a direct-mapped cache cannot
produce a victim that changes between repetitions of the same row.

Three gates now stand in front of it: configurations where the cache is off are
excluded from the exported geometry table; the `not_applicable` shortcut requires
an associativity that was actually determined; and a falsified threshold model
blocks it outright. The H723 now reports `unknown`.

That verdict is also unreachable on this part for a second, independent reason
worth stating: the LRU/FIFO discriminator needs `evict n spacing -k*spacing` at a
multiple of the conflict period, the second pass is sized from a measured
geometry, and there is none. Through a 64 KB window the H723's replacement policy
is out of reach.

---

## 10. What the capture itself says, and one thing it cannot

The H723's eviction surface is non-monotone, and there are two very different
explanations: a non-deterministic victim (the target survives past capacity
some of the time - the documented Cortex-M7 L1 default), or an
address-dependent effect the `(ways, sets, line)` family cannot express. They
are separable by reproducibility, and my first attempt separated them the wrong
way.

What I got wrong. I wrote a check that read `min == max` off the stored
repeats and concluded "reproducible, therefore not a random victim". The kept
repeats are a filtered sample: `Bench` discards a warm-up repetition before
taking the median, and `meta.warnings` records that discarded reading disagreeing
with the seven kept ones for 16 distinct `(n, spacing)` pairs, in both
directions - exactly the threshold region the geometry is fitted from. The
disagreeing sample is the one that was thrown away, and it is not in
`obs[].raw`. `_repeats_agree` now returns "unknown" whenever the capture's own
warnings report an `evict` outlier, and the cache claim carries the fact as a
caveat. Recommendation for the shim/host: carry the warm-up reading in `obs[]`
rather than in prose.

What two hardware runs settled, and it is not what I first wrote. I
re-measured `evict` at spacings 512, 2048, 4096 and 8192 on the H723 (COM21) in
three passes: two forward and one with the plan order reversed. The two forward
passes are bit-identical to each other; the reversed pass differs at `sp = 8192`
`n = 10/11`, at `sp = 4096` `n = 9/15`, and at `sp = 512` `n = 67-73`. I read
that as order dependence, and it is - but of a specific reading. That probe took
single-shot measurements, which is exactly the repetition `Bench` discards.
So what moves with the order is the warm-up reading, and it moves on
precisely the rows the capture's own warm-up warnings name.

A second full `map` run then settled the other half. It carried the new replay
pass (32 `evict` rows re-measured at the end, in reverse order, around the
measured 32768 B capacity) and every replayed row came back identical. So at
median-of-seven the H723's eviction surface *is* reproducible, order and all -
and its non-monotonicity is therefore a real, repeatable response, not
measurement noise. The whole structure re-derived identically from that fresh
capture: 32 B read width, `32B x 1` latch that no knob reaches, 32768 B capacity,
policy unknown.

Put together: `PROTOCOL.md` rule 2 ("a fixed warm-up access precedes every timed
access, so each probe enters from the same state") does not hold on this part
- one warm-up access cannot restore 32 KB of L1 data cache, and the first reading
after a different predecessor differs. What the median protocol does is hide
that, by measuring a state the probe has warmed itself into. That is defensible,
but it means the discarded reading is data and belongs in `obs[]`.

So the tool now has a replay control. A third pass, emitted after the others
and sized from the first pass's measured capacity, re-measures the `evict` rows
nearest the capacity threshold in the opposite order. Where a replayed row
disagrees, the eviction surface is not a measurement of a geometry and none is
reported (`_replay_disagreements`, with a synthetic regression test). It is sized
from the first pass for the same reason the policy probes are: where retention is
marginal is not known until the capacity has been measured.

Honest accounting of what it has proved: on the H723 it is armed and has not
fired, and the run above is why that is the right answer rather than a failure.
It would fire on a part whose median readings move with the plan order, and it is
cheap. Catching the warm-up-level instability instead needs the discarded
repetition carried in `obs[]`, which is a shim-and-host change this pass did not
make.

---

## 11. Coverage gaps, recorded rather than closed

The tool now prints each of these as a note on any capture that has them.

* Both parts with hardware hit/miss counters never used them. The nRF52840
  (`NVMC.IHIT`/`IMISS`) and the L552 (`ICACHE_HMONR`/`MMONR`) advertise
  `counters`, and neither capture contains a single reading. `PROTOCOL.md` calls
  these an independent instrument; on the nRF a counter read would settle the one
  claim the timing cannot touch at all (does the I-cache exist, and what is its
  geometry), and on the L552 it would give the `waysel` re-indexing - which rests
  on two spacings - a second witness.
* Geometry is probed at exactly one wait-state setting on every part. All
  four parts with a `waitstates` knob have zero `evict` and `chase` rows
  outside `waitstates = 5`. Nothing suggests the geometry moves with the latency;
  nothing here tests it either, and `research/targets/stm32g474_latency0.md` exists because
  `LATENCY = 0` is a case where behaviour does change.
* The H723's twin is DTCM, and that is the right choice with a price.
  `FINDINGS_h7_nrf.md` section 3.1 shows why the shim picks it: the only other
  same-size region, `axisram`, sits *behind* the L1 D-cache, so using it as the
  twin would put the structure under test on both sides of the subtraction. But
  a zero-wait tightly-coupled memory is not on the same fabric as the flash
  either, so the subtraction leaves a constant `+3` to `+4` behind instead of
  cancelling - and section 9a is that constant swallowing a real signal. There
  is no third option on this part; the answer is not a better twin but not
  classifying against the twin at all, which is what section 9a now does. The
  twin claim's sign explanation is also written for the sign actually measured
  and names the twin's declared kind, instead of reciting the L552's
  SRAM-contention mechanism next to a positive number on a board with no SRAM
  twin.

* The H723 L1-I (32 B / 2-way / 512 sets) and the nRF's 2 KB I-cache are
  entirely out of reach. Every primitive in `memmap/1` is a data access and the
  probe loop runs from ITCM/RAM, so `icache` changes nothing in any measurement
  on either part. This is the same wall as Part 1 section 4 item 5: it needs an
  `exec` mode.

---

## 12. What changed, per part

Nothing moved on the F429, the G474 or the L552 except three capacity floors that
were above the capacity they bounded. (The floor is now the largest measured
working set below the first loss, so it sits one probe step under the capacity
rather than on it - a floor, which is what it claims to be.) No previously-correct answer became
`unknown` - the one candidate for that, the F303's "no data-side reuse at all",
is what made the rule asymmetric.

| | F429 | G474 | L552 | H723 | nRF52840 |
|---|---|---|---|---|---|
| read width | 16 B | 8 B | 8 B | 32 B | 16 B |
| fill unit | unknown | unknown | 16 B | unknown | unknown |
| latch | 1 x 16 B, d1 | 1 x 8 B, d1 | 2 x 8 B on A[3], d1 | 1 x 32 B, d1 *(was: family of 6, depth unknown)* | 1 x 16 B, d1 *(was: empty family)* |
| latch model determined | yes | yes | yes | yes *(was no)* | yes *(was no)* |
| latch confidence | high | high | high | high *(was low)* | high *(was low)* |
| a knob reaches the latch | no | no | no | no *(was yes)* | no |
| cache capacity | 128 B | 256 B | 8192 B | 32768 B *(was 65536 B)* | none |
| ways / sets | 8 / 1 | 8 / 4 | 1 / 512 (2 / 256 at `waysel=1`) | family of 7, contains 4 x 256 *(was 1 / 2048)* |  -  |
| capacity floor | 124 B *(was 512 B)* | 252 B *(was 512 B)* | 8188 B *(was 32768 B)* | 32736 B *(was 49184 B)* |  -  |
| replacement policy | LRU | LRU | LRU | unknown *(was `not_applicable`, high)* |  -  (no cache) |
| wait-state scaling | 1.000 | 1.000 | 1.000 | 1.000 | no knob |
| twin calibration | +0.000 | +0.000 | -1.000 | +4.000 (`walk`), +3.000 (`reread`) *(was +2.000 - a median over two configurations, the one thing this claim exists to forbid)* | no knob |

Every cell in the H723 and nRF columns now matches `research/targets/stm32h723.md` and
`research/targets/nrf52840.md`, or says `unknown` with the measurement that would
close it.

---

## 13. Regression tests

`tests/test_flashmap.py` gains a real-capture test for each of the two parts that
had none (`test_real_h723_capture`, `test_real_nrf52840_capture`) and two
invariant suites parametrised over all five committed captures:

* `test_every_real_capture_keeps_its_claims_self_consistent` - one assertion per
  defect that shipped: a model family may be large but never empty while the
  model is undetermined; a capacity floor may never exceed the capacity it
  bounds; an undetermined associativity must come with its family and with what
  would settle it; and `not_applicable` may only be claimed from a determined
  `ways`.
* `test_no_claim_rests_on_a_cell_that_could_not_discriminate` - the general rule
  itself: every `waitstates = 0` cell must fail the control, and no cell that
  fails it may appear as a knob setting that removed something.

Plus `test_replay_control_refuses_a_geometry_when_a_row_does_not_reproduce` and
`test_kept_repeats_are_not_evidence_when_the_capture_reported_outliers`, which
are synthetic because neither can be provoked on demand from hardware.

One existing assertion changed wording rather than substance
(`test_h723_associativity_is_unknown_when_the_region_is_too_small`), and it
gained the assertion that was missing: that the floor is at or below the true
capacity.

`python -m pytest tests/ -q` is 181 passed, 16 skipped (197 collected),
against 167 passed / 16 skipped before this pass: fourteen new tests, no
regressions, and the same sixteen skips.
