# `flashmap` - reverse-engineering a microcontroller's memory system

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

One firmware shim per part, one host tool, and a structure at the end
rather than a table a human reads.

`flashmap` measures flash read width, read latches, data and instruction
caches, and the configuration knobs that move them. It measures
*structure*, not secrets. It's not a crypto tool and imports nothing from
`flashsim`, `flashattack` or `flashleak`; `tests/test_flashmap.py` asserts
that.

```
python -m flashmap selftest --port COM9
python -m flashmap map      --port COM9 --out flashmap/f429.json --rawout results/flashmap/f429.raw.json
python -m flashmap map      --raw results/flashmap/f429.raw.json   # re-infer, no hardware
python -m flashmap compare  f429.json g474.json
```

## Why it exists

This repository already contained five bespoke probes -
`f4_latch_probe.py`, `g4_cache_probe.py`, `l5_cache_probe.py`,
`h7_cache_probe.py`, `nrf_cache_probe.py` - each with its own firmware,
each answering the same question for one part, each printing a table
someone then interpreted by hand. The write-ups those produced
(`research/targets/stm32g474_art_geometry.md`,
`research/targets/stm32f4_latch.md`, `research/targets/stm32l552.md`,
`research/targets/stm32h723.md`, `research/targets/nrf52840.md`) are this
tool's ground truth: it has to rediscover what they established without
being told.

What's generalised is the *reasoning*, not the tables.

## Layout

| file | what it is |
|---|---|
| [`PROTOCOL.md`](PROTOCOL.md) | the device protocol, `memmap/1`. Frozen. |
| `device.py` | the protocol driver. Thin, paranoid, and it never invents a value the shim did not send. |
| `experiments.py` | the probe primitives, the SRAM-twin rule, the repeat/statistics discipline, and the measurement plan. |
| `infer.py` | raw `(config, mode, args, cycles)` tuples -> a structure with confidences and evidence. The interesting part. |
| `report.py` | renders a "measured datasheet", markdown, JSON, and a two-part diff. |
| `__main__.py` | `selftest`, `map`, `compare`. |
| [`FINDINGS.md`](FINDINGS.md) | what it measured on the F429, against the published numbers, and what this method cannot reach. |

## What `infer.py` claims, and how

Every claim carries a value, a confidence, the method that produced it, the
measurements that support it, and its caveats. A claim the data cannot
support comes out as `unknown`, never as a guess.

### Read width
Cold forward stride walk, flash minus its own SRAM twin. The per-access
cost rises with the number of distinct flash words touched and saturates at
one word per access; the saturating stride is the read width.

This is a property of the flash array rather than of the accelerator, so it
must be invariant across every knob setting, and the tool checks that
rather than assuming it. Where it isn't invariant, the smallest saturating
stride is the array's read width and the largest is a cache's fill unit (a
line-filling cache saturates only once the stride reaches the line). Both
are reported, and `knob_map` cross-checks that no knob moved the width.

### Latch
`reread off`: read A, read A+`off`, time a re-read of A. The whole offset
sweep is fitted against a model family

```
slow(off)  iff  block(A+off) != block(A)  and  entry(A+off) == entry(A)
block(x) = x >> log2 g          entry(x) = block(x) mod k
```

over granularity `g`, entries `k` and the target's own alignment. That
single family covers the F429/G474/H723/nRF52 one-entry latch and the
L552's *two* entries indexed on address bit 3, which is the case a "one
16-byte latch" reading gets wrong, and which is only visible because the
sweep is dense across the boundary.

The sweep is SIGNED, which is what separates a latch holding one aligned
flash word from a "within ±g bytes" proximity effect: with an aligned
target the two models disagree on every negative offset. The tool fits the
rival model too and reports which won.

*Depth* comes from `evict n spacing` at a spacing that maps back to the
same entry. *Whether any knob reaches it* comes from repeating the sweep at
every knob combination, and a configuration where the probe reads uniformly
FAST is reported as *masking* rather than absence: a cache big enough to
hold both probe addresses hides the latch underneath it.

Configurations get combined by what they exclude, not by majority. Each
resolved configuration contributes the *set* of models its own offsets are
consistent with, and the answer is the intersection. A sweep of six offsets
fits `16 B × 1` and `8 B × 2` equally perfectly - at those six offsets the
two models predict the same thing - so it must not get a vote against a
47-offset sweep that separates them. Counting best-fits let five
six-offset wait-state cells outvote the one dense sweep and report the
L552's two entries as one 16-byte latch. If the intersection holds more
than one model the family is reported as such, the representative is the
*simplest* member of it, and the confidence drops; if it's empty the
configurations contradict each other, and that is itself the finding.

### Cache
`evict n spacing` over a spacing sweep. `N_evict(spacing)` is fitted
against an exact enumeration of which walk addresses land in the target's
set, so there's no special case for sub-line, line-sized or aliasing
spacings.

Two distinctions the tool is built around:

* Capacity in tags versus capacity in bytes. Walk one word of each of `n`
  fresh lines. A structure whose allocation unit is the tag evicts after
  `ways` of them; a flat budget of `capacity/read_width` word slots would
  survive far longer. On the G474 those are 8 and 32 and 8 is measured -
  the tag is claimed whole even though only one of its four doublewords
  was fetched.
* Indexed versus fully associative. Vary the spacing of the working set. An
  indexed cache's `N_evict` collapses to `ways` at multiples of
  `sets × line` and is larger in between; a fully-associative one is flat.
  `sets = 1` isn't a special case in the fit, it's just the answer.

Where the evidence doesn't pin the geometry, the tool says so rather than
printing the first thing that fits. See FINDINGS.md §"what this cannot
reach", which is a deliverable rather than an apology.

### Replacement policy
Two instruments: the sharpness of the eviction step (a deterministic victim
makes `N_evict` a hard threshold; a random one makes survival probabilistic
and the step graded), and a cyclic `chase` one line past the working-set
knee (LRU and FIFO both thrash completely there; pseudo-random does not).

LRU and FIFO are NOT separable with `memmap/1` as frozen, and the tool says
so every time rather than picking one. That's a property of the primitives:
every mode produces a reference string that is monotone or cyclic, and on a
cyclic string over capacity+1 lines LRU and FIFO evict the same line at
every step.

Where the shim offers the optional third `evict` argument (see the
conventions table), a second phase of `map` runs a walk that passes
*through* the target, and the policy becomes measurable: LRU loses the
target at `ways + k + 1` and FIFO at `ways + 1`, so a sweep over `n` at two
values of `k` decides it. On the F429 the answer is LRU, at both re-touch
positions, exactly on the prediction. The host verifies the shim honoured
the argument by the checksum, since a shim that ignored it would return the
default walk and read as FIFO.

Both discriminators are sized from the geometry the first pass measured,
not from a constant. A re-touch walk only reaches the target's set if its
spacing is a multiple of the measured conflict period, and only
discriminates if `k` is strictly below the measured associativity; a cyclic
chase only ever conflicts if its stride is a multiple of that same period.
Emitted at a fixed 16/32/64 B they work on a fully-associative 32-byte ART
and never fire at all on a part whose conflict period is 4 KB, and a fixed
`k ∈ {2, 4}` produces no usable row on a 1- or 2-way cache. `infer.py`
enforces the same two preconditions when reading rows back, so an old
capture taken at the wrong stride is refused rather than interpreted. A
configuration whose probe loop lives in the memory under test is excluded
outright: there a "partial hit rate over the knee" is the loop's own
footprint and not a random victim, and reading it as `pseudo_random` is a
positive claim in the wrong direction.

### Which knob controls which structure
The full cross-product. For each knob, every pair of measured
configurations that differs in that knob *alone* is compared on three
metrics: walk saturation, the fitted latch model, and the fitted cache
geometry `(ways, conflict period, capacity)`. One-knob-at-a-time sweeps
can't see an interaction, which is why the grid is a cross-product.

There are four verdicts, and the third and fourth are the ones a scalar
metric can't produce:

| verdict | what it means |
|---|---|
| `controls` | a matched pair moves the structure |
| `masks` | the probe stops being able to *see* the structure - a cache large enough to hold both probe addresses hides the latch underneath it. Not the same claim as switching it off |
| `re-indexes` | the geometry moves at constant capacity: associativity traded against index width. The L552's `WAYSEL` does exactly this, and against a scalar "largest `N_evict`" it reports as *no effect* - the metric's maximum is unchanged and its whole *shape* has changed |
| `confounds` | the knob is `loopmem`: the probe loop's own residence, not a register. A difference across it is a statement about the instrument, and calling it `controls` reports the measurement as a property of the part |

### Twin calibration
`flash − twin` at `waitstates = 0`, where a flash access can't cost more
than an SRAM one, so whatever is left is the harness. Computed per
configuration and per loop body, and never pooled across either: on the
L552 the `walk` body reads −1.000 cyc/access with the probe loop in SRAM
and +2 to +3 with it in flash, because `loopmem` is the knob that decides
which memory shares a bus port with instruction fetch. Their mean is a
number with the wrong sign, which tells the reader to correct in the wrong
direction. Where the values don't agree the claim is `unknown`, not an
average.

### Wait-state scaling
Linear fit of the per-access cost against the `waitstates` knob, per
configuration. The headline coefficient is the latch differential's slope.
A `LATENCY = 0` point contributes a legitimate zero and is *not* an absent
structure - the structure is still there and simply worth nothing
(`MEASURING_CHANNELS.md` B3).

## The discipline, and why each piece is there

Each of these is a trap this bench already paid for once.

* Every flash measurement carries its own SRAM twin: the same shim function
  with the same arguments over an identically shaped buffer. Comparing two
  different probe functions once produced a spurious 2-cycle "effect" that
  survived into SRAM (`MEASURING_CHANNELS.md` A5).
* The twin is recorded, not folded away. The twin can *eat* the effect when
  the probe loop is loose enough that the SRAM side does work the flash
  side gets for free (`nrf52840.md` §1a), so `infer.py` also keeps a
  within-column reference (stride 0 against stride N on flash) and flags a
  disagreement.
* The probe loop runs from RAM. Running from flash conflates the I-side
  with the D-side and understated the H7's differential by 42 %.
* `LATENCY` is over-programmed deliberately. At zero wait states a hit and
  a miss cost the same cycle and every flash structure reads flat.
* `alt` for sub-cycle resolution. A single-shot `reread` sits on the
  counter's floor (10 vs 13 cycles on the nRF); accumulating the same
  pattern over `reps` gives `1/reps`-cycle resolution.
* Checksums. Every probe returns a checksum over the bytes it read. A probe
  whose checksum doesn't move when its addresses move read nothing, and the
  bench raises instead of recording a fast zero.
* Knob readbacks, never echoes. A knob that refuses to move is recorded as
  it actually is. The L552's `WAYSEL` did exactly that once and a whole
  column of a cross-product was nearly mislabelled.

## Writing a shim for a new part

1. Copy `rigs/fw_map_f4/`, which is the reference implementation and the
   template. Implement `V R K S T X`; `A` and `C` are optional.
2. Keep the address map conventions below. `infer.py` reasons about what
   the probes did, so it has to know what they did.
3. `python -m flashmap selftest --port COMn` until it passes. It fails
   loudly on a frozen counter, an uncopied `.ramfunc`, an optimised-away
   loop, a missing or mis-sized twin, and a checksum that doesn't track the
   arguments - every one of which otherwise produces clean, plausible,
   meaningless numbers.
4. `python -m flashmap map --port COMn --out flashmap/<part>.json --rawout results/flashmap/<part>.raw.json`

### Shim conventions the host relies on

`PROTOCOL.md` is frozen and these don't change it; they pin down the
freedom it leaves, and the reference shim implements them.

| thing | convention |
|---|---|
| region layout | identical in the flash region and the twin, so the twin is a twin |
| walk origin | `base + 0` |
| probe target `T` | `base + size/8`, and aligned to at least 4096 - so negative `reread` offsets stay inside the region, and so the address bits the inference reasons about are all zero at `T` |
| warm-up word | `base + size - 16` |
| warm-up order | warm-up access first, cache invalidation second. The other order leaves the warm-up's line resident and eats one cache tag, which moves every capacity result by one. |
| `walk stride n` | `n` reads at `base + i*stride`, `i = 0..n-1`, all timed |
| `reread off` | read `T`; read `T+off` (`off` may be negative); time one read of `T` |
| `evict n spacing` | read `T`; read `T + spacing*i` for `i = 1..n`; time one read of `T` |
| `evict n spacing start` | addendum, optional. The walk starts at `T + start` instead of `T + spacing`; `start` defaults to `spacing`, so a two-argument call is unchanged. A *negative* `start` makes the walk pass through `T` once, which is the only way to separate LRU from FIFO - see FINDINGS.md §4 and §8. The host probes for it by checking that the checksum changes, and skips the experiment on a shim that ignores it. |
| `err range` | a shim SHOULD reply this when a probe's addresses would leave its region, rather than wrapping. The host reads it as "not measurable here", not as a failure, and records it once. |
| `chase n stride reps` | `reps` cyclic passes over `T + i*stride`, `i = 0..n-1`, all timed, with the next address made to depend on the previous load's value |
| `alt off reps` | `reps` iterations of (read `T`, read `T+off`), all timed - so one "iteration" is two accesses |
| `nop reps` | the same loop shape with no memory access, and no volatile stack slot in it either (that makes the "floor" dearer than the probe it bounds) |
| `A`'s mean | printed as a fixed-point decimal with three places; the host parses it as a float and falls back to repeating `T` if it cannot |

If a part can't honour one of these - the H7's buffers must live somewhere
specific, the nRF's flash is based at 0 - change the *addresses*, not the
*relationships*.

## Testing without hardware

`tests/test_flashmap.py` is host-only. It builds measurement sets two ways
and asserts the inference recovers the geometry:

* from an explicit, mechanism-level model of a memory system (a latch is an
  address-tagged register; a cache is tags with per-word validity),
  configured as the F429, G474, L552, H723, nRF52840 and F303;
* from the published tables in `hardware/*.md`, fed in literally.

It also asserts the things that must come out `unknown`: a `LATENCY = 0`
capture, a capture that only saw a masking configuration, and a cache
probed through a window too small to reach its conflict spacing.

```
pytest tests/test_flashmap.py -q
```
