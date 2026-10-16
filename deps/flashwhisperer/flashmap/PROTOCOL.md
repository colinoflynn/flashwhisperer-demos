# `memmap/1` - the device protocol `flashmap` speaks

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

One firmware shim per part, one host tool. The shim exposes timed memory
primitives and configuration knobs; it knows nothing about what is being
inferred. All structure inference happens on the host, so adding a part means
writing a shim, not an analysis.

This is deliberately not a crypto tool. It characterises a memory system:
flash read width, read latches, data and instruction caches, and the knobs that
move them.

## Line format

ASCII, one command per line, `\n` terminated, 115200 8N1 unless the shim's
banner says otherwise. Replies are one line unless stated. Numbers are decimal
unless prefixed `0x`. A command the shim does not implement replies `unsupported`.
Errors reply `err <reason>`. Every reply ends in `\n` and nothing else is
printed - no banners mid-stream, no progress chatter.

## Commands

### `V` - identify
```
memmap/1 <part> <core> <clk_hz> <timer> <timer_hz> <caps>
```
`timer` is `systick` | `dwt` | other; `timer_hz` is the *counter's* rate, which
is not always the core clock. `caps` is a comma-separated set from
`counters` (has hardware hit/miss counters), `icache`, `dcache`, `unified`,
`waitstates`, `ramfunc` (the probe loop runs from RAM/TCM).

> The shim MUST verify its counter actually advances before reporting it, and
> MUST report `timer=none` if it does not. A frozen counter makes every probe
> identical and therefore every structure look absent - the archetypal silent
> pass. The DWT is dead on the nRF52 and on the H7 when enabled too early; both
> were found this way.

### `R` - list probe regions
One line per region, then `END`:
```
<name> <base_hex> <size_bytes> <kind>
```
`kind` ∈ `flash` | `sram` | `itcm` | `dtcm` | `axisram` | `ccm` | `other`.
Every shim MUST expose at least one `flash` region and one uncached RAM region
of the same size - the twin. The twin is what every flash measurement is
subtracted against; it must be the *same probe function over an identically
shaped buffer*, never a second function.

### `K` - list knobs
One line per knob, then `END`:
```
<name> <values,...> <current>
```
Canonical names, so the host can reason across parts: `waitstates`, `icache`,
`dcache`, `prefetch`, `waysel`, `unified`, `loopmem`. Parts without a knob
simply omit it.

> `loopmem` is canonical, and it is the one knob that is not a register.
> Requested by the G474 and L552 shims, and adopted. `loopmem = 0` means the
> probe loop runs from RAM/ITCM - the isolated configuration that rule 3 below
> requires - and `loopmem = 1` means it runs from flash, which is the
> deliberately *confounded* control: there the loop's own instruction fetches
> share the structure under test, and on a part whose `caps` include `unified`
> they share it by construction.
>
> It has to be canonical because the host must be able to tell an instrument
> control from a device register by name. A shim that called it `iloc` or
> `fromflash` would have the host report "a register reaches the latch" on the
> L552, where the truth is that running the probe from flash destroys the
> measurement (`FINDINGS_g4_l5.md` §2b). With the name fixed, the host: takes
> every structural claim from `loopmem = 0`; reports a difference across
> `loopmem` as `confounds` rather than `controls`; refuses to read a
> replacement policy out of a `loopmem = 1` configuration; and never pools a
> twin-calibration figure across it, because `loopmem` is precisely the knob
> that decides which memory shares a bus port with instruction fetch and so
> the knob across which the twin offset changes sign.
>
> A shim whose probe loop is always in RAM omits the knob and is taken at its
> word. A shim whose probe loop is always in flash MUST still omit it and MUST
> NOT claim `ramfunc`; the host then caveats every claim instead of silently
> treating a confounded measurement as isolated.

> The smallest advertised value of every knob is its least-accelerated
> state. `icache 0` is the cache off, `prefetch 0` is the prefetcher off,
> `loopmem 0` is the probe loop out of flash, `waysel 0` is the narrower
> associativity. Every shim in this repository already does this; it is written
> down because the host now relies on it in two places that are not obvious
> from a transcript. It calibrates the wait states with every other knob at its
> minimum - the configuration that gets the least help, so the setting it picks
> resolves a miss against the bare array rather than against a cache - and it
> takes `min(values)` as the isolating value of `loopmem`. A shim that
> advertised `icache 1,0` meaning "1 = off" would silently invert both.

### `S <knob> <value>` - set a knob
Reply `ok <knob>=<value_readback>`. The shim performs whatever invalidation
the reference manual requires (F4/G4: pulse `ICRST`/`DCRST` with the caches
off; L5: `ICACHE_CR.CACHEINV` and wait `BSYENDF`; M7: `SCB_InvalidateICache` /
`InvalidateDCache`). The host trusts the readback, so read the register back  - 
do not echo the requested value.

### `T <region> <mode> <args...>` - one timed primitive
Reply `<cycles> <checksum_hex>`. The checksum is over the values actually read;
it exists so a probe that measured nothing (loop optimised away, region
unmapped, `.ramfunc` not copied) is detectable rather than silently fast.

Modes - all take byte offsets/strides, all run from RAM if `ramfunc`:

| mode | args | what it times |
|---|---|---|
| `walk` | `stride n` | cold forward walk, `n` reads `stride` apart |
| `reread` | `off` | read A, read A+`off`, re-read A - the latch probe |
| `evict` | `n spacing [start]` | read A, touch `n` addresses `spacing` apart, re-read A |
| `chase` | `n stride reps` | pointer chase over `n` nodes (defeats prefetch) |
| `alt` | `off reps` | alternate A and A+`off` `reps` times - amplification |
| `nop` | `reps` | the loop with no memory access - the instrument's own floor |

`evict`'s optional `start` (default: `spacing`, so two-argument calls are
unchanged) is the offset the interference walk begins at, signed. A negative
start makes the walk pass *through* A partway along. This was added at the
request of two independent shim implementations, and it is adopted: without it
replacement policy is not merely unmeasured but unmeasurable, because every
other primitive leaves A most-recently-used at the moment interference begins,
so LRU and FIFO predict the same eviction point. With it they separate - LRU
moves the eviction to `k + ways`, FIFO stays flat. The host detects support by
checking the checksum changes, not the cycle count: a shim that silently
ignored the third argument would otherwise read as FIFO.

`alt` and `chase` exist because single-shot `reread` sits at the counter's
resolution floor (10 vs 13 cycles on the nRF). Accumulating over `reps` gives
1/`reps`-cycle resolution and is how a sub-cycle effect becomes visible.

> Amplification can lose signal, and the two probes do not agree. Measured on
> the F429: single-shot `reread` gives exactly `LATENCY`, while a 200x amplified
> `alt` loop gives `LATENCY - 1` at every setting from 2 upward, reproducible to
> three decimals - and at `LATENCY = 1` the amplified probe reads 0.000 while
> the single-shot resolves it. The per-collision signal is loop-dependent by one
> cycle. Never mix the two in one comparison, and state which was used: at
> `sboot_stm32`'s `LATENCY = 2` the difference is half the signal, which moves a
> trace-count estimate by up to 4x.

### `A <region> <mode> ...` - same, but returns `min max mean n` over repeats
Optional. Where absent the host repeats `T` itself.

### `C` - hardware counters
`<name>=<value> ...` then `END`, or `unsupported`. Reset on read.
Only the L552 (`ICACHE_HMONR`/`MMONR`) and nRF52840 (`NVMC.IHIT`/`IMISS`) have
these. Where present they are an independent instrument: every timing-derived
claim can be cross-checked against a counter, and a disagreement is a result.

### `X` - self-test
Reply `ok` or `fail <what>`. MUST check: the timer advances; a `nop` costs less
than a `walk`; the flash and twin checksums are what the shim expects; and if
`ramfunc` is claimed, that the copied code's first word is not zero.

## Three things the host does that a shim must not be surprised by

None of them changes the wire format; they are stated here because a shim author
reading a transcript will otherwise think the host has lost its place.

### A wait-state calibration before the plan

Before the measurement programme, the host sets each advertised `waitstates`
value in turn and issues `T <flash> walk 0 64` and `T <flash> walk 256 64`. It
is choosing the cheapest setting at which a missed flash access actually costs
enough cycles to be told apart from a hit, and it stops at the first one that
does.

It is measured rather than assumed because "use `LATENCY >= 4`" is only the
right rule on a part where one wait state is worth one cycle. That is true of
every part in this repository and is not a property of the protocol, and a plan
built on it would be a plan with a fact about this bench's silicon buried in
it. At `LATENCY = 0` a hit and a miss cost the same cycle and every flash
structure reads flat (`MEASURING_CHANNELS.md` B3), so some over-programming is
mandatory; which setting is the part's answer, not the host's.

### A second pass sized from the first pass's geometry

Some experiments cannot be written down until something has been measured.
Both of the replacement-policy discriminators are in that class:

* `evict n spacing -k*spacing` only reaches the target's set if `spacing` is a
  multiple of the measured conflict period, and only discriminates if `k`
  is strictly below the measured associativity (at `k >= ways` the target
  is evicted before the re-touch and LRU and FIFO predict the same thing
  again);
* a cyclic `chase n stride reps` only ever produces a conflict if `stride` is a
  multiple of that same period.

So `map` runs the plan, infers a first structure, and then emits a short second
plan sized from it. The fixed spacings this replaced (16/32/64 B) reach the
target's set on a fully-associative 32-byte ART and never on a part whose
conflict period is 4 KB, which is how the L552 came to carry a positive
`pseudo_random` verdict with not one re-touch row behind it. A constant that is
right for one part and silently wrong for another is the failure mode this
protocol exists to avoid, and the fix is to derive the constant, not to widen
it.

The second pass uses no command the first does not; a shim needs to do nothing
for it beyond honouring `evict`'s optional third argument, and a shim that does
not honour it gets the cyclic chase alone and an honest `LRU or FIFO`.

### A replay control after the measurement programme

Last of all, the host re-measures a handful of `evict` rows - the ones nearest
the capacity it has just measured - in the opposite order, and compares.
It uses no new command and asks nothing of the shim.

It exists because rule 2 below is an assumption about the *part*, not something
a shim can guarantee. "A fixed warm-up access precedes every timed access, so
each probe enters from the same state" holds on a 128-byte ART and does not
hold on a Cortex-M7 with a 32 KB L1 data cache: one warm-up access cannot
restore 32 KB of state, and on the H723 the *first* reading of `evict n 8192`
depends on which `evict` ran before it. Repeating one row cannot reveal that --
repeats of a single command leave the same residue behind each time, so they
agree while the surface as a whole does not. Only replaying a row after
different neighbours can.

Where a replayed row disagrees, the probe's result is not a function of its
arguments, and the host reports no cache geometry rather than fitting a surface
that is partly a record of its own measurement order.

> A related request to shim and host authors, from the same part: `Bench`
> discards a warm-up repetition before taking the median and records any
> disagreement as a *warning string*. That reading is data - on the H723 it
> disagrees with the kept ones on 16 distinct `(n, spacing)` pairs, in both
> directions, all of them in the threshold region a geometry is fitted from --
> and it should be carried in `obs[]` beside the repeats, not in prose. Until
> it is, `min == max` over the stored repeats is a statement about a filtered
> sample and the host refuses to reason from it.

## Rules the host relies on

1. Interrupts off inside the timed region, fixed clock, nothing printed.
2. A fixed warm-up access precedes every timed access, so each probe enters
   from the same state. Without it the first access after a knob change is
   systematically dearer and reads as input dependence.
3. The probe loop runs from RAM/ITCM where the part allows it. On a part with
   an I-cache this is not optional: running from flash with the I-cache off
   understated the H7's differential by 42 %.
4. Buffers are aligned to at least 32 bytes and the shim reports the actual
   address, because alignment mod the read width is itself a variable.

## Adding a part

1. Copy the nearest existing shim (`fw_map_*`).
2. Implement `V R K S T X`; `A` and `C` are optional.
3. Run `python -m flashmap selftest --port COMn` - it exercises every command,
   checks the checksums move when they should, and fails loudly on a frozen
   counter or an uncopied `.ramfunc`.
4. Run `python -m flashmap map --port COMn --out <part>.json`.
