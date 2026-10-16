# What the G474 and L552 shims need from the host package

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Written from `rigs/fw_map_g4/` and `rigs/fw_map_l5/`, which implement
`memmap/1` exactly as [`PROTOCOL.md`](PROTOCOL.md) freezes it. Everything below
is either a request against the host package (which I do not own) or a
deviation the host should know about.

Measurements backing every item are in the captures
`results/flashmap/map_g4_geometry.npz`, `results/flashmap/map_l5_geometry.npz` and
`results/flashmap/map_l5_counters.npz`, produced by
`results/flashmap/map_experiments.py` over `results/flashmap/map_shim_probe.py`; the mapped
structure is in `results/flashmap/map_g4.json` and `results/flashmap/map_l5.json`.

Nothing here blocks: both shims pass `python -m flashmap selftest` as written,
and every workaround is already in place on the device side.

---

## 1. `evict` needs an explicit walk start - and it is the difference between measuring a replacement policy and not

Status: worked around, in a way the host cannot see.

`PROTOCOL.md` defines `evict n spacing` as "read A, touch `n` addresses
`spacing` apart, re-read A". It does not say *where* the walk starts, and the
obvious choice - `A + spacing` - makes the walk a uniform progression that never
revisits A.

Both shims accept an optional third argument, `evict n spacing [start]`,
defaulting to `start = spacing`, so a host that passes two arguments gets the
documented behaviour unchanged. With a negative `start` the walk straddles A and
passes through it once, and that single re-touch is what separates LRU from
FIFO: a hit promotes a line under LRU and is invisible under FIFO, so with `k`
conflicting lines before the re-touch and `m` after,

```
LRU  evicts A when            m >= ways
FIFO evicts A when        k + m >= ways
```

Any `(k, m)` with `m < ways <= k + m` discriminates. With `start = -k*spacing`
this is one `T` command. Without it, the question is unreachable - every
probe re-reads the same address it primed, so A is always most-recently-used at
the start of the interference and the two policies predict the same transition.

Using it, both parts came out LRU, and not FIFO: the G474 at three
independent re-touch positions, the L552 with the hardware miss counter as
witness. Both ground-truth documents leave the policy open, and
`stm32l552.md` §8 states explicitly that its measurement "does not separate
LRU from FIFO".

Request: adopt the optional `start` argument into `PROTOCOL.md`, and add a
replacement-policy experiment to `experiments.py` that uses it. If it stays a
shim extension, the host's inference will keep reporting the policy as
undetermined on parts where it is in fact determined.

---

## 2. `reread off` needs a documented anchor, and `off` must be signed

Status: worked around.

`reread off` says "read A, read A+`off`, re-read A" without saying what A is,
and the sign of `off` is load-bearing: on both parts the sweep has to cross the
word boundary *downwards* as well as upwards to exclude "the latch holds a
16-byte row" as an alternative to "two 8-byte entries".

Both shims: A defaults to `region_base + ANCHOR` (G4 `0x2000`, L5 `0x4000`),
`off` parses as signed decimal, and an optional trailing argument overrides the
anchor - `T flash reread -24 0x4008`. The same optional anchor is accepted by
`walk`, `evict`, `chase` and `alt` as their last argument.

This is not only a documentation gap. `experiments.py` already *encodes* an
address-map convention, in a comment rather than in the protocol:

```
#   scratch  = base + size - 16   (the fixed warm-up access)
#   walk     = base + 0           (walks upward)
#   target   = base + size/8      (room below it for negative reread offsets)
```

and it sizes `walk_span` and `evict_span` from it. My shims do not follow it
exactly - both walk from the anchor rather than from `base + 0`, and the G474's
anchor is `size/4` rather than `size/8` - and they happen to stay inside the
host's spans in every step it generates. That is luck, not agreement: a shim
that placed its anchor lower would return `err range` on steps the host believes
are safe, exactly as the stride-0 case did.

Request: write the anchor into `PROTOCOL.md` (either "the shim's choice,
reported by `R`" or "an optional trailing argument"), and state that `off` is
signed. A host that only sweeps `off >= 0` on the L552 sees
`0..15 free, 16..23 lost, 24..31 free` and can still get the geometry right, but
it never tests the `A mod 16 == 8` parity that rules out a four-entry latch
indexed on `A[4:3]`.

---

## 3. A non-canonical knob, `loopmem`, and why it should become canonical

Status: implemented; the host may ignore it safely.

`K` on both shims lists a fifth knob:

```
loopmem 0,1 0        # 0 = probe loop in SRAM (.ramfunc), 1 = the identical loop in flash
```

It is listed last, so a host that stops at the canonical names still sees a
complete set, and it has no register behind it - the readback is the selected
function-table index, which the shim reports honestly.

It exists because `PROTOCOL.md` rule 3 ("the probe loop runs from RAM/ITCM where
the part allows it") is stated as a rule the shim must obey, which makes the
violation unmeasurable. On the L552 the violation is the single most
consequential fact about the part:

| | latch visible? |
|---|---|
| loop in SRAM (`loopmem 0`) | yes - the two-entry signature is crisp |
| loop in flash (`loopmem 1`) | no - every offset reads the same cycle count |

A tool that ran the loop from flash on this part would report "no read latch",
which is the opposite of the truth, with no warning anywhere in the output. The
G474 does *not* behave this way - its latch signature is bit-identical with the
loop in flash - so this is not a generic caveat, it is a property of the L552
that only a deliberate A/B shows.

Request: promote `loopmem` to a canonical knob name in `PROTOCOL.md`, and
have `infer.py` run at least the latch probe both ways on any part whose caps
include `unified`. Reporting "latch present (and it survives a flash-resident
probe loop)" versus "latch present (but invisible to a flash-resident probe
loop)" is a real distinction between parts.

---

## 4. `A` returns `min max mean n` - please fix the format

Status: guessed.

`PROTOCOL.md` says the reply is `min max mean n` but not how `mean` is
formatted, and cycle counts here are small integers where the interesting
structure sits in fractions of a cycle. Both shims print `mean` with three
decimal places (`7.000`), `min`/`max`/`n` as integers, and `n` fixed at 32.

Two consequences:
- `n` is not settable. A host that wants more repeats must call `T` itself.
- `A` does not report a checksum, so the twin-checksum equality that `T`
  guarantees cannot be checked on an `A` result. My driver therefore uses `T`
  for anything where the checksum matters and `A` only for jitter.

Request: pin the `mean` format in `PROTOCOL.md`, and consider
`min max mean n checksum_hex` so `A` is as self-checking as `T`.

---

## 5. `C` field names

Status: implemented; names are a guess.

`PROTOCOL.md` specifies `<name>=<value> ...` then `END` and "reset on read", but
names no fields. The L552 shim reports:

```
hits=<n> misses=<n> hits_sum=<n> misses_sum=<n> n=<n> hmonr=0x... mmonr=0x...
END
```

`hits`/`misses` are the counts for the most recent timed region only - they
are sampled either side of the measured code and subtracted, so they answer "and
how many misses was that?" for the immediately preceding `T`. `hits_sum` /
`misses_sum` / `n` aggregate over the most recent `T` or `A`. `hmonr` / `mmonr`
are the raw registers, included because a *frozen* monitor and a monitor
reporting *no misses* are the same reading otherwise - the same failure mode
`PROTOCOL.md` already guards against for the cycle counter.

That distinction is not hypothetical here: with `icache 0` the L552's monitors
read exactly zero and stay there - and that is the only configuration in which
the read latch is observable, so the part's one independent instrument cannot
cross-check any of the latch result. `map_l5_counters.npz` has the sweep.

Request: name `hits` and `misses` in `PROTOCOL.md` as the per-probe fields,
and say that a shim MAY add others. And have the host treat
`hmonr == 0 and mmonr == 0` as "counters unavailable in this configuration"
rather than "no cache activity".

---

## 6. There is no way to ask for an instruction-side access

Status: not worked around. The question is out of reach.

Every mode in `PROTOCOL.md` is a *data* read. On a part with a unified cache the
instruction side is half the story, and this shim can say nothing about it
except through its own loop. The counters prove the gap is real rather than
theoretical: with `loopmem 1` and the cache on, an SRAM walk - which performs
zero cacheable data accesses - still reports 331 hits and 5 misses,
every one of them the probe loop fetching itself. The instrument and the
perturbation are the same object.

`rigs/fw_l5_cache/` solved this with flash-resident instruction footprints
at known addresses (`pad.S`: a 16 KB NOP run enterable at any 16-byte offset,
and 512 `bx lr` stubs on 64-byte centres), so a chosen number of lines on chosen
sets can be executed on demand.

Request: a seventh mode,

```
exec <n> <spacing>      execute n instruction lines `spacing` bytes apart, then return
```

optionally combined with the existing modes (prime A, `exec`, re-read A). With
it, `flashmap` could measure I-side geometry, I/D sharing, and the instruction
footprint at which a data table starts being evicted - the L552's headline
result - through the protocol instead of through bespoke firmware. Without it,
`unified` in the caps string is a label the host cannot act on.

---

## 7. The twin is not a zero on every part, and `flash - twin` should not be the only estimator

Status: measured; needs a host-side change.

`PROTOCOL.md` rule: the twin is "the same probe function over an identically
shaped buffer", and every flash measurement is subtracted against it. That
cancels the loop framing only if the twin's buffer stands in the same
relationship to the loop's *own instruction fetch* as the flash buffer does.

On the G474 it does: at `LATENCY 0` the flash walk and the twin agree to the
cycle, so `flash - twin` is a clean estimator and reads exactly `LATENCY`.

On the L552 it does not. The probe loop runs from SRAM, so SRAM data loads
share the M33's S-AHB port with the loop's instruction fetches while flash data
loads go over C-AHB. The twin therefore costs one cycle per access more than
flash at zero wait states, and `flash - twin` under-reports by exactly that:

| | `flash - twin`, per access |
|---|---|
| `walk` body | `LATENCY - 1` |
| `chase` body | `LATENCY` |

and setting `loopmem 1` flips the sign exactly (flash 455 / twin 392 at
`LATENCY 0`, the mirror of 391 / 455), which is what identifies it as port
contention rather than a memory-speed difference. The bias depends on the loop
body because a longer body has an idle cycle for the extra bus beat to hide in.

Request: have `infer.py` measure `flash(LATENCY=0) - twin(LATENCY=0)` once
per part and carry it as a calibration offset, reporting it in the output.
The robust quantity is `flash(LATENCY) - flash(0)`, which is instrument-neutral
and on which both my shim and the pre-existing `fw_l5_cache` firmware agree
exactly. If the host reports a per-word cost of `LATENCY - 1` on the L552 it is
not wrong about the silicon, it is reporting an uncalibrated instrument - and
the fix is one extra measurement.

---

## 8. Small things

- `R` base addresses are printed `0x`-prefixed. `PROTOCOL.md` says numbers
  are decimal unless prefixed `0x`, so this is compliant, but `int(tok, 0)` is
  required on the host rather than `int(tok)`.
- Checksums are printed `0x`-prefixed for the same reason. They are a
  running sum of the bytes actually read. Both shims fill the flash buffer and
  the SRAM twin with the *same* function of the byte index,
  `v(i) = ((i mod 256)*31 + (i div 256)*17 + 7) mod 256`, so the flash and
  twin checksums must be equal for every probe. That is a stronger invariant
  than "non-zero" and the host is welcome to assert it; my driver does.
- One line can be printed that is not a reply: a hard fault prints
  `HARDFAULT pc=... lr=... cfsr=... hfsr=...` and resets. It is a deliberate
  deviation from "nothing else is printed" - a wedged board costs more than the
  line does - and it is why the host should drain to silence before each
  command rather than assume one reply per write.
- `walk` with stride 0 is legal and both shims now accept it. They did not
  at first - it was rejected as a degenerate walk - and since the host issues
  `walk 0 64` as its within-column reference in *every* configuration, that one
  rejection produced 38 capture warnings per run and cost a complete `map` run on
  the L552. Worth a line in `PROTOCOL.md` saying stride 0 is the all-hit control
  and must be accepted.
- `err range` is returned when a probe's addresses would leave the region,
  rather than wrapping. The L552's index sweep at `span 16384, n 8` needs 128 KB
  beyond the anchor and gets `err range`; the host should treat that as "not
  measurable here", not as a failure.

---

## 9. `_miss_scale` was global while the deltas it classifies are per-configuration

Status: FIXED in `infer.py` at 07:36 while this was being written. The
signature is now `_miss_scale(ms, cfg)` and the docstring names the G474 capture.
Kept here as the record of what the symptom looked like from the shim side,
since the symptom is worth recognising again: a `confidence: high` claim that
a cache-enable knob reaches nothing.

`infer.py`'s `_miss_scale(ms)` takes the maximum per-access walk delta over
the entire knob grid and `_classify_delta` then calls a measurement "fast"
when `abs(delta) < 0.5 * scale`. The grid includes `waitstates` 0 … 15, so on
both my parts the scale is set by the `waitstates=15, loopmem=1` cell.

The capacity and index sweeps, however, run at `waitstates = 4`, where a
cache miss is worth exactly 4 cycles. 4 is less than half of 16, so every
eviction in the sweep classifies as a hit and `_n_evict` never fires.

The arithmetic is confirmed by the tool's own evidence lines. On the G474:

- max per-access walk delta = `LATENCY + 1` at `loopmem=1` → 16 cycles at
  `waitstates=15`, so the threshold is 8;
- the latch differential is exactly `LATENCY`, so it should resolve at every
  wait-state setting - and the report says it resolved in exactly 4 of 38
  settings, at `waitstates = 8, 10, 12, 15`. That is precisely `LATENCY >= 8`;
- the 8-tag data cache, whose differential at `waitstates=4` is 4 cycles, was
  therefore never seen at all. The report gives
  `N_evict 8:640+ 16:640+ 32:640+ …` - no eviction found at any spacing, in any
  configuration - and concludes `capacity_bytes = 32768` (the whole probe
  region), `line_bytes = 8`, ways and sets undetermined, and
  `dcache -> data_reuse : no effect, identical in all 8 matched pairs`.

Measured directly through the same `T flash evict n 32` command the host issues,
at the same `waitstates=4`:

| N | 1 | … | 7 | 8 | 9 | … | 16 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `dcache=1` cycles | 8 | 8 | 8 | 12 | 12 | 12 | 12 |
| `dcache=0` cycles | 12 | 12 | 12 | 12 | 12 | 12 | 12 |

The transition is crisp, `min == max` over 32 repeats, and `DCEN` is the only
knob that moves it. The data is in the capture; the classifier discarded it.

Consequences, all three of them wrong in the same way:
- `cache.capacity_bytes = 32768` instead of 256 (8 tags × 32 B);
- `cache.line_bytes = 8` - the read width standing in for a line the sweep never
  resolved;
- `knob_map.dcache -> data_reuse : no effect`, which is the exact opposite of
  `stm32g474_art_geometry.md` §2, whose whole point is that `DCEN` is the only
  source of data reuse on this part.

Request: compute the scale per configuration - or at minimum per
`waitstates` value - rather than once over the whole grid:

```python
scale = _miss_scale_for(ms, cfg)       # max per-access walk delta at THIS cfg
```

A miss costs `LATENCY` cycles by construction (that is the
`WAITSTATE_SCALING = 1` claim the tool already makes with R²=1.0000), so the
scale is knowable exactly from the configuration rather than from the grid's
worst cell. As it stands, adding a high wait-state cell to the sweep silently
destroys every structural claim measured at a low one, and the failure is
invisible: the tool reports `confidence: high` on
`knob_map = dcache -> nothing measured here`.

A cheap guard, independent of the fix: if a knob whose canonical name is
`dcache` or `icache` is reported as reaching nothing, that is far more
likely to be a classifier problem than a part with an inert cache-enable bit,
and is worth a caveat line at least.

A workaround I deliberately did not take. `_reference_waitstates` picks the
smallest advertised value `>= 4` for the structural grid, and `experiments.py`
notes that "the shim caps the list it advertises". So a shim can make its own
cache resolve by advertising `waitstates 0,1,2,3,4,5,6` instead of `0 … 15`: the
scale then comes from a 7-cycle cell, the threshold drops to 3.5, and the
G474's 4-cycle cache differential classifies as `slow`.

That would be gaming the classifier by under-reporting the hardware.
`FLASH_ACR.LATENCY` is four bits and every value 0–15 is writable on both parts,
the repository over-programs it on purpose (`MEASURING_CHANNELS.md` B3), and the
`waitstate_scaling` claim is only as good as the range it is fitted over - this
run fits `1.000 x WS + 0.000` with `R2 = 1.0000` across twelve settings up to 15.
Both shims therefore advertise the full list, and the fix belongs in the
classifier.

---

## 10. After the `_miss_scale` fix: three claims that are still wrong, and why

> Resolved. Sections 10, 11 and 12 below, and section 1's request, were all acted on; see [`FINDINGS_reliability.md`](FINDINGS_reliability.md) for what was changed and what each part reports now. Two of the requests were answered differently from how they were framed, and the reasoning for that is in that document: the latch aggregation is fixed by intersecting each configuration's *consistent-model set* rather than by weighting votes by evidence density, and the read-width aggregation (`REQUESTS_h7_nrf.md` section 4a) is fixed by excluding the wait-state sweep cells rather than by taking the modal value, which would have broken this part.

Re-run of `python -m flashmap map` against the fixed `infer.py`. The G474 now
comes out essentially correct - `cache = 8 ways, 256 B, conflict period 32 B,
capacity_unit "tags"`, `latch = 8 B x 1 entry, depth 1, knob_reaches_it false`,
`dcache -> data_reuse: controls (1 -> 32)`, `dcache -> latch: masks` - all at
high confidence and all matching `stm32g474_art_geometry.md`. The L552 has three
remaining problems, each with a specific cause.

### 10a. The L552 latch: the right answer is measured and then outvoted

The report says `granularity_bytes: 16, entries: 1`. The truth is 8 B x 2
entries indexed on `A[3]`. But look at the evidence the tool prints:

```
waitstates=10 ... : 6/6  offsets fit granularity 16 B x 1 entry
waitstates=12 ... : 6/6  offsets fit granularity 16 B x 1 entry
waitstates=15 ... : 6/6  offsets fit granularity 16 B x 1 entry
waitstates=2  ... : 6/6  offsets fit granularity 16 B x 1 entry
waitstates=3  ... : 6/6  offsets fit granularity 16 B x 1 entry
waitstates=4  ... : 47/47 offsets fit granularity 8 B x 2 entries
```

The 47/47 row is the correct model, fitted to the dense sweep. The five
`6/6` rows come from the wait-state sweep, which `default_plan` deliberately
runs with "only the cheap probes" - six offsets. Six offsets cannot separate
`8 B x 2` from `16 B x 1`, both fit perfectly, and `_fit_latch`'s tie-break
(`cand = (hits, -k, -g, -a)`) prefers the smaller `k`. The aggregation across
configurations then takes the majority, and 5 sparse-sweep configurations
outvote the one dense-sweep configuration that actually discriminated.

`_LATCH_K = (1, 2, 4, 8)` already contains the right model and
`_latch_predict(off, 8, 2, 0)` reproduces the measured sweep exactly at all 47
offsets - nothing about the model family needs to change.

Request: weight the per-configuration fits by how many offsets they were
fitted to, or take the fit from the configuration with the most *discriminating*
offsets rather than the modal fit. A fit over 6 offsets and a fit over 47 should
not carry one vote each. Failing that, exclude the wait-state-sweep
configurations from the latch model fit and keep them only for the differential.

### 10b. `waysel` is reported as having no effect, while the cache claim shows it working

The eviction surface resolves both associativities correctly:

```
icache=1 waysel=0 : ... 4096:2 8192:1  16384:1  -> 1-way, conflict period 8192 B, 8192 B
icache=1 waysel=1 : ... 4096:2 8192:2  16384:2  -> 2-way, conflict period 4096 B, 8192 B
```

Same capacity, different conflict period and different ways - which is exactly
`stm32l552.md` §3b's finding that `WAYSEL` re-indexes rather than resizes,
and the tool does *not* make the "1-way = half the cache" error. Good.

But `knob_map` says `waysel -> data_reuse : no effect, identical in all 4
matched pairs`, because `_metric_reuse` is the scalar "largest `N_evict` over
every spacing" - 1024 at spacing 8 in both modes. The knob's whole effect lives
in the *shape* of `N_evict(spacing)`, not in its maximum. And the two correct
geometries are then surfaced as a *disagreement*:

```
! Not every knob setting fits the same geometry: 1-way/period 8192 in 2 config(s);
  2-way/period 4096 in 2 config(s); 1-way/period 16 in 4 config(s).
```

Request: make the knob-map reuse metric the fitted `(ways, period, capacity)`
triple rather than `max N_evict`. Then `waysel` reports "controls: ways 1 -> 2,
conflict period 8192 -> 4096, capacity unchanged at 8192 B", which is the
finding. As it stands the tool measures the most interesting thing about this
part and files it as an inconsistency.

### 10c. `replacement_policy = "pseudo_random"` on the L552 is wrong

The G474 run says `lru_or_fifo` at low confidence with the honest caveat that
only one of two instruments ran. The L552 run says `pseudo_random` at medium
confidence.

Measured directly, with the hardware miss counter rather than timing
(`evict n 4096 -4096`, 2-way, so the walk is `A-4096, A, A+4096` and A is
re-touched in the middle):

| N | walk | misses | LRU predicts | FIFO predicts |
|---:|---|---:|---|---|
| 1 | A−4096 | 0 | survives | survives |
| 2 | A−4096, A | 0 | survives | survives |
| 3 | A−4096, A, A+4096 | 0 | survives | evicted |
| 4 | …, A+8192 | 1 | evicted | evicted |

Zero counted misses at N=3, where three distinct lines have passed through a
two-way set. That excludes FIFO, and a random victim would not give 0 misses
reproducibly (`min == max` over repeats). The same probe on the G474 at three
re-touch positions gives transitions at N = 11, 13, 15 for k = 2, 4, 6 - exactly
`k + 9`, which is LRU, against FIFO's flat prediction of 9.

Both parts are LRU. `pseudo_random` is a positive claim in the wrong
direction, and it is reached because the two timing-only instruments disagreed
and the tie was broken toward randomness. See §1 for the one-argument change
that makes this directly measurable instead of inferred.

---

## 11. `twin_calibration` landed - and it pools across the one knob that flips its sign

Status: the claim requested in §7 now exists in `infer.py`. Its headline number
is wrong for the configuration every structural claim is measured in.

The L552 report says:

```
twin calibration | +0.5156 cyc/access at 0 wait states  (BIASED: every
                 | flash-twin figure carries this)
```

with a caveat that names the bus-port mechanism correctly. But the evidence
under it is:

```
waitstates=0 icache=0 waysel=0 loopmem=0: stride 8  -> flash-twin = -1.000 cyc/access
waitstates=0 icache=0 waysel=0 loopmem=0: stride 16 -> flash-twin = -1.000
waitstates=0 icache=0 waysel=0 loopmem=0: stride 32 -> flash-twin = -1.000
waitstates=0 icache=0 waysel=0 loopmem=0: stride 64 -> flash-twin = -1.000
waitstates=0 icache=1 waysel=1 loopmem=1: stride 8  -> flash-twin = +2.031
waitstates=0 icache=1 waysel=1 loopmem=1: stride 16 -> flash-twin = +3.031
waitstates=0 icache=0 waysel=0 loopmem=0: single reread     -> flash-twin = +0.5
```

Four rows at −1.000 from the isolated configuration, two rows at +2 / +3
from the *deliberately confounded* one, and the headline is their mean. The
offset is not a single constant: it is −1.000 cyc/access with the loop in SRAM
and positive with the loop in flash, because `loopmem` is precisely the knob
that decides which memory shares a port with instruction fetch. Averaging across
it is averaging a quantity with its own negation.

This matters beyond bookkeeping. Every structural claim in the report is
measured at `loopmem = 0`, where the true offset is −1.000, so the report tells
the reader to correct in the wrong direction by 1.5 cycles per access.

On the G474 the same fit gives ≈ 0 at `loopmem = 0` and a positive value at
`loopmem = 1`, so the pooled figure is wrong there too, just less visibly.

Request: compute `twin_calibration` per configuration, exactly as
`_miss_scale` now is - same failure mode, one layer up - and report the value
for the configuration each claim was actually measured in. If a single headline
number is wanted, take it from the configuration the shim advertises as its
isolated one (`loopmem = 0` where the knob exists, or any part whose caps
include `ramfunc`), and say which.

Two further notes on the same claim:

- Do not mix the `reread` term into the `walk` term. The last evidence row
  (`single reread -> +0.5 cyc`) is a different loop body, and §7 shows the bias
  is loop-body dependent: the `walk` body reads −1.000 and the `chase` body
  reads 0.000 in the *same* configuration, because the longer body has an idle
  cycle for the extra bus beat to hide in. One number per (config, body) is the
  smallest honest unit.
- The sign convention deserves a sentence in the report. A negative
  calibration means the flash buffer is *cheaper* than its own SRAM twin, which
  reads as nonsense until the port-contention mechanism is stated. The caveat
  text already states it well; the headline row should carry the sign rather
  than the word "BIASED".

---

## 12. The re-touch discriminator runs at fixed small spacings, so it never fires on a part whose conflict period is 4 KB

Status: the §1 request was adopted - and it works. It just does not reach the
L552.

`infer.py` now carries the re-touch probe, and on the G474 it decides the
question outright:

```
evict walk re-touching the target after k=2 conflicts (spacing 32) loses it at n=11; LRU predicts 11, FIFO predicts 9
evict walk re-touching the target after k=4 conflicts (spacing 32) loses it at n=13; LRU predicts 13, FIFO predicts 9
-> every re-touch position lands on the LRU prediction and none on the FIFO one
```

`replacement policy | LRU (measured against FIFO, not assumed) | high`. That is
the right answer and it matches my own sweep at k = 2, 4, 6 (n = 11, 13, 15).

On the L552 the same claim reads `pseudo_random`, medium confidence, and the
re-touch probe contributed nothing - there is not one re-touch row in its
evidence. The whole verdict rests on a single line:

```
waitstates=4 icache=1 waysel=0 loopmem=1: cyclic chase, 17 lines -> 0.07 miss/access,
                                          32 lines -> 0.21  [not adjacent sizes]
-> a cyclic working set one step over the knee still hits part of the time (21% miss).
   Neither LRU nor FIFO nor an address index can do that
```

Three things are wrong with concluding randomness from it:

1. It is measured at `loopmem = 1` - the deliberately confounded
   configuration, the probe loop resident in flash, on the one part in this rig
   whose cache is unified. The loop's own instruction lines occupy sets
   alongside the data under test, so a cyclic data working set "one step over
   the knee" is not one step over the knee at all. The partial hit rate is the
   loop's footprint, not a non-deterministic victim. The evidence line's own
   tag `[not adjacent sizes]` (17 against 32) says the discriminator's
   precondition was not met either.
2. The re-touch probe never ran here. `default_plan` emits its `evict` and
   `chase` steps at spacings 16, 32 and 64 B. On the L552 a walk at those
   spacings does not produce a set conflict until N reaches 512, because the
   conflict period is 4096 B at 2-way and 8192 B at 1-way (the tool's own
   cache claim measures this). The probe is looking in the wrong place.
3. Measured directly, with the miss counter, the L552 is LRU. `evict 3 4096
   -4096` at 2-way walks `A-4096, A, A+4096`: three distinct lines through a
   two-way set with A re-touched in the middle. FIFO must evict A. The counter
   reports 0 misses, reproducibly (`min == max`). The k=2 control returns the
   predicted `0 1 0 0 1`.

Request: emit the re-touch steps at the fitted conflict period rather
than at a fixed small spacing - the cache claim already computes it, so a second
pass, or a plan that reads the first pass's geometry, would place them correctly.
And do not draw a positive `pseudo_random` conclusion from a configuration whose
`loopmem` is 1 (or, more generally, from any configuration where the probe loop
shares a cache with the data) on a part whose caps include `unified`: there the
cyclic-chase discriminator is measuring the probe, not the part.

Falling back to `lru_or_fifo` at low confidence, as the G474 run did before the
re-touch probe existed, would have been the safe answer. `pseudo_random` at
medium confidence is a positive claim in the wrong direction, and it is the
unified confound reaching the tool's output - which is the same failure this
document's §3 asks `loopmem` be promoted to guard against.
