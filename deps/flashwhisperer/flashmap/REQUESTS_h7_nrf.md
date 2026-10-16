# Requests from the H723 and nRF52840 shims

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

What `rigs/fw_map_h7/` and `rigs/fw_map_nrf/` need from the host package
(`device.py`, `experiments.py`, `infer.py`, `report.py`, `__main__.py`), which I
do not own. Everything here is worked around in the shims meanwhile, so nothing
below blocks a `map` run - but four of them are wrong answers, not
inconveniences, and they are marked as such.

Each item says what was measured, on which part, and what the fix would be.
Evidence lives in `flashmap/FINDINGS_h7_nrf.md` and the `hardware/map_*.npz`
captures.

---

## 1. `_miss_scale` should not come from `walk` alone - WRONG ANSWER (fixed shim-side, but fragile)

Measured, nRF52840. `infer._miss_scale()` takes the hit/miss threshold from
the saturated cold `walk`, and `_classify_delta` calls a re-read a hit when
`|flash − twin| < 0.5 × scale`. On this part the walk's per-access cost is
schedule-dependent by a factor of three:

| probe (same build, same part, stride ≥ 16) | cycles per 16 B word |
|---|---:|
| `walk`, loop body written in C | 1.00 |
| `walk`, loop body with the loaded value consumed by the next instruction | 2.97 |
| `chase` (a real pointer chase) | 2.98 |
| `alt`, 1000 reps | 2.998 |

With `scale = 1.00` the threshold is 0.5 cycles, and the latch's own
differentials  -  −1 cycle at a hit and +2 at a miss - both classify as
"slow". `infer` then reported

```
latch = {'present': False}   [high confidence]
basis: "a re-read of A is as dear as a fresh read even when the intervening
        access was to A itself (offset 0)"
```

on a part that has a 1-entry 16-byte read latch that `alt` resolves to three
decimal places in the same capture. A *high-confidence false negative* on the
headline structure.

I fixed this in the shims by writing the walk loop so the loaded value is
consumed by the next instruction (`nrf52840.md` §1a's `dep=1`), which
brings `walk` into agreement with `chase` and `alt`. But the fix lives in the
shim, and the next shim author will not know to do it.

Request. Derive the scale from `chase` when the part reports it, falling
back to `walk`; or take `max(walk_saturated, chase_saturated)`. A pointer chase
cannot hide the stall in loop slack - that is what it is for. Failing that,
warn loudly when `chase` and `walk` disagree by more than ~30 %, because that
disagreement is itself a result about the instrument.

## 2. The twin is not always a zero, and `abs()` hides which way it went - WRONG ANSWER

Measured, nRF52840. A flash latch hit costs *less* than the SRAM twin:

```
reread, I-cache off, target 16 B aligned
off      -16   -8   -4    0    4    8   12   15   16   20   32   64
flash      8    8    8    5    5    5    5    8    8    8    8    8
sram(twin) 6    6    6    6    6    6    6    6    6    6    6    6
delta     +2   +2   +2   -1   -1   -1   -1   +2   +2   +2   +2   +2
```

The structure is perfectly crisp in the flash column and the twin is perfectly
flat, but the *differential* is −1 at a hit. `_classify_delta` takes
`abs(d)`, so a hit that is 1 cycle cheaper than the twin is indistinguishable
from a miss that is 1 cycle dearer.

Request. Two things, either of which fixes it:

* classify against the flash column's own minimum rather than against the
  twin. `nrf52840.md` §1a already prescribes this ("take the reference
  from the same column") for exactly this failure, and the plan already
  measures `walk 0 n` as the within-column reference - use it here too;
* and keep the sign: a systematically negative differential means the twin is
  slower than a flash hit, which is a fact about the part worth reporting, not
  noise to be absolute-valued away.

The same thing bites the H723, where `twin_calibration` catches it and the
latch claim does not use the answer. On that part the claim comes out

```
twin_calibration = 4.0   [high]
  ! The twin is NOT a zero here: at `waitstates = 0` ... `flash - twin` still
    reads +4.000 cycles per access. Every figure derived by subtracting it
    carries that bias.
  - single reread at 0 wait states -> flash-twin = +2 cyc
```

and the latch claim then reports

```
latch.knob_reaches_it = true
  ! 3 knob setting(s) show no data-side reuse at any offset, including offset 0:
    waitstates=0, waitstates=1, waitstates=2
```

Those three settings are exactly the ones where the latch differential (0, 1 and
2 cycles) is smaller than the twin's own +2-cycle offset on a single re-read, so
every offset lands on the wrong side of the threshold and the configuration
reads as "no reuse at all". From that the tool concludes a register *reaches*
the latch - on a part where `knob_map` in the same run correctly says "no knob
reaches the latch; dcache only masks it". The two claims contradict each other
in one report, and `twin_calibration` already measured the number that explains
why.

Request (addendum). Feed `twin_calibration`'s measured offset back into
`_classify_delta` as a correction, or at minimum suppress
`latch.knob_reaches_it` in configurations where the differential is smaller
than the calibrated twin bias. Trap B3 ("zero wait states") is already
documented in `MEASURING_CHANNELS.md`; this is that trap plus a biased twin,
and the tool has both ingredients in hand.

Note `twin_calibration` returned `UNKNOWN` on the nRF because it needs a
`waitstates` knob to find a setting where a flash access is known to be free.
On a part with no wait states there is no such setting, so it needs a different
anchor - the within-column minimum is one.

## 3. Do not grid every knob a shim advertises - WRONG ANSWER (worked around)

Measured, both parts. `_binary_knobs` grids every knob with ≤ 4 values. My
shims advertised `exec`, which moves the probe loop off ITCM/SRAM and into
flash - a deliberate violation of PROTOCOL.md rule 3. The host dutifully
swept it, so half of an entire nRF52 map ran with the probe fetched from flash,
where the loop's own instruction fetches thrash the 1-entry read latch and every
re-read misses. That contributed to the `latch: present=False` above, and on the
H723 it tripled a 48-cell grid (`icache × dcache × wrhighfreq × exec`).

I have stopped advertising `exec` (it is still reachable as `S exec <n>` for
`results/flashmap/map_capture.py`), so this is worked around. But the underlying issue
is general: the host has no way to tell a configuration knob from a knob that
breaks its own measurement discipline.

Request. Either reserve the canonical set for gridding and treat unknown
knob names as read-only diagnostics, or let `K` mark a knob, e.g. a trailing
field `diag`. The protocol's sentence "Canonical names, so the host can reason
across parts" already implies the first.

## 4. `walk` at stride 1 and 2 with a 32-bit access is unaligned - WRONG ANSWER (fixed shim-side)

Measured, STM32H723. With a 32-bit load, strides 1 and 2 are unaligned, and
an unaligned flash read on this part costs more than an aligned one. The
cost curve then *dips* between stride 1 and stride 4:

```
stride       1     2     4     8    16    32    64
delta (32b) 525   419   313   369   481   705   705      <- not monotone
delta (8b)  270   284   312   368   480   690   690      <- monotone
```

`_saturation()` fitted the non-monotone curve and returned `read_width = 8` on a
part whose flash read unit is 32 bytes (`fill_unit` came out 32, correctly, from
the same capture - so the two claims contradicted each other).

Fixed in the shims by making `walk` a byte load, which is aligned at every
stride and is what the published H7/G4 walks use. Recorded here because the
protocol says only "all take byte offsets/strides" and is silent on the access
width, so the next shim will pick one at random.

Request. Say in PROTOCOL.md that `walk` uses the narrowest access the part
supports, and that `reread`'s straddle test and `chase`'s pointer are the modes
that need a wider one. Optionally: have `_saturation()` reject a non-monotone
prefix rather than fit it.

### 4a. …and `read_width` should not be outvoted 37 to 1

With the byte-load walk the H723 capture is clean, but the claim still reports
the wrong number:

```
read_width = 8   [medium]
  - (every evidence line): "saturates at stride 32, 8.00 cyc/access"
  ! Read width is NOT invariant across knob settings: saturation at stride 8 in
    1 config(s), stride 32 in 37 config(s).
```

Thirty-seven configurations say 32 bytes, one says 8, and the claim reports 8  - 
while `fill_unit`, from the same capture, correctly reports 32. The notes then
flag the contradiction the claim created:

```
NOTE: the latch granularity (32 B) is not the flash read width (8 B).
```

It is, and the capture says so 37 times.

Request. Take the modal value across configurations, or prefer the
configurations with no line-filling cache enabled (the caveat already
identifies them), rather than the minimum. A single outlier config should lower
the confidence, not change the answer.

---

## 5. The twin choice is a *result* on the H723, and the report should say so

Not a bug - `twin_region()` picks `dtcm` correctly, by the preference order that
is already there. But on this part the choice is worth a line in the report,
because the wrong choice is available and it is not obviously wrong:

| twin used | flash − twin, stride 32, caches off | inferred cost per access |
|---|---:|---:|
| `dtcm` (correct - not behind the L1 D-cache) | 690 | 10.8 |
| `axisram` (same size, is behind the L1 D-cache) | 374 | 5.8 |
| `axisram`, stride 1 | −35 | flash "faster than RAM" |

Request. Record `twin_region` / `twin_kind` in the report body (they are
already in the JSON), and when more than one same-size non-flash region exists,
either re-run one probe against the alternative and note the difference, or at
least list the candidates that were rejected. On this part that is the
difference between 10.8 and 5.8 cycles per access, and a negative differential
at small strides that reads as "flash is faster than RAM".

## 6. `--twin <name>` override

To produce the table above I drove the shim directly. A `--twin` flag on `map`
would let the disagreement be captured by the tool itself rather than by a
side-script, which is the whole point of having the tool.

## 7. Optional target-offset argument for `reread` / `evict`

Both shims accept `reread <off> [aoff] [nother]` and
`evict <n> <spacing> [start] [aoff]`, where `aoff` moves the target A. The
host never sends it, so the "aligned block versus within-N-bytes" distinction  - 
which the H7 report quotes as a finding - cannot be measured by the host; I take
it in `results/flashmap/map_capture.py`. Sliding A's own alignment is the only way to
tell an address-tagged row register from a proximity rule, and the two leak
differently.

Request. Add an optional target offset to `reread` in PROTOCOL.md, the way
`start` was just added to `evict`. Both shims already implement it.

## 8. `C` returns per-probe deltas, not free-running counters

PROTOCOL.md says counters are "reset on read". The nRF shim instead reports
`IHIT`/`IMISS` deltas across the last timed primitive, snapshotted inside
that primitive's interrupts-off window.

This is not laziness, it is the only correct implementation: read outside that
window and the UART busy-wait loop's own flash instruction fetches land in the
count. An early version of this measurement in `nrf52840.md` §3 reported
~5 500 hits for a 650-cycle walk - more hits than cycles.

Request. Say in PROTOCOL.md that `C` reports the last timed primitive's
deltas and that the shim MUST sample them inside the timed region. The host
already treats the values correctly; only the wording is loose.

## 9. Two conventions worth freezing, because they cost a day between them

Both are shim-side and both are now in the shims' comments, but they belong in
PROTOCOL.md's "Rules the host relies on" because they are not discoverable:

* No `ISB` in the probe's preamble. With `dsb; isb` before the timed region
  the nRF's single-access window floored at 8 cycles and could not resolve its
  3-cycle latch *at all*  -  flash and twin read 8 at every offset, a flat null,
  in a build where `alt` resolved the same structure cleanly. Removing the ISB
  restored 5 against 8 immediately. An ISB flushes and refills the pipeline and
  the refill overlaps the following load, hiding exactly the stall under
  measurement. DSB alone gives the ordering the probe needs.
* `reread` and `evict` must be the same function. Written as two functions
  with two copies of the same four instructions, GCC scheduled them differently
  and their floors came out 3 cycles apart on the M4 - which is that part's
  entire latch signal. `evict` then read a flat 8 on flash *and* on SRAM at
  every `n`, blind to a structure `reread` resolved. That is trap A5 committed
  inside a single shim. Factoring the window into a shared `noinline` helper
  made it *worse* (the call's prologue added slack and both modes went flat);
  writing it as fixed inline assembly also floored at 8. What works is not
  duplicating the window at all: one function, two argument patterns.

## 10. `hardware/boards.py` no longer flashes the nRF52840 (not your file, recorded for whoever owns it)

`boards.require()` now refuses because the J-Link's serial enumerates as
`001050219420` while `BOARDS["nrf52840"]["probe"]` is `1050219420`:

```
RuntimeError: nrf52840: probe 1050219420 is NOT attached.
Attached now: ['001050219420', ...]
```

pyocd itself wants the unpadded form - `-u 001050219420` hangs on
"Waiting for a debug probe matching unique ID", `-u 1050219420` works. So the
padding comes from the new enumeration path, not from pyocd, and the fix is to
compare with leading zeros stripped (or `endswith`) rather than to change the
registry entry. I flashed via pyocd directly meanwhile:

```
python -m pyocd flash -u 1050219420 -t nrf52840 --connect halt \
       --base-address 0x0 --format bin rigs/fw_map_nrf/fw.bin
```

The H723 (`001800353438511734313939`) is unaffected - its serial is already
24 characters and enumerates identically.
