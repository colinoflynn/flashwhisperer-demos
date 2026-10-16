# What `flashmap` infers on an STM32H723 and an nRF52840

*🤖WARNING🤖: This file LLM generated and may read oddly. Will eventually be human-edited for that real-life touch and typos.*

Two shims - [`rigs/fw_map_h7/`](../../rigs/fw_map_h7) and
[`rigs/fw_map_nrf/`](../../rigs/fw_map_nrf) - and what the host package
makes of them. These are the two parts that stress the `memmap/1` method hardest
and in opposite directions: the H723 has a memory hierarchy and two L1 caches
that the protocol's "twin" concept was not written for, and the nRF52840 has
no data cache and no wait-state register at all, so almost everything the
tool looks for genuinely is not there.

This is a memory-system instrument, not a crypto tool. Nothing below is about
keys.

The four results, up front.

1. The nRF52840 is the most valuable negative test in the set, and the tool
   passes it - but only after two shim defects were found *by* the negative
   test first coming out wrong in the other direction. `cache: present=False`
   and `waitstate_scaling: UNKNOWN` are now reported on a part that has neither,
   with no fitted number anywhere (section 2.1). Its hardware counters then
   prove, by *counting* rather than by timing, that its only cache is
   instruction-only: sixteen data probes over flash, IHIT = IMISS = 0 in every
   one (section 2.2).
2. On the H723 the tool reproduces the published stride table bit-exactly in
   all nine cells and recovers the closed-form law "4 cycles + LATENCY" per
   access with R-squared = 1.0000 over twelve wait-state settings (section 3.3)
    -  but only with the right twin, the right statistic and the right loop.
   Those three are worth 45%, 4% and 300% respectively, and sections 3.1, 3.7
   and 4 show what each one does when you get it wrong.
3. The published "running the probe from flash understates the H7 differential
   by 42%" is a special case, not a rule. It is 0% when the probe loop fits
   inside one aligned 32-byte flash block and 45% when it straddles one, and a
   16-byte link-time shift of the identical instructions moves it between the
   two (section 3.6). Running from AXI SRAM is worse than either, at 73%.
4. `WRHIGHFREQ` does nothing measurable on the read path - 12 of 12 matched
   configuration pairs identical, across three wait-state settings and four
   different probes (section 3.5). That is a new number; the field is not swept
   anywhere else in this repository.

Section 5 is a proper section on what this method cannot reach,
tested rather than asserted.

---

## 1. Reproducing

Toolchain is WSL-only; flashing and the hosts run on Windows.

```sh
wsl.exe -e bash -lc "cd /mnt/c/dev/flash-accelerator-tests/rigs/fw_map_h7 && make"
wsl.exe -e bash -lc "cd /mnt/c/dev/flash-accelerator-tests/rigs/fw_map_nrf && make"

python hardware/boards.py flash h723 rigs/fw_map_h7/fw.bin
python -m pyocd flash -u 1050219420 -t nrf52840 --connect halt --base-address 0x0 --format bin rigs/fw_map_nrf/fw.bin

python -m flashmap selftest --port COM21      # H723
python -m flashmap selftest --port COM24      # nRF52840
python -m flashmap map --port COM21 --out flashmap/h723.json
python -m flashmap map --port COM24 --out flashmap/nrf52840.json

python results/flashmap/map_capture.py both           # the part-specific captures
```

`boards.py flash nrf52840` currently refuses - its probe-attachment check
compares `1050219420` against an enumeration that returns `001050219420`, while
pyocd itself wants the unpadded form. Recorded in
[`REQUESTS_h7_nrf.md`](REQUESTS_h7_nrf.md) item 10 for whoever owns that file;
the direct pyocd line above is the workaround.

Section 3.6 needs two extra builds, which differ from the default and from each
other by nothing but a 16-byte link-time shift. Take CFLAGS and LDFLAGS from the
Makefile, append `-DPROBE_ALIGN=16` to the first and `-Wl,--defsym=PCPAD=0` or
`-Wl,--defsym=PCPAD=16` to the second: PCPAD 0 puts the walk loop inside one
32-byte flash block, PCPAD 16 makes it straddle a boundary.

Captures: [`map_h7_geometry.npz`](../../results/flashmap/map_h7_geometry.npz),
[`map_h7_twin.npz`](../../results/flashmap/map_h7_twin.npz),
[`map_h7_dcache.npz`](../../results/flashmap/map_h7_dcache.npz),
[`map_nrf_geometry.npz`](../../results/flashmap/map_nrf_geometry.npz),
[`map_nrf_counters.npz`](../../results/flashmap/map_nrf_counters.npz).

Both parts: SysTick is the time base and `V` refuses to name it until it has
been seen to advance, because both parts have a dead DWT and they are dead
in different ways. On the nRF52 it sits in the debug power domain and reads a
frozen constant with no debugger attached - the shim's `Y` command reports
`dwt_delta=0` over a loop SysTick times at 200 cycles. On the H723 writes to
`DEMCR` and `DWT->CTRL` from early init are silently dropped and read back zero
while the identical writes from a command handler work; `Y` shows
`demcr=0x00000000 dwtctrl=0x00000000` after boot and the shim's `Q` command
issues the same writes at run time to demonstrate it. A frozen counter makes
every probe identical and therefore every structure look absent, which is the
archetypal silent pass.

---

## 2. The nRF52840 - the control case

`FICR.INFO.PART = 0x00052840`, variant `0x41414630` ("AAF0"),
`HFCLKSTAT = 0x00010001` (crystal-derived 64 MHz), `ICACHECNF = 0` at reset.
All read back by the shim, not assumed.

### 2.1 What the tool must NOT find - and does not

This is the point of the part. `python -m flashmap map` reports:

| claim | value | confidence |
|---|---|---|
| `read_width` | 16 | high |
| `latch` | present, 16 B x 1 entry, depth 1 | low |
| `cache` | present: False | high |
| `waitstate_scaling` | UNKNOWN | none |
| `twin_calibration` | UNKNOWN | none |
| `replacement_policy` | UNKNOWN | none |
| `knob_map` | `icache`, `cacheprof` move nothing | high |

Three of those are the negative test, and all three come back as an *absence*
rather than as a fitted number:

* `cache: present=False`, with the basis *"the best fit has the capacity and
  granularity of the latch already claimed, so there is no multi-line structure
  above it"* and the caveat *"in every knob setting the target is lost after the
  latch's own depth. Reuse that is not back-to-back is not retained anywhere."*
* `waitstate_scaling: UNKNOWN`, caveat *"This part exposes no wait-state knob."*
  Not a slope of zero - no slope.
* `twin_calibration: UNKNOWN`, caveat *"there is no setting at which a flash
  access is known to be free and the twin cannot be calibrated this way."* That
  one is honest about being unable to do something it does do on the H723.

The absence has to arrive at the host as an absent knob, so `K` on this part
lists only `icache` and `cacheprof`, and `S` rejects the others rather than
accepting and ignoring them - a shim that accepted `S waitstates 3` would let
the host believe it had swept an axis that does not exist:

```
S waitstates 3  ->  err unknown knob
S dcache 1      ->  err unknown knob
S prefetch 1    ->  err unknown knob
S waysel 1      ->  err unknown knob
S unified 1     ->  err unknown knob
```

### 2.2 The counters, used as an independent instrument

`NVMC.IHIT` and `NVMC.IMISS` are the only hardware cache counters on either of
my parts. They are sampled inside each primitive's interrupts-off window,
which is the only place they mean anything: read them after a print and the UART
busy-wait loop's own flash instruction fetches land in the count. (`IHIT` is at
`NVMC+0x548` and `IMISS` at `+0x54C`; `+0x544` is reserved, and reading one word
low silently gives `IHIT = 0` and reports IHIT's value as IMISS.)

With the probe loop in SRAM, where the protocol says it belongs:

| probe | cycles | IHIT | IMISS |
|---|---:|---:|---:|
| `flash walk 16 64` | 966 | 0 | 0 |
| `flash walk 256 64` | 966 | 0 | 0 |
| `flash chase 64 16 1` | 1237 | 0 | 0 |
| `flash alt 32 200` | 3606 | 0 | 0 |
| `flash reread 16` | 8 | 0 | 0 |
| `sram walk 16 64` | 776 | 0 | 0 |
| `sram chase 64 16 1` | 1046 | 0 | 0 |
| `sram alt 32 200` | 2413 | 0 | 0 |

Sixteen cells (the eight above at `icache` 0 and 1), every one zero. And the
counters are demonstrably alive, because moving the *probe loop itself* into
flash lights them up on the identical data probes:

| `exec` | `icache` | `flash walk 16 64` | IHIT | IMISS |
|---|---|---:|---:|---:|
| sram | 0 | 966 | 0 | 0 |
| sram | 1 | 966 | 0 | 0 |
| flash | 0 | 1087 | 259 | 194 |
| flash | 1 | 962 | 386 | 67 |

So: the counters count, they count instruction fetches, and no data access
over the same flash array moves either of them. That is the claim "the cache
is instruction-only" made by counting rather than by timing, and it is much
stronger than the timing evidence on its own - which is also present, in that
section 2.3's whole table is bit-identical at `ICACHECNF = 0` and `1`.

The last row deserves its own sentence: with the probe loop in flash, turning
the I-cache on drops `IMISS` from 194 to 67 for the same 64 accesses. The cache
is working - on the probe's own instruction stream. Section 5.3 is about what
that does and does not let me measure.

### 2.3 What the tool does find

Read width 16 bytes, from a cold stride walk, flash minus its own SRAM twin,
64 accesses:

| stride | 0 | 4 | 8 | 16 | 32 | 64 | 128 | 256 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| delta (cyc) | 1 | 46 | 94 | 190 | 190 | 190 | 190 | 190 |
| per 16 B word |  -  | 0.72 | 1.47 | 2.97 | 2.97 | 2.97 | 2.97 | 2.97 |

Saturates at stride 16 and is bit-identical at `ICACHECNF = 0` and `1`,
which is the control that says this is the array and not the cache. Stride 0  - 
64 reads of the same address - costs the same as 64 SRAM reads.

A 1-entry, 16-byte read latch, from `reread`: read A, read one other address
at A+off, time a re-read of A.

| off | -24 to -4 | 0 | 4 | 8 | 12 | 15 | 16 | 20 to 4096 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| flash | 8 | 5 | 5 | 5 | 5 | 8 | 8 | 8 |
| SRAM twin | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 |

`off = 15` is a 4-byte load covering bytes 15-18, straddling the word boundary,
and it misses exactly as it must. The twin is flat at 6 across all nineteen
offsets, so the probe's own address arithmetic contributes nothing.

It is an aligned word, not a neighbourhood. Sliding A's own alignment moves
the fast window with it, and it always covers exactly the aligned 16 bytes
containing A (76 cells, no exceptions):

| A mod 16 | fast window, relative to A |
|---:|---|
| 0 | 0 to +12 |
| 4 | -4 to +8 |
| 8 | -8 to +4 |
| 12 | -12 to 0 |

Depth is exactly one. `evict n 16` - prime A, touch `n` distinct 16-byte
words, re-read A: `n = 0` gives 5 cycles, `n = 1` gives 8, and 8 at every `n` up
to 1023. Nothing recovers at any larger `n`, because there is nothing above the
latch to recover into.

The host's own words on the aligned-block question: *"aligned-block model 96%
vs proximity model 89% over 47 offsets (17 of them negative)"*.

### 2.4 The four instruments now agree, which they did not before

`nrf52840.md` quotes the per-word cost as a range, 2.5 to 3.0, because
the number moved with the probe's shape: 2.94 in a tight hand-written walk, 0.98
in a compiler-scheduled one, 2.5 in an amplified loop, 3 for an isolated
re-read. With the walk loop written so the loaded value is consumed by the very
next instruction (section 4.1), all four of this tool's instruments converge:

| instrument | cycles per 16-byte word |
|---|---:|
| `walk`, stride 16 or more | 2.969 |
| `chase`, stride 16 or more | 2.984 |
| `alt`, 1000 reps | 2.9975 |
| `reread`, single shot | 3 |

That tightens the published range rather than contradicting it, and it says the
spread was the instrument, not the part.

The `alt` ladder is also the cleanest demonstration I have of *why*
`PROTOCOL.md` has an `alt` mode at all. A 3-cycle effect against a counter with
1-cycle resolution needs amplification, and here is exactly how much:

| reps | 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 200 | 512 | 1000 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cyc / 16 B word | 0.50 | 1.75 | 2.38 | 2.69 | 2.84 | 2.92 | 2.96 | 2.98 | 2.99 | 2.995 | 2.9975 |

At one repetition the probe resolves one sixth of the effect. It takes about 200
before the answer is good to half a percent.

---

## 3. The STM32H723 - the hard case

`DBGMCU_IDC = 0x10016483` (DEV_ID 0x483, rev Z), `FLASH_ACR = 0x00000037`
(`LATENCY = 7`, `WRHIGHFREQ = 3`), `SCB->CCR = 0x00040200` - the part boots
with seven wait states and both L1 caches off. `CCSIDR_D = 0xf01fe019`
(256 sets x 4 ways x 32 B = 32 KB), `CCSIDR_I = 0xf03fe009`
(512 x 2 x 32 B = 32 KB), `CTR = 0x8303c003`. All read back by the shim's `Y`.

### 3.1 The twin, which on this part is a result

`PROTOCOL.md`'s twin is "an uncached RAM region of the same size", and the H723
has two regions that satisfy that description by name. Only one of them is
uncached. `R` therefore exposes four regions, three of them the same size as
flash so the host can be shown the right choice *and* the wrong one:

```
flash   0x08002000 65536 flash
dtcm    0x20001000 65536 dtcm      <- correct: NOT behind the L1 D-cache
axisram 0x24001000 65536 axisram   <- same size, IS behind the L1 D-cache
itcm    0x00001000 16384 itcm
```

`device.twin_region()` picks `dtcm` unaided, by the preference order already in
it. Here is what the other choice costs. Same flash column, four candidate
twins, caches off, `LATENCY = 7`, minimum of 5 repeats:

| stride | 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| flash | 602 | 616 | 644 | 700 | 812 | 1036 | 1036 | 1036 | 1036 |
| dtcm | 332 | 332 | 332 | 332 | 332 | 332 | 332 | 332 | 332 |
| itcm | 332 | 332 | 332 | 332 | 332 | 332 | 332 | 332 | 332 |
| axisram | 652 | 652 | 652 | 652 | 652 | 652 | 652 | 652 | 652 |
| flash − dtcm | 270 | 284 | 312 | 368 | 480 | 704 | 704 | 704 | 704 |
| flash − axisram | −50 | −36 | −8 | 48 | 160 | 384 | 384 | 384 | 384 |

* The correct twin reproduces `stm32h723.md`'s published table bit-exactly
  in all nine cells, and the whole row is the closed form
  "4 x accesses + 7 x distinct 32-byte blocks" with no fitted parameter:
  270, 284, 312, 368, 480, 704, 704, 704, 704 predicted and measured.
* The wrong twin halves the answer. 384 against 704 at saturation - 6.0
  cycles per access instead of 11.0, a 45% understatement - because AXI SRAM
  is behind the same L1 D-cache and pays its own miss cost on every access,
  which then cancels out of the subtraction.
* The wrong twin goes negative at small strides. At stride 1 the
  differential is −50: flash appears *faster than RAM*. A tool that looked
  at the sign of the differential would conclude the flash path is the fast one.
* What survives the wrong choice is the *saturating stride*: both columns
  saturate at 32, so `read_width` and `fill_unit` are recoverable from the wrong
  twin while every magnitude is not. The shape of the curve is more robust than
  its scale.
* ITCM is as good a twin as DTCM, to the cycle, at every stride - even
  though the probe loop is being fetched from ITCM at the same time. The M7's
  TCM ports do not contend measurably at this access rate. A small negative
  result, and the one I expected to go the other way.

### 3.2 `CCR.IC` / `CCR.DC` mapped onto `icache` / `dcache`

This part's `FLASH_ACR` has no `PRFTEN`, no `ICEN`, no `DCEN` - only `LATENCY`
and `WRHIGHFREQ`. All the caching is the Cortex-M7 L1, so the shim maps
`SCB->CCR.IC` and `.DC` onto the protocol's canonical `icache` / `dcache` names
and the host compares an H7 against a G4 with no special casing. The readback is
from `CCR`, not an echo of the request.

Cache maintenance is mandatory on an M7 and the order is the whole of it:

* invalidate before enabling - the cache RAM holds garbage out of reset;
* clean+invalidate before disabling, *while the cache is still on*, so dirty
  lines reach memory. `SCB_InvalidateDCache()` on a dirty line throws the line
  away and the data with it; the shim uses `DCCISW` on the way down and `DCISW`
  only on the way up, and nothing writable lives in AXI SRAM except the probe
  buffer and the AXI copy of the probe code, both re-derived at boot;
* never issue a set/way operation on a disabled cache.

The geometry for that walk is read from `CCSIDR` at run time rather than
assumed. This is the H7's version of the `ICRST`/`DCRST` discipline in
`PROTOCOL.md`, and skipping it is trap B5.

The host's cross-product gets the semantics right, and the distinction it draws
is the one that matters:

```
icache     -> read_width : no effect  identical in all 8 matched pairs
icache     -> latch      : no effect  identical in all 8 matched pairs
dcache     -> latch      : masks      8 of 8 pairs moved, 32Bx1 -> all-hit
dcache     -> data_reuse : controls   8 of 8 pairs moved, 4.0 -> 1024.0
wrhighfreq -> everything : no effect  identical in all 12 matched pairs
-> no knob reaches the latch; dcache only masks it
```

`masks`, not `removes`. The D-cache holds both probe addresses trivially, so
a re-read is fast at every offset and the latch becomes invisible - exactly as
on the G474 and F429. Measured:

| configuration | flash `reread 0` | flash `reread 32` | delta | dtcm |
|---|---:|---:|---:|---:|
| `icache=0 dcache=0` | 13 | 20 | 7 | 10 / 10 |
| `icache=0 dcache=1` | 11 | 11 | 0 | 10 / 10 |
| `icache=1 dcache=0` | 13 | 20 | 7 | 10 / 10 |
| `icache=1 dcache=1` | 11 | 11 | 0 | 10 / 10 |

### 3.3 Read width, the latch, and `LATENCY`

The latch is an aligned 32-byte block, not a distance. Sliding A's own
position inside its block moves the fast window with it and the step always
lands on the block boundary (4 alignments x 23 offsets from -40 to +40, no
exceptions):

| A mod 32 | fast window, relative to A |
|---:|---|
| 0 | 0 to +28 |
| 8 | -8 to +20 |
| 16 | -16 to +12 |
| 24 | -24 to +4 |

(The window ends 4 bytes short of the published byte-granular one because this
probe's access is a 4-byte load: at `off = 31` it covers bytes 31-34 and
straddles, the same effect the nRF shows at `off = 15`.)

The differential is exactly `LATENCY`, at every setting from 0 to 15:

| `LATENCY` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| same block | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 |
| other block | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 |
| delta | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |

Sixteen of sixteen, with the same-block row flat at 13 throughout, which is the
cleanest possible statement that a latch hit costs nothing. The host fits it
without being told what to expect:

```
waitstate_scaling = 1.0  [high]
  - latch differential = 1.000 x WS + 0.000, R2=1.0000, worst residual 0.00 cyc (n=12)
  - cold per-word cost = 1.000 x WS + 4.000, R2=1.0000 (n=12)
  - points: 0:0 1:1 2:2 3:3 4:4 5:5 6:6 7:7 8:8 10:10 12:12 15:15
```

The second line is `stm32h723.md`'s closed form recovered as a fit: the `4` is
the fixed cost of an uncached flash access, the `1.000 x WS` is the latch.

`alt` at 200 repetitions confirms the same thing at 1/200-cycle resolution:
within-block offsets give 7.975 cycles per iteration, crossing offsets give
21.940, and the difference of 13.965 is two misses of 6.98 cycles each against a
`LATENCY` of 7.

### 3.4 It is a latch, not a prefetcher

`chase` - a real pointer chase, where the next address is computed from the
value just loaded so nothing can run ahead of it - costs the same as the strided
walk, at every stride:

| stride | 4 | 8 | 16 | 32 | 64 | 128 |
|---|---:|---:|---:|---:|---:|---:|
| `walk` delta | 312 | 358 | 470 | 694 | 694 | 694 |
| `chase` delta | 312 | 368 | 480 | 704 | 704 | 704 |

Defeating prefetch changes nothing, which places this part squarely on
`MECHANISMS.md`'s mechanism 1 (flash width plus a row latch) with no
mechanism 2. Note also that `chase` is the *more* accurate of the two here  - 
section 3.7 is why.

### 3.5 `WRHIGHFREQ` does nothing measurable

The other field in `FLASH_ACR`, swept at three wait-state settings against four
different probes:

| `LATENCY` | `WRHIGHFREQ` | `reread 0` | `reread 32` | walk delta | `alt` delta |
|---:|---:|---:|---:|---:|---:|
| 0 | 0 / 1 / 2 / 3 | 13 | 13 | 270 | 1595 |
| 4 | 0 / 1 / 2 / 3 | 13 | 17 | 502 | 3191 |
| 7 | 0 / 1 / 2 / 3 | 13 | 20 | 694 | 4388 |

Every column is constant across all four `WRHIGHFREQ` values, and the host's
independent cross-product agrees: *"wrhighfreq -> read_width / latch /
data_reuse : no effect, identical in all 12 matched pairs"*. The reference
manual describes it as a programming-time control; on the read path it is inert,
and this is the only place in this repository where that has been checked rather
than assumed.

### 3.6 Instruction placement, and the published "42%" settled

The protocol's rule 3 says the probe loop runs from RAM/ITCM, and
`stm32h723.md` quantifies the cost of ignoring it as a 42% understatement.
The shim's (deliberately unadvertised - section 4.3) `exec` knob runs the *same
compiled bytes* from ITCM, AXI SRAM or flash in place. `nop` is pure instruction
fetch with no data access at all, so it isolates the placement cost:

| `icache` | probe code in | fetch cyc/iter | flash − dtcm, 512 accesses | per access |
|---|---|---:|---:|---:|
| 0 | ITCM | 2.99 | 5632 | 11.000 |
| 0 | AXI SRAM | 13.00 | 1549 | 3.025 |
| 0 | flash | 25.03 | 4595 | 8.975 |
| 1 | ITCM | 2.99 | 5632 | 11.000 |
| 1 | AXI SRAM | 3.00 | 5632 | 11.000 |
| 1 | flash | 3.00 | 5632 | 11.000 |

Instruction fetch really is 8x dearer from flash than from ITCM with the I-cache
off, and turning the I-cache on repairs every row exactly. But the *differential*
understates by 18% from flash here, not 42%, and by 73% from AXI SRAM.

The published number is alignment, and a 16-byte link shift proves it.
`PCPAD` moves the whole probe-code block by 16 bytes without changing a single
instruction - every branch and literal reference inside the block is
PC-relative, so a uniform shift is transparent to the code and moves only where
its loops sit relative to the 32-byte flash read unit. Two builds, identical
except for that shift:

| build | loop body vs the 32 B flash block | fetch cyc/iter | per access |
|---|---|---:|---:|
| `PCPAD=0` | fits inside one block | 3.05 | 10.996 |
| `PCPAD=16` | straddles a boundary | 25.03 | 6.023 |
| either, I-cache on |  -  | 3.0 | 10.99 |

A loop contained in one aligned 32-byte block hits the flash read latch on every
instruction fetch and costs essentially nothing; a loop across two blocks misses
it twice per iteration. So the read latch serves the instruction path too,
and "run the probe from flash" is worth anywhere between 0% and 45% depending on
where the linker happened to put the loop. The published 42% is the straddling
case, and this reproduces it (45%) rather than contradicting it - but it is not
a property of running from flash, it is a property of that build.

> A bonus from this experiment: the first `PCPAD=16` build had a wrong LMA - the
> pad bytes landed at `_sprobecode` and the probe would have executed zeros,
> which decode as `movs r0,r0`, fall through and return the first argument, so
> every "cycle count" would silently have been the buffer's base address. `X`
> answered `fail probecode-itcm-zero` on the first command. That is exactly the
> trap this project has paid for before, caught by the self-test, organically,
> without anyone looking for it. The same check is verified to fire on the nRF
> by a deliberately broken build (`-DBREAK_RAMFUNC_COPY`), which answers
> `fail ramfunc-mismatch` with `w0=0xe00abe00` against `w0_lma=0x47f0e92d`.

### 3.7 An instrument artefact worth naming: the H723 alternates

Repeating one command over the wire on this part gives a strictly alternating
two-state result:

```
T dtcm walk 4 64, twelve times:  346 332 346 332 346 332 346 332 346 332 346 332
```

The alternation tracks the command index - not the stride, not the region,
not the arguments. Alternating two different strides gives
`s4:346 s2:332 s4:346 s2:332 ...`; alternating two different regions does the
same. The identical probe repeated *inside* the shim by `A` does not do it
(`A dtcm walk 2 64` returns `332 332 332.000 9`), so it is the cost of the first
probe after a UART round-trip rather than anything in the memory system.

It is only 14 cycles in 332, but it lands exactly where it does the most damage:
a median over an even number of repeats is parity-dependent, and the stride
sweep came out `690 718 690 718` alternating around the right answer. The
minimum is the correct statistic for a distribution with a hard floor and an
additive disturbance, and with it the table in section 3.1 reproduces the
published numbers in all nine cells. `results/flashmap/map_capture.py` uses `min`; the
host's `Sample` uses the median, by an explicit and normally sound argument,
which is [`REQUESTS_h7_nrf.md`](REQUESTS_h7_nrf.md)'s smallest item and its
easiest fix.

### 3.8 The L1 D-cache

Capacity is 32 KB, from a two-pass `chase` over `N` lines, flash minus DTCM,
with the D-cache off as the positive control:

| lines (bytes) | 64 (2 K) | 256 (8 K) | 512 (16 K) | 1024 (32 K) | 1536 (48 K) | 2048 (64 K) |
|---|---:|---:|---:|---:|---:|---:|
| D-cache off | 1408 | 5632 | 11264 | 22528 | 33792 | 45056 |
| D-cache on | 704 | 2816 | 5632 | 11354 | 27291 | 45045 |

Up to 32 KB the second pass is free (half the cold cost); 48 KB is partial; at
64 KB the cache retains nothing at all and the two rows agree to 11 cycles in
45 000. With the D-cache off a warm walk costs exactly what a cold one does,
which is what licenses reading the row above as the cache. This matches the
published table (32 KB fully retained, 48 KB partially, 64 KB not at all) and
therefore the corrected 32 KB figure rather than the older "an H7's 16 KB".

The *contiguous-fill* eviction probe does not give a clean threshold and I
am not using it as evidence: `evict n 32` with the D-cache on returns
hit/miss/hit at n = 1152 / 1280 / 1408 / 1536 / 2047 = 11 / 20 / 11 / 11 / 20.
Non-monotone, reproducible, and unexplained. The retention probe above is the
one that gives a clean answer, and the host's own claim carries the right lower
bound (`capacity_bytes_min: 32800`).

The index is `addr[12:5]`. Sweeping a single intervening read over 40 KB in
32-byte steps, for four different targets, the target is displaced at exactly
five offsets and no others:

```
flash  A=+0x1000:  8192, 16384, 24576, 32768, 40960
flash  A=+0x1020:  8192, 16384, 24576, 32768, 40960
flash  A=+0x1400:  8192, 16384, 24576, 32768, 40960
flash  A=+0x2000:  8192, 16384, 24576, 32768, 40960
```

8192 bytes = 256 sets x 32 B, exactly as `CCSIDR` implies. Five conflicting
addresses out of 1280 swept, per target, four targets.

And the published associativity anomaly reproduces. `CCSIDR` says 4-way. A
*single* intervening read 8192 bytes away evicts A, at every target tested,
deterministically:

| k reads 8192 B apart | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| flash, any of 4 targets | 11 | 20 | 20 | 20 | 20 | 20 | 20 | 20 |

A 4-way cache with any fill policy that prefers invalid ways should not evict A
when three ways in that set are empty - and the probe runs immediately after a
full clean+invalidate, so they are. `stm32h723.md` recorded this as 21 of 21
trials and flagged it unresolved; it is still unresolved, and section 5.1 is
what I can and cannot say about it.

The host lands on `cache = {present: True, line_bytes: 32, ways: 1,
capacity_bytes: 65536, capacity_bytes_min: 32800}`. The line size is right, the
lower bound on capacity is right, and `ways: 1` is the anomaly above taken at
face value - a cache that gives up a line to one conflicting access is
indistinguishable from a direct-mapped one by this probe. The 65536 upper figure
comes from a configuration with less reuse under-constraining the fit, and the
claim carries that caveat itself.

---

## 4. Three shim defects the tool's own output exposed

All three produced *plausible, confident, wrong* answers, and all three are
fixed. They are here because the fixes live in the shim and the next shim author
will not know to make them.

### 4.1 A walk loop that hides the stall makes the tool deny a structure

`infer` scales its hit/miss threshold by the saturated cost of the cold `walk`.
On the nRF that cost is schedule-dependent by a factor of three: a
compiler-scheduled C loop reports 1.00 cycles per 16-byte word where `chase` and
`alt` both say 2.98, because the loop's other work absorbs the flash stall. With
the threshold set to half of 1.00, the latch's differentials (minus 1 cycle at a
hit, plus 2 at a miss) both landed on the wrong side of it, and the first nRF
map reported:

```
latch = {'present': False}   [HIGH confidence]
basis: "a re-read of A is as dear as a fresh read even when the intervening
        access was to A itself (offset 0)"
```

on a part whose latch `alt` resolved to three decimal places in the same
capture. A high-confidence false negative on the headline structure, produced by
the instrument's own floor becoming the instrument's answer.

The fix is `nrf52840.md` section 1a's `dep=1`, applied: the walk loop is
written out so the loaded value is consumed by the very next instruction.
`walk` then agrees with `chase` and `alt` (section 2.4) and the latch is found.

### 4.2 An unaligned access in `walk` makes the read width come out wrong

With a 32-bit load, strides 1 and 2 are unaligned, and an unaligned flash read
on the H723 costs *more* than an aligned one - so the cost curve dips
between stride 1 and stride 4 and the saturation fit has nothing monotone to
work on:

| stride | 1 | 2 | 4 | 8 | 16 | 32 | 64 |
|---|---:|---:|---:|---:|---:|---:|---:|
| delta, 32-bit load | 525 | 419 | 313 | 369 | 481 | 705 | 705 |
| delta, byte load | 270 | 284 | 312 | 368 | 480 | 704 | 704 |

`walk` now uses a byte load, which is aligned at every stride and is what the
published H7 and G4 walks use. The modes that genuinely need a wider access  - 
`reread`'s straddle test, `chase`'s pointer - keep `LDR`.

### 4.3 Advertising a knob that breaks the measurement discipline

The shims originally advertised `exec` in `K`. The host grids every knob it is
told about, so half of an entire nRF map ran with the probe loop fetched from
flash, where the loop's own instruction fetches thrash the 1-entry read latch
and every data re-read misses. That contributed to section 4.1's false negative,
and on the H723 it tripled a 48-cell grid.

`exec` is no longer advertised. `S exec <n>` still works, and
`results/flashmap/map_capture.py` - which knows what it is doing - uses it for
section 3.6.

> Two more from the same family, recorded in the shims' comments. An ISB in
> the probe's preamble floored the nRF's single-access window at 8 cycles and
> made it blind to the 3-cycle latch *entirely*  -  flash and twin both read 8 at
> every offset, a flat null - because the pipeline refill overlaps the load
> under measurement; DSB alone gives the ordering the probe needs and removing
> the ISB restored 5 against 8 immediately. And writing `reread` and `evict` as
> two functions gave them floors 3 cycles apart on the M4, which is that
> part's whole signal, so `evict` could not see a structure `reread` resolved;
> factoring the window into a shared noinline helper made it worse (both went
> flat), and the answer was not to duplicate the window at all. Both are trap A5
> and trap B4 committed inside a single shim, which is the last place they
> should happen.

---

## 5. What this method cannot reach

Tested, not asserted. Each of these was attempted.

### 5.1 The L1-D replacement policy: no, and the reason is the primitives

The Cortex-M7's policy is documented; the question was whether `memmap/1` can
*measure* it. It cannot, and the host says so in its own words before I do:

```
replacement_policy = lru_or_fifo  [low]
  ! LRU and FIFO are NOT separable with `memmap/1`'s primitives, and this is a
    property of the primitives rather than of the part. Every mode here produces
    a reference string that is monotone.
```

Every primitive leaves A most-recently-used at the moment interference begins,
so LRU and FIFO predict the same eviction point. `PROTOCOL.md` has since gained
a signed `start` for `evict` precisely to break that symmetry - a negative
start makes the interference walk pass *through* A partway along, refreshing it
under LRU and not under FIFO. Both shims implement it, and the checksum moves so
the host can detect support. I ran it:

| A re-touched at step m | 0 | 1 | 2 | 3 | 4 |
|---|---|---|---|---|---|
| eviction point (k reads 8192 B apart) | 1 | 1 | 1 | 1 | 1 |

Inconclusive, and for a structural reason rather than a measurement one: the
discriminator needs an eviction point *above* 1 to have anything to move, and on
this part one aliasing access already evicts (section 3.8). The new argument is
the right tool and the shim honours it; there is simply no room for it here.

What would be needed. Reading the L1 tag RAM directly - which ARMv7-M does
not expose to software on the M7 - or a cycle-accurate model of the fill logic.
Failing that, an eviction surface over a working set small enough that the
anomaly does not dominate, which is a different experiment from anything the
protocol currently has.

### 5.2 Separating the 32-byte latch from the 32-byte L1 line: yes, but only because the cache has an off switch

On this part the flash read unit, the latch granularity and the L1 line size are
all 32 bytes. Every granularity measurement is therefore consistent with either
structure, and the two cannot be told apart by granularity at all.

They *are* separable by depth, and only in the configuration where one of
them is switched off:

| | `evict` depth (intervening reads before A is lost) |
|---|---:|
| D-cache off | 1 |
| D-cache on | about 1024 |

Depth 1 is a single-entry latch; depth 1024 is a 32 KB cache. The host reaches
the same conclusion through `knob_map`: *"no knob reaches the latch; dcache only
masks it"*.

So the answer is conditional, and the condition is the knob. On a part where
the line-filling cache cannot be disabled - and there are plenty - a 32-byte
latch under a 32-byte line is invisible: every probe that would reveal the latch
is answered by the cache first. `PROTOCOL.md`'s `icache` and `dcache` knobs are
not a convenience, they are what makes the bottom layer observable at all, and a
shim for a part without them should report `latch: unknown`, not
`latch: absent`.

### 5.3 Characterising the I-cache: no on the H723, partly on the nRF52840

The protocol has six modes and every one of them is a data access. There is
no instruction-side primitive, and the probe loop is itself the only code whose
fetching can be observed - so on the H723 I can say the I-cache exists and what
it repairs (section 3.6: fetch cost 25.03 down to 3.00 cycles per iteration) and
nothing whatever about its line size, capacity or associativity, even though
`CCSIDR_I` sits right there saying 512 sets x 2 ways x 32 B.

The nRF's counters do let me do something the STM32s cannot, and it is worth
being precise about how much. They let me:

* prove the cache is instruction-only, by counting (section 2.2) - the thing
  that is impossible on every STM32 in this rig;
* watch the cache work on the probe loop itself: with the loop in flash,
  enabling it takes `IMISS` from 194 to 67 over 64 iterations, and on a `chase`
  from 195 to 4;
* bound the loop's own footprint - 195 misses for a loop executed 64 times is
  three misses per iteration, so the loop spans about three 16-byte lines.

They do not let me measure the cache's geometry through `memmap/1`, because
that needs instruction fetches at *chosen* addresses - a table of identical code
stubs, which is how `fw_nrf_probe` measured 2 KB, 16-byte lines, direct-mapped.
That table is outside the protocol. The counters are an instrument for a
primitive the protocol does not have.

What would be needed: an instruction-side mode, say
`icall <table> <n> <stride>` over a shim-provided stub table, which would make
the I-cache a real target on every part, and on the nRF would come with
hardware ground truth attached. That is the single highest-value addition to
`memmap/1` I can see from these two parts.

### 5.4 WRHIGHFREQ: measurably nothing, which is an answer

Twelve matched configuration pairs, three wait-state settings, four probes
(section 3.5), all identical. This is a null with its resolution stated: the
`alt` probe at 200 repetitions would have shown a per-access difference of 0.005
cycles, so the bound is *"smaller than 1/200 of a cycle per access on the read
path"*, not "zero". Whatever `WRHIGHFREQ` does, it does on the write path, which
this instrument does not touch and should not.

### 5.5 Absolute time, and anything below one cycle without repetition

SysTick is a 1-cycle counter and the shim reports cycles, never seconds. A
single-access probe therefore cannot resolve anything below one cycle  - 
section 2.4's ladder shows a 3-cycle effect needing about 200 repetitions to be
read to half a percent, and on the nRF a *single* access resolves 0.5 of the 3.
Sub-cycle effects exist on both parts (the H723's `alt` probe reads 6.98 cycles
per miss where `LATENCY = 7`) and are only reachable by amplification, which
`PROTOCOL.md` warns can itself lose a cycle. Neither part has a sub-cycle
instrument; a scope on a GPIO toggle would be one, at the cost of a completely
different harness.

---

## 6. What these measurements do NOT establish

* One die each. One NUCLEO-H723ZG (DEV_ID 0x483, rev Z) and one
  nRF52840-DK (variant AAF0). Nothing here is a claim about "H7 parts" or
  "Nordic parts". The nRF5340 in particular documents an 8 KB *unified* cache
  that caches data accesses, so section 2's structure does not carry over to it.
* One clock each, and the H7's is the reset clock. HSI 64 MHz on the H723
  with no PLL and no prescalers, 64 MHz from the crystal on the nRF.
  `stm32h723.md` reproduced its numbers at 64, 32 and 16 MHz; I did not re-run
  that here, so "a fixed number of cycles, not a fixed time" is inherited from
  that work rather than re-established.
* The AXI-SRAM arm of section 3.8's conflict map did not reproduce across
  builds. The flash column is clean and matches the published index; the AXI
  SRAM control gave one pattern under an earlier shim build and a different one
  under the final build, and neither is explained. That sub-measurement is not
  build-stable and nothing in section 3.8's conclusions rests on it. It is
  called out rather than dropped because an unexplained instability is itself a
  result about the instrument.
* The contiguous-fill capacity probe is non-monotone (section 3.8) and is
  excluded from the capacity claim rather than averaged into it.
* `replacement_policy` is untested, not tested-and-unknown. Section 5.1
  shows the experiment that would settle it cannot run on this part, not that it
  ran and came back empty.
* Both shims wrap probe offsets inside the region, so an argument larger
  than the buffer aliases rather than faulting, and `chase` with `n x stride`
  larger than the region shortens its node ring to `(n x stride) mod size`. The
  host's plan never reaches either case and the checksum records which addresses
  were actually read, but a hand-driven probe can silently measure a shorter
  ring than it asked for.
* The nRF's I-cache geometry is quoted from `nrf52840.md`, not
  re-measured here - section 5.3 says why this tool cannot re-measure it.
* "`SCB_InvalidateDCache` on a dirty line loses data" is a rule this shim
  follows, not a thing it demonstrates. Nothing writable lives in AXI SRAM
  here except buffers that are re-derived at boot, so the failure mode has no
  way to bite and was never provoked.
* `A`'s repeats are the shim's, not the host's, and the host does not use
  them by default. Where this document quotes an `A` result (the alternation
  diagnosis in section 3.7) it says so.

---

## 7. Against the published numbers in this repository

| published | this tool | verdict |
|---|---|---|
| H723 flash read unit 32 B | `fill_unit = 32`; saturation at stride 32 in 37 of 38 configurations | confirmed (the `read_width` claim reports 8 - a host aggregation bug, [`REQUESTS`](REQUESTS_h7_nrf.md) item 4a) |
| H723 stride table 270 to 704 | 270 284 312 368 480 704 704 704 704 | confirmed, bit-exact in all 9 cells |
| H723 latch 1 entry x 32 B, aligned block | reproduced, 4 alignments x 23 offsets | confirmed |
| H723 differential = `LATENCY`, 0 to 15 | 16 of 16; fit 1.000 x WS + 0.000, R-squared 1.0000 | confirmed |
| H723 law "4n + LATENCY x blocks" | fit 1.000 x WS + 4.000, R-squared 1.0000 | confirmed |
| H723 L1-D = 32 KB (correcting an older "16 KB") | 32 KB retained, 48 KB partial, 64 KB none | confirmed |
| H723 L1-D index `addr[12:5]` | 5 conflicting offsets in 1280 swept, x 4 targets | confirmed |
| H723 "4-way per CCSIDR, but one aliasing read evicts, 21/21" | reproduced at all 4 targets, deterministic | confirmed, still unexplained |
| H723 "probe in flash understates by 42%" | 0% or 45% depending on a 16-byte link shift; 73% from AXI SRAM | refined - the published figure is the straddling case |
| H723 `WRHIGHFREQ` | not previously swept | new: no measurable effect on the read path |
| nRF read width 16 B | saturates at stride 16, all knob settings | confirmed |
| nRF latch 1 x 16 B, depth 1, aligned word | reproduced; aligned-block 96% vs proximity 89% | confirmed |
| nRF per-word cost "2.5 to 3.0, build-dependent" | walk 2.969, chase 2.984, alt 2.9975, single-shot 3 | tightened - the spread was the instrument |
| nRF "no wait-state axis" | `waitstate_scaling = UNKNOWN`, no knob to sweep | confirmed as an absence |
| nRF "no data cache" | `cache = {present: False}` | confirmed as an absence |
| nRF "I-cache is instruction-only" | 16 data probes, IHIT = IMISS = 0, counters proven live | confirmed by counting |
| nRF DWT frozen | `dwt_delta = 0` with no debugger | confirmed |
| H723 DWT dead if enabled early | `demcr = 0` after boot; the same writes work from a command handler | confirmed |
