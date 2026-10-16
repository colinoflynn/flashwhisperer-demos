# Wiring the NUCLEO-F303RE as a bus-side timer

**TWO VICTIMS NOW USE THIS TIMER, and the F303 side is identical for both.**
It is one file rather than two because the only thing that differs is which
pin on the victim carries chip-select; duplicating the rest would be two
documents to keep in step, and this project has paid for that before.

* §1-§4 are the **SAM D21 Xplained Pro** ([`rigs/fw_samd21_sbsfu/`](../fw_samd21_sbsfu/)),
  the board the whole rig was built against and the one the key was
  recovered on.
* §6 is the **NUCLEO-L152RE** ([`rigs/fw_l152_sbsfu/`](../fw_l152_sbsfu/)),
  which needs no board rework at all -- its memory is on flying leads, so
  chip-select is already a header pin.
* §5's sanity checks apply to both and are not optional for either.

The victim in §1-§4 is a SAM D21 Xplained Pro running the SBSFU port in
[`rigs/fw_samd21_sbsfu/`](../fw_samd21_sbsfu/). Its encrypted image sits in the
board's on-board 8 Mbit serial flash, and the bootloader reads it back over
SERCOM5 one `SFU_IMG_CHUNK_SIZE` chunk at a time, decrypting each chunk between
reads. The attacker times the gap between chip-select envelopes.

This file is the wiring. It requires **R313 populated with R314 left in
place**, which connects `PA13` (`#CS`) to EXT3 pin 8 without lifting it from
the flash; without that link `#CS` does not leave the board and only the
SCK-gap fallback in §4 is available.

## 0. State of this bench's wiring — **11/11, 2026-09-26**

**The firmware now exists and has measured a pass.** `main.c`, `startup.c` and
`link.ld` in this directory are a TIM2 both-edge input capture feeding DMA1
channel 5 into a 12 288-entry buffer at 64 MHz (15.62 ns per tick), driven
from the host by [`rigs/host/spitimer.py`](../host/spitimer.py). One trap is
worth reading before changing the arming code: see the comment on
`capture_arm()`, which drops `CC1DE` before touching anything. Clearing
`CC1IF` alone is not enough — a DMA request already delivered survives the
channel being disabled, and the first arm after a stretch of uncaptured
traffic serviced it and wrote one stale timestamp from the previous epoch
into `cap[0]`. That shifts the fall/rise parity of the whole capture.

Run [`rigs/host/spitimer_wiring.py`](../host/spitimer_wiring.py) to regenerate.
It drives and reads both boards through their debug probes, so it needs no
firmware on either.

| link | state | how it is known |
|---|---|---|
| `#CS` PA13 (EXT3-8) → F303 `PA0` | **good** | follows in both drive directions under both F303 pull directions |
| `SCK` PB23 (EXT3-18) → F303 `PB0` | **good** | same, and both locator scans agree |
| GND | **good** | implied: neither link would resolve without a common reference |
| `PA13` → AT25DF `#CS` on the board | **good** | §C bit-bangs `0x9F` through PA13/PB23/PB22/PB16 and the flash answers |

**Both conditions hold at once, and that is the point.** Adding the `#CS` link
could have been done the way the user guide's Table 4-7 note 2 describes — by
*moving* R314 to R313 — and on the plain reading of that sentence moving it
takes `PA13` away from the flash's `#CS`, which this demo needs. The check that
distinguishes the two outcomes is section C: it still identifies the
AT25DF081A, so `PA13` now drives the flash select *and* EXT3 pin 8 together.
Nothing else on the board drives that header pin, so there is no contention.

Re-run both assertions after any rework on this board. A green section A with a
silent section C means the chip-select has been lifted, and every capture taken
in that state would be of a bootloader reading nothing.

### Before the fix, for the record

The `#CS` link read dead on 2026-09-26 with the SAM D21 pad following every
drive, the F303 pin following only its own pull resistor, and a scan of *every*
F303 pin — and, in reverse, of every SAM D21 PORTA/PORTB pin — finding none
that moved. That combination is what identified an unpopulated R313 rather than
a misplaced jumper: had the wire landed a row over at either end, one of the
scans would have caught it.

### What the checker found on the flash itself

`0x9F` returns manufacturer `0x1F`, device `0x45 0x01` — an **AT25DF081A,
8 Mbit = 1 MB**, read off the part rather than inferred from the user guide's
"8Mbit serial flash". That capacity is what decides whether this target has a
distinct-input ceiling: 1 MB of ciphertext is 65 536 AES-CBC blocks, and
because SBSFU's input *is* the ciphertext block, rewriting the image gives a
fresh set every time. There is no ceiling here of the kind
[`BOOTLOADER_SPI_ORACLE.md`](../../research/exposure/BOOTLOADER_SPI_ORACLE.md)
§4C imposes on MCUboot and wolfBoot.

## 1. What the SAM D21 side already is

From the SAM D21 Xplained Pro user guide (Atmel-42220B, 04/2016), Table 4-8
*Serial Flash Connections*, quoted verbatim:

```
Pin on SAM D21   Function          Serial Flash   Shared functionality
PA13             GPIO #CS                         EXT3 PIN8 (default disconnected)
PB22             SERCOM5 PAD[2]    SPI MOSI  SI   EXT3 and EDBG
PB16             SERCOM5 PAD[0]    SPI MISO  SO   EXT3 and EDBG
PB23             SERCOM5 PAD[3]    SPI SCK   SCK  EXT3 and EDBG
```

and Table 4-7 for the EXT3 header positions:

```
 8 [PWM(-)]    PA13   TCC2/WO[1]        Serial Flash SS
16 [SPI_MOSI]  PB22   SERCOM5 PAD[2]    SPI MOSI   EDBG and Serial Flash
17 [SPI_MISO]  PB16   SERCOM5 PAD[0]    SPI MISO   EDBG and Serial Flash
18 [SPI_SCK]   PB23   SERCOM5 PAD[3]    SPI SCK    EDBG and Serial Flash
19 [GND]
20 [VCC]
```

Note 2 of that table is the modification this file assumes: *"PA13 is by default
connected to the Serial Flash SS line and is disconnected from the EXT3 PIN8.
This can be changed by moving the 0Ω resistor R314 to R313."*

Two consequences worth holding on to:

* **MOSI/MISO/SCK are shared with the EDBG**, which has a Data Gateway Interface
  on the same three lines. It is idle unless something asks for it, but if the
  captured waveform ever shows traffic the bootloader did not generate, that is
  where it came from.
* **`#CS` is a plain GPIO**, driven by software, not by the SERCOM. So the
  chip-select envelope is exactly what the driver code does, not what a
  peripheral does around a transfer — which is the property the whole attack
  rests on.

## 2. The connections

Three wires for the timing attack. Two more if the ciphertext is to be recovered
passively rather than taken from the image the host wrote.

| | SAM D21 XPro | signal | NUCLEO-F303RE | Nucleo pin | F303 function |
|---|---|---|---|---|---|
| **1** | EXT3 pin 19 | GND | **GND** | CN6 pin 6 (or CN5 pin 7) | — |
| **2** | EXT3 pin 8 | `#CS` (PA13) | **PA0** | CN8 pin 1, silkscreen `A0` | `TIM2_CH1` / `TIM2_CH2`, AF1 |
| **3** | EXT3 pin 18 | `SCK` (PB23) | **PB0** | CN8 pin 4, silkscreen `A3` | `TIM3_CH3`, AF2 |
| 4 | EXT3 pin 17 | `MISO` (PB16) | PB4 | CN9 pin 6, silkscreen `D5` | `SPI1_MISO`, AF5 |
| 5 | EXT3 pin 18 | `SCK` (PB23) | PB3 | CN9 pin 4, silkscreen `D3` | `SPI1_SCK`, AF5 |

**Do not connect EXT3 pin 20 (VCC).** Both boards are separately USB-powered and
tying the two 3V3 rails together achieves nothing the ground wire does not.
Ground is not optional: without a shared reference the F303 sees noise, not
edges.

Rows 3 and 5 both take SCK. If both are used, fan the one wire out to PB0 and
PB3 — they are inputs, so the only cost is a little extra capacitance on a line
the AT25DF is already driving.

## 3. Why PA0, and why a timer rather than an interrupt

`#CS` goes to **PA0** because `PA0` is `TIM2_CH1_ETR` on alternate function
**AF1**, and `TIM2` is the F303's **32-bit** general-purpose timer. At 72 MHz
that is **13.9 ns per tick** and **59.6 s before it wraps** — enough resolution
for the ~15 ns effects this channel produces, and enough range that a whole boot
pass fits in one unwrapped counter.

The capture is set up as **input capture on one pin, two channels**: `CC1S = 01`
maps IC1 to TI1 and captures the **rising** edge, `CC2S = 10` maps IC2 to the
*same* TI1 and captures the **falling** edge. One wire, two independent capture
registers, two DMA streams. The interval the attack wants —
CS-rise of read *N* to CS-fall of read *N+1* — is then a subtraction between the
two buffers with no software in the path at all.

This is deliberately **not** an EXTI interrupt handler. An ISR entry on a
Cortex-M4 costs 12 cycles plus whatever the compiler prologue adds, and it
varies with what the core was doing when the edge arrived. That jitter is the
same order as the signal. Hardware capture has none of it: the timestamp is
latched by the timer, and DMA moves it without the core waking up.

`PA0` is otherwise free on a NUCLEO-64 — the user button is `PC13`, not `PA0`.
Avoid `PA5`, which is also `TIM2_CH1` (AF1) but carries the green `LD2` LED and
so is loaded.

`SCK` on **PB0** (`TIM3_CH3`, AF2) is a sanity channel rather than part of the
attack: counting its edges per envelope confirms the bootloader really read the
number of bytes `SFU_IMG_CHUNK_SIZE` says it should, and measuring its period
gives the actual SCLK. A capture where the chunk size in the firmware and the
byte count on the wire disagree is the failure this catches.

## 4. If R313 is not populated — the SCK-gap fallback

Time the **SCK** gaps instead. The chip-select envelope encloses the clock
burst, so the interval from the last SCK edge of read *N* to the first SCK edge
of read *N+1* differs from the CS interval only by the driver's fixed
pre-transfer and post-transfer overhead — a constant, which the attack
differences away. It costs one extra step (finding the burst boundaries in a
dense edge stream) and nothing else. Wire only rows 1 and 3.

## 5. Sanity checks before trusting a capture

Per [`research/mechanism/MEASURING_CHANNELS.md`](../../research/mechanism/MEASURING_CHANNELS.md):

* **The timer must be live.** A dead counter reads constant and would certify
  any build as constant-time, which has already happened once on this bench.
  The firmware reports `TIM2->CNT` advancing at boot and refuses to capture if
  it does not.
* **Count the envelopes — and the rule needed refining once it was run.**
  The pass over an image of *S* bytes at chunk *K* produces `ceil(S/K)` DATA
  envelopes, each preceded by one short status-poll envelope, in strict
  alternation. Measured on 2 816 chunks: poll 3.64 us, data 35.45 us, and
  **2 817** alternating pairs, not 2 816. The extra one is the first read of
  the phase that follows the verify pass, which has the same shape until its
  first write breaks the alternation — so the rule to check is *"the
  alternating run is at least `ceil(S/K)` pairs"*, and the pass is its first
  `ceil(S/K)`. `verify_pass()` in
  [`rigs/host/spitimer.py`](../host/spitimer.py) is that check.

  The off-by-one matters more than it looks. If the extra pair were at the
  FRONT rather than the back, every interval would be attributed to the wrong
  block and the recovery would fail in a way indistinguishable from "no
  channel". It is dated independently of the envelope count, by SHA-256: the
  bootloader hashes 16 bytes per chunk and SHA-256 compresses once per 64, so
  every fourth interval is ~310 us against a ~110 us median. Measured, the
  slow one is index 3 mod 4 — which is where it belongs if interval *k*
  follows chunk *k* and chunk 0 is the first body block. The extra pair is at
  the end.

* **The capture buffer WILL overflow, and that is expected.** The install does
  not stop when the verify pass does; it goes on to copy the image and then
  scan the whole 1 MB download slot, 65 536 more reads at chunk 16. The pass
  being measured is a prefix of what was recorded. A capture is not rejected
  for overflowing; it is rejected if the alternating prefix is short.
* **Take the RAM twin. TAKEN, 2026-09-26, and it passes.** The SBSFU port
  builds it with `RAMTABLES=1`, which comments out `MBEDTLS_AES_ROM_TABLES`
  so mbedTLS generates its tables into `.bss` — `RT0` moves from `0x168c` to
  `0x200011f8`, flash text drops 2 124 bytes, and nothing else about the
  build, the image, the probe or the analysis changes. On the same 28 706
  traces the recovery goes **11/16 → 0/16** and the pooled effect
  **−20.80 ± 0.41 ns → −0.34 ± 0.30**. The alternative this control exists
  to exclude — the cipher's own data dependence, live on an ARMv6-M core
  with no IT blocks — is excluded.

  **The control needs its own control**, because "no effect" is also what a
  broken rig produces. What must still be TRUE in the twin, and was: the
  SHA-256 every-fourth-block period (0.250 in both), the SysTick mode (0.108
  against 0.101), and the envelope pairing. The twin was in fact 13.6 ns
  *quieter*, and its error bar smaller — so it could have resolved 0.9 ns at
  3 σ and saw nothing.
  [`results/bootloader_spi/samd21/ramtwin_compare.py`](../../results/bootloader_spi/samd21/ramtwin_compare.py)

## 6. The NUCLEO-L152RE victim

The second victim is a NUCLEO-L152RE running
[`rigs/fw_l152_sbsfu/`](../fw_l152_sbsfu/), with a Winbond W25Q256JV on
flying leads from SPI2. **No board rework is needed**, which is the one
way this target is easier than the SAM D21: there is no R313 to populate,
because chip-select never went anywhere near a 0 Ohm link -- it is a plain
GPIO on a header pin with a wire already soldered to it.

### The connections

| | NUCLEO-L152RE | signal | NUCLEO-F303RE | Nucleo pin | F303 function |
|---|---|---|---|---|---|
| **1** | CN6 pin 6 (or CN7 pin 8) | GND | **GND** | CN6 pin 6 (or CN5 pin 7) | — |
| **2** | `PA8`, CN9 pin 8 (`D7`) | `/CS` | **PA0** | CN8 pin 1, silkscreen `A0` | `TIM2_CH1` / `TIM2_CH2`, AF1 |
| 3 | `PB13`, CN10 pin 30 | `SCK` | PB0 | CN8 pin 4, silkscreen `A3` | `TIM3_CH3`, AF2 |
| 4 | `PB14`, CN10 pin 28 | `MISO` | PB4 | CN9 pin 6, silkscreen `D5` | `SPI1_MISO`, AF5 |
| 5 | `PB13`, CN10 pin 30 | `SCK` | PB3 | CN9 pin 4, silkscreen `D3` | `SPI1_SCK`, AF5 |

**Rows 1 and 2 are the whole timing attack.** Three and five are the
SCK-gap fallback of §4, which this board does not need because
chip-select is directly available. Four and five together let the
ciphertext be recovered passively off the wire rather than taken from the
image the host wrote -- worth having eventually, not needed for a first
capture.

**Do not connect the two 3V3 rails.** Both boards are separately
USB-powered and tying them together achieves nothing the ground wire does
not. Ground is not optional: without a shared reference the F303 sees
noise, not edges.

The probe wire taps the SAME node that already runs to the memory's `/CS`
(pin 1 of a SOIC-8). Tap it wherever is convenient -- at the header or at
the breakout -- but keep it short and keep it next to the ground lead.
The F303 pin is a high-impedance input, so it does not load the line.

### Check the header positions against UM1724 for the L152RE

The NUCLEO-64 Arduino mapping differs between targets. `D7` is `PA8` on
this one, which the bring-up image confirms by reading `MPU_TYPE` and the
device ID off the same silicon -- but the *header* position is a document
claim, not a measured one, so read it off UM1724 rather than off this
table before cutting anything.

### Confirming the tap before trusting a capture

The bring-up image in [`rigs/fw_l152_sbsfu/bringup/`](../fw_l152_sbsfu/bringup/)
exists for this. Press `1` on its console and `PA8` square-waves at one
second high, one second low, push-pull, with the other three lines left
as unpulled inputs -- so a meter or the F303 can confirm the tap without
any interpretation. That is the L152's equivalent of §5's envelope count,
and it is the cheaper half: it proves the wire, not the firmware.

The expensive half still applies. §5's rule holds here unchanged: the
driver's own envelope counters and the F303's edge count are independent
measurements of the same events, and a capture where they disagree has
lost edges or gained them. The counters are printed by
`rigs/fw_l152_sbsfu`'s `ORACLE=1` build at the end of each pass.

### What differs about the signal itself

Two things, both measured in
[`results/bootloader_spi/l152/README.md`](../../results/bootloader_spi/l152/README.md):

* **The envelopes are wider.** 115 us for a 16-byte read and 353 us for a
  64-byte one, against roughly 110 us per AES block on the SAM D21. The
  bus runs at 8 MHz on both; the difference is `HAL_SPI_TransmitReceive`
  polling a byte at a time, which is left in deliberately because an
  attack demonstrated through ST's HAL is an attack on what integrators
  ship.
* **The chip-select lead crosses the board.** `PA8` is on CN9 and SPI2 is
  on CN10, so the CS wire does not share a ground return with SCK. On a
  software-driven, microsecond-wide envelope that should not matter; it
  is written down because CS edges *are* the measurement, and if a
  capture ever shows edge jitter that the SAM D21's did not, this is the
  first thing to suspect.

## Sources

* UM1724, STM32 Nucleo-64 boards, for the NUCLEO-L152RE Arduino and morpho
  header mapping.
* SAM D21 Xplained Pro User Guide, Atmel-42220B-SAM-D21-Xplained-Pro, 04/2016,
  §4.1.1 Table 4-7 and §4.2.5 Table 4-8.
* STM32F303xD/xE datasheet, alternate-function table: `PA0` → `TIM2_CH1_ETR` on
  AF1, `PB0` → `TIM3_CH3` on AF2.
* NUCLEO-64 Arduino header assignment: `A0` = `PA0` (CN8-1), `A3` = `PB0`
  (CN8-4), `D3` = `PB3` (CN9-4), `D5` = `PB4` (CN9-6), GND at CN6-6 and CN5-7.
