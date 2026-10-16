# X-CUBE-SBSFU on the NUCLEO-L152RE

A second board for the SPI/AES timing oracle that
[`research/exposure/BOOTLOADER_SPI_ORACLE.md`](../../research/exposure/BOOTLOADER_SPI_ORACLE.md)
screens for: ST's X-CUBE-SBSFU, in its `2_Images_ExtFlash` configuration,
staging an AES-CBC-encrypted image in an off-chip SPI NOR that the bootloader
reads back block by block, decrypting between reads.

The first board was the SAM D21 Xplained Pro
([`rigs/fw_samd21_sbsfu/`](../fw_samd21_sbsfu/)), which recovered the whole
AES-128 key. This one exists to answer the question that result leaves open.

## Why a second board, and why this one

The SAM D21 port had to hand-write a HAL, because X-CUBE-SBSFU has no
Microchip support and there is no Atmel driver to point it at. So the key
recovered there was recovered through code written for the purpose, and the
honest reading is that the timing channel was demonstrated on *a* bootloader
running ST's cipher, not on the thing an integrator would ship.

The L152 removes that objection. It is an ST part, ST ships a real
`STM32L1xx_HAL_Driver` for it, and the SPI transactions the attack times go
through `HAL_SPI_TransmitReceive` exactly as an integrator's would. What
stays hand-written is the same seam ST designed for it: one directory per
board under `NUCLEO_L152RE/`, which is how ST's own `Projects/` tree is laid
out.

It is also the part this project has already characterised as the floor case
for the channel — no cache at all, and a `LATENCY` field one bit wide, so
the only configuration that has a wait state is the one this port runs in.
See [`research/targets/stm32l152.md`](../../research/targets/stm32l152.md).

## Status

| | |
|---|---|
| Vendor sources | `./fetch_sbsfu.sh` next door for X-CUBE-SBSFU v2.7.0, `./fetch_cubel1.sh` here for STM32CubeL1 v1.10.6 (HAL driver V1.4.6) |
| **BSP** | [`NUCLEO_L152RE/BSP/`](NUCLEO_L152RE/BSP/) written: the `BSP_QSPI_*` API over SPI2, on ST's HAL |
| **Bring-up image** | [`bringup/`](bringup/) written and building |
| Bring-up, clock half | **verified on silicon**: 32 MHz, one flash wait state, `FLASH_ACR` 0x07, IDCODE 0x10086437, and `MPU_TYPE` 0x800 -- this die HAS an MPU, eight regions |
| Bring-up, bus half | **ALL PASS on silicon** with a Winbond W25Q256JV fitted. JEDEC ID `ef 40 19`; 64 KB block erase verified blank by reading it back; a 16-byte write across a page boundary read back whole; reads of 16, 64, 512 and 4096 bytes all matched; one counted chip-select envelope per `BSP_QSPI_Read` |
| Memory map | [`NUCLEO_L152RE/Linker_Common/`](NUCLEO_L152RE/Linker_Common/) written, and the link fits: 80 KB of SE region against about 78 KB used |
| **SBSFU port layer** | complete: `sfu_low_level`, `sfu_low_level_flash_int`, `sfu_low_level_flash_ext`, `sfu_low_level_security`, `se_low_level` |
| **ST's application layer** | **compiles unmodified** -- `sfu_boot`, `sfu_fwimg_common`, `sfu_fwimg_no_swap`, `sfu_loader`, `sfu_com_loader`, `sfu_com_trace`, `sfu_error`, `sfu_new_image`, `sfu_low_level_flash`. One tracked one-line patch between them |
| **Secure Engine + mbedTLS** | builds and links, 64 translation units: 8 port, 18 HAL, 10 SBSFU, 7 Secure Engine, 23 mbedTLS |
| **Links** | `build/sbsfu.elf`, 122 144 B text, 192 B data, 2 800 B bss |
| **AES tables in flash** | confirmed from the symbol table, not from the config: `RT0` at `0x080017f8`, `RSb` at `0x08001ff8` |
| **Runs on silicon** | **yes.** Boots, runs ST's state machine, reads the serial flash, and reaches the YMODEM local loader |
| **Bus traffic from the bootloader** | **measured**: 4 data reads, 384 bytes, 5 status polls per boot -- SBSFU reading the image headers over SPI2 through this port's BSP |
| **Image staging** | **works** -- an image built with ST's own `prepareimage` goes in over SBSFU's YMODEM loader: 66 page programs into the W25Q256JV |
| **Install pass** | **runs to completion.** The installer reads the download slot back, decrypts and hashes it, the signature verifies, and SBSFU executes the image. [`results/bootloader_spi/l152/README.md`](../../results/bootloader_spi/l152/README.md) |
| **Oracle capture** | **taken.** 200 passes, 246 543 timed AES blocks, F303 on PA8 |
| **Key recovered** | **the whole AES-128 key**, `4f454d5f4b45595f434f4d50414e5931`, 16 of 16 bytes from 198 072 blocks at a 5.36 sd margin, with NO residual search. [`results/bootloader_spi/l152/README.md`](../../results/bootloader_spi/l152/README.md) |
| **RAM twin** | **taken, and it passes** -- `RAMTABLES=1` puts mbedTLS's tables in `.bss` and the same analysis on 147 789 traces each gives **0/16 against 16/16**, effect **-0.99 +/- 0.43 ns against -17.89 +/- 0.46**. The twin is the QUIETER capture (residual sd 128.9 against 140.3 ns), so it had more power to resolve an effect and saw none. It is the flash read path, not the cipher |
| Bus-side timing | [`rigs/fw_f303_spitimer/`](../fw_f303_spitimer/) exists and is unchanged; not yet pointed at this board |

## Wiring, as fitted

| L152 pin | header | signal |
|---|---|---|
| `PB13` | CN10 pin 30 | SPI2_SCK (AF5) -> SCK |
| `PB14` | CN10 pin 28 | SPI2_MISO (AF5) -> SO |
| `PB15` | CN10 pin 26 | SPI2_MOSI (AF5) -> SI |
| `PA8` | CN9 pin 8 (D7) | GPIO output -> /CS |

Check the header positions against UM1724 for the L152RE rather than against
this table: the NUCLEO-64 Arduino mapping differs between targets, and the
morpho positions are the ones worth reading off the document.

`/WP` (pin 3) and `/HOLD` (pin 7) on the memory must be tied high. A part
with `/WP` floating can refuse the status-register write that clears block
protection, and the driver reports that case as `protected (check /WP)`
rather than failing later and elsewhere.

**Chip-select is a plain GPIO, and that is the whole attack.** PA8 is not an
NSS pin for SPI2 — that would be PB12 — so hardware framing is not available
and `SPI_NSS_SOFT` is forced. The envelope around each read is therefore
produced by the driver's own C: CS falls when it says so and rises when it
says so, with the cipher running in between, so both edges the attacker
times are the victim's.

PA8 is on CN9 while SPI2 is on CN10, so the chip-select lead runs across the
board with a ground return that does not match SCK's. That is worth knowing
when reading a capture — CS edges *are* the measurement — but it is not a
reason to rewire: the edges are software-driven and slow, and the first
capture is what should decide whether it matters.

## What the bus costs, measured

| read | per envelope |
|---|---|
| 16 bytes | 115 us |
| 64 bytes | 353 us |
| 512 bytes | 2 583 us |
| 4096 bytes | 20 407 us |

Taken over a thousand back-to-back reads, so these are per-envelope
averages rather than a single draw.

They are about five times the bus time: 64 bytes plus a four-byte header at
8 MHz is 68 us of clocking, against 353 us measured. The difference is
`HAL_SPI_TransmitReceive`'s per-byte polling at a 32 MHz core, and it is
**deliberately not optimised away** -- an attack demonstrated through the
HAL is an attack on what integrators ship, and a hand-rolled register loop
here would be measuring a driver nobody writes. It costs throughput and
nothing else: the overhead is outside the AES, lands in the same place on
every block, and does not change the interval the probe measures.

For planning a campaign, the figure that matters is per AES block. At
`CHUNK=64` a chunk is four blocks, so the bus contributes about 88 us per
block -- close enough to the SAM D21's 110.7 us that trace counts carry
across.

## The part is bigger than the driver addresses

A W25Q256JV is 32 MB and every opcode this driver issues carries a 24-bit
address, which reaches 16 MB. `BSP_QSPI_Init` therefore clamps the size it
reports, so the bounds checks reject an unreachable address rather than
letting the chip alias it to the start of the array and answer with the
wrong data and no error. The download slot is 384 KB at offset 0, so
nothing here needs the upper half; reaching it would want the 4-byte
opcodes (`0x13`, `0x12`, `0xDC`) or `EN4B`.

## How close to stock this is

The brief was to keep ST's shipped configuration wherever a real integrator
would.

| what changes | why it is realistic |
|---|---|
| a new `NUCLEO_L152RE/` board directory | this is the port seam ST designed. Every board in `Projects/` has its own copy of these files; adding one is adding a board, not modifying the product |
| a new BSP with ST's `BSP_QSPI_*` names | so `sfu_low_level_flash_ext.c` changes by one `#include` and nothing else. The signatures are byte-for-byte ST's, from `stm32l475e_iot01_qspi.h` |
| the HAL | **not** changed: ST's own `STM32L1xx_HAL_Driver`, unmodified, from the Cube package |
| the clock configuration | copied from ST's own `NUCLEO-L152RE/Examples/SPI/SPI_FullDuplex_ComPolling`, which is where the HSI/PLL6/DIV3 -> 32 MHz, range 1, one-wait-state sequence comes from |
| `stm32l1xx_hal_conf.h` | ST's `NUCLEO-L152RE/Templates` copy, verbatim except for line endings. It is a file ST expects each project to own |

ST ships that file with CRLF and `.gitattributes` pins LF in this tree, so a
byte-for-byte `diff` against the Cube checkout shows every line changed and
no content changed. Compare with `diff --strip-trailing-cr` before concluding
anything from it.

Everything above the port layer is ST's, and the crypto scheme stays at the
shipped `SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256`.

### Checking it, rather than claiming it

```bash
./diff_vs_stock.sh          # one line per file
./diff_vs_stock.sh -v       # full unified diffs, and the patch bodies
```

As of the last run:

| | |
|---|---|
| files this rig keeps its own copy of | 15 changed from ST's, 7 new, **0 unchanged** |
| SBSFU application sources compiled from the checkout | 10, of which **1 patched** (`sfu_boot.c`, 2 lines) |
| Secure Engine sources compiled from the checkout | 7, of which **1 patched** (`se_callgate.c`, 21 lines) |
| mbedTLS | 23 files, none patched |

**Nothing in the port directory is unchanged from ST, and that is not the
damning number it looks like.** Those twenty-two files are the board layer
— `Core/`, `SBSFU/Target/`, `SECoreBin/`, `BSP/` — and every board in ST's
`Projects/` tree has its own. Changing them *is* porting. The number that
carries the realism claim is the one below it: the application and Secure
Engine sources compile straight out of the pinned checkout, which is never
written to, and only two of the seventeen carry a patch.

**`sfu_fwimg_no_swap.c` — the read / decrypt / hash loop this whole
campaign attacks — is stock**, and what it does is described in
[`results/bootloader_spi/PROTOCOL.md`](../../results/bootloader_spi/PROTOCOL.md).

**A stock `.c` is not the same as a stock build of it**, and the report says
so. Those files are ST's byte for byte but compile against this port's
headers: `app_sfu.h` and `sfu_fwimg_internal.h` are both in the changed
list, and the second is what makes `SFU_IMG_CHUNK_SIZE` a build option.
`make chunkcheck` asserts that the override actually reaches the loop,
because for a while it silently did not.

### The two patches, in full

| patch | against | what and why |
|---|---|---|
| `0001-sfu_boot-l1-it-header.patch` | `sfu_boot.c` | 2 lines. Drops an `#include "stm32l4xx_it.h"`, which does not exist on this part |
| `0002-se_callgate-trace-caller-checks.patch` | `se_callgate.c` | 21 lines, and **off by default** — it is behind `GATE_TRACE=1` and reports the caller's LR when the call gate rejects a caller. Diagnostic only; the capture builds do not enable it |

Both are applied at build time into `build/`, never to the checkout, with
`patch -F0` and no fuzz — so if a future X-CUBE-SBSFU release moves the
context, the build fails loudly rather than applying a patch somewhere
plausible.

### Deviations that are NOT in a patch file

These are in the port's own files, so `diff_vs_stock.sh` shows them as
changed lines rather than as a patch. They are the ones worth knowing about:

| where | what | why |
|---|---|---|
| `se_low_level.c` | `SE_LL_FLASH_Read` reads with `memcpy` instead of delegating | delegating recursed: the delegate routes header reads back through the call gate. ST's split-binary build cannot hit this; a single-image port can |
| `sfu_low_level_security.c` | `apply_wrp()` rewritten for the L1's four flat sector masks; flow-control steps added | the L1 has no `WRPArea`, and ST's flow-control accumulator must be fed or the first check stops the boot |
| `main.c` | `port_preflight()`, `port_direct_install()`, ST's verbatim 32 MHz clock config | the direct-install path is the instrumentation; it is behind `DIRECT_INSTALL=1` |
| `syscalls.c` (new) | retargets `_write` to the SBSFU UART | `TRACE` is `(void) printf` and `nosys.specs` discards it. Not cosmetic — the YMODEM sender keys on ST's prompt string |
| `mapping_fwimg.ld` | slots cut to 64 KB each | sized to the timer's buffer. **The file carries the old values and the arithmetic for putting them back** |

Build-time switches — `CHUNK`, `DIRECT_INSTALL`, `ORACLE`, `RAMTABLES` —
change behaviour through `-D` flags rather than edits, and each is
documented where it is defined in the Makefile.

## Building

```bash
./fetch_cubel1.sh
wsl -- bash -lc 'cd /mnt/d/.../rigs/fw_l152_sbsfu/bringup && make'
python rigs/host/l152_spif_bringup.py
```

The bring-up **erases the first 64 KB of the attached serial flash**. That
chip holds nothing but staged images, so it is cheap — but it is not
read-only, and it should not be run against a board mid-campaign.
