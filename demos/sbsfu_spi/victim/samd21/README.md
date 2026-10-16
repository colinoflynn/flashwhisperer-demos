# X-CUBE-SBSFU on the SAM D21 Xplained Pro

A demo bootloader for the SPI/AES timing oracle that
[`research/exposure/BOOTLOADER_SPI_ORACLE.md`](../../research/exposure/BOOTLOADER_SPI_ORACLE.md)
screens for: ST's X-CUBE-SBSFU, in its `2_Images_ExtFlash` configuration,
staging an AES-CBC-encrypted image in an off-chip SPI NOR that the bootloader
reads back block by block, decrypting between reads.

It runs on a **non-ST part**, which is the point. The channel is not an ST
property — the ledger already carries that from the nRF52840 — but every
bootloader candidate in the sweep was measured on ST silicon, so a port to
Microchip silicon is what separates "SBSFU leaks" from "this part leaks".

## Status

| | |
|---|---|
| **HAL and BSP** | written, compiled, and **verified on silicon** — see *Bring-up* below |
| **SBSFU port layer** | complete: `sfu_low_level`, `sfu_low_level_flash_int`, `sfu_low_level_flash_ext`, `sfu_low_level_security`, `se_low_level` |
| **ST's application layer** | **compiles unmodified** — `sfu_boot`, `sfu_fwimg_common`, `sfu_fwimg_no_swap`, `sfu_loader`, `sfu_com_loader`, `sfu_com_trace`, `sfu_error`, `sfu_new_image`, `sfu_low_level_flash`. One tracked one-line patch between them |
| **Memory map** | `Linker_Common/mapping_sbsfu.ld` and `mapping_fwimg.ld` written |
| **Secure Engine + mbedTLS** | builds and links; `SE_Init` succeeds through the absolute-address call gate |
| **Boots** | the full state machine runs: security check, SE init, slot checks, and the YMODEM local loader |
| **Image staging** | an image built with ST's own `prepareimage` is sent over SBSFU's YMODEM loader into the AT25DF081A; SBSFU reports `New Fw to be installed from slot SLOT_DWL_1` |
| **Oracle components** | all verified on silicon: a 64-byte `SFU_LL_FLASH_Read` from the download slot (one chip-select envelope, counted), `SE_Decrypt_Append` (ST's AES-CBC through mbedTLS), `SE_AuthenticateFW_Append` (SHA-256) |
| Install pass | **runs to completion.** `VerifyFwSignatureBeforeDecrypt` reads every chunk of the staged image over SPI, decrypts and hashes each one, and reaches its tag check |
| Bus-side timing | [`rigs/fw_f303_spitimer/`](../fw_f303_spitimer/) written and measuring: 15.6 ns per tick, one timestamp per chip-select edge |
| Timing measured | yes -- one interval per AES block |
| **Key recovered** | **the whole AES-128 key**, `4f454d5f4b45595f434f4d50414e5931`: 12 000 timed blocks give 11 of 16 bytes and say which five they do not, and 2^40 finishes it in under three minutes. [`results/bootloader_spi/samd21/README.md`](../../results/bootloader_spi/samd21/README.md) |
| **RAM twin** | **taken, and it passes** -- `RAMTABLES=1` puts mbedTLS's tables in `.bss` and the same analysis on the same trace count gives 0/16 against 11/16, effect -0.34 +/- 0.30 ns against -20.80 +/- 0.41. It is the flash read path, not the cipher |

### How the bus traffic is counted

The BSP counts data reads, bytes, status polls, page writes and erases, in
`.noinit` so they survive the reset that a failed install causes, and `main()`
prints the previous boot's totals. That is the target side of the
envelope-count control
[`WIRING.md`](../fw_f303_spitimer/WIRING.md) §5 requires before a capture can
be trusted — and it is also what showed that the decrypt loop was not running
at all, which no amount of reading ST's trace would have said.

`make check` compiles every translation unit that exists and links nothing —
the target to use while the port is incomplete, because it catches the
register-name and prototype errors that are most of the work without needing
the linker script or the Secure Engine. Sixteen objects compile clean:
seven of this port's, nine of ST's.

`make chunkcheck` asserts separately that `SFU_IMG_CHUNK_SIZE` really is
`CHUNK` **as ST's sources resolve it**. Run it after any change to the include
paths; see [chunkprobe.c](chunkprobe.c) for why that phrasing is the whole
test.

## How close to stock this is

The brief was to keep ST's shipped configuration wherever a real integrator
would. Deviations, and why each one is what a user would actually do:

| what changes | why it is realistic |
|---|---|
| a new `SBSFU/Target/` and `SECoreBin/se_low_level.c` for the SAM D21 | this is the port seam ST designed. Every board in `Projects/` has its own copy of these files; adding one is adding a board, not modifying the product |
| a new HAL, [`SAMD21_XPRO/HAL/`](SAMD21_XPRO/HAL/) | the user's own framing: "adding HALs or new chips". It is small — see below |
| a new BSP, [`SAMD21_XPRO/BSP/`](SAMD21_XPRO/BSP/) | ditto; it keeps ST's `BSP_QSPI_*` names so `sfu_low_level_flash_ext.c` changes by one `#include` |
| `SFU_IMG_CHUNK_SIZE` 512 → 64 | a documented setting whose own comment only requires 16-byte alignment. **Forced by simulation, not by preference** — see below |
| `MBEDTLS_AES_ROM_TABLES` uncommented | the flash-saving option mbedTLS documents. Without it the tables are generated into `.bss` and there is no flash channel to measure at all |
| protections without SAM D21 hardware disabled (`SFU_FWALL_PROTECT_ENABLE`, `SFU_MPU_PROTECT_ENABLE`) | the part has no firewall, and no MPU is fitted — **measured**, `MPU_TYPE` reads 0, agreeing with `samd21j18a.h:223`. ST's own M0+ project (`NUCLEO-L073RZ`) is the reference for which protections an M0+ drops |

Everything else is ST's. The crypto scheme stays at the shipped
`SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256`, the loader stays at
`SECBOOT_USE_LOCAL_LOADER` (YMODEM over the EDBG virtual COM port), and
`sfu_fwimg_no_swap.c` — the read/decrypt/hash loop the whole attack targets —
is unmodified, which it can be because it references no STM32 HAL symbol at
all.

### Why the chunk size has to come down

`SFU_IMG_CHUNK_SIZE` sets how many AES blocks hide behind one chip-select
envelope: at ST's shipped 512 bytes it is 32. Simulated on this part's
measured cache geometry
([`results/bootloader_spi/sim_spi_oracle_samd21.json`](../../results/bootloader_spi/sim_spi_oracle_samd21.json)):

| chunk | AES blocks/read | blocks to 16/16 | SPI reads to 16/16 |
|---|---|---|---|
| 16 B | 1 | 100 000 | **100 000** |
| 32 B | 2 | 200 000 | **100 000** |
| 64 B | 4 | 400 000 | **100 000** |
| 128 B | 8 | 1 600 000 | 200 000 |
| 256 B | 16 | never (14/16 at 1.6 M) | — |
| **512 B (shipped)** | 32 | **never (6/16 at 1.6 M)** | — |
| 1024 B | 64 | never (0/16) | — |

So 64 bytes is the largest chunk that costs nothing, and the shipped 512 does
not fall. This part sits between the two geometries already published in
§4A — flatter than the STM32F429's cached column, steeper than the nRF52840's
pure latch.

Those are upper bounds twice over: the simulated timer is noise-free, and the
model is a data-path model that does **not** represent this part's cache being
*unified* with instruction fetch. Silicon will be worse. The numbers are here
to choose a chunk size, not to predict a trace count.

## The HAL is smaller than it sounds

Porting SBSFU off STM32 sounds like reimplementing STM32Cube. Across every
file this port compiles, the complete set of Cube symbols referenced is
`HAL_Delay`, `HAL_SuspendTick`, `HAL_MPU_Disable`, `__HAL_FIREWALL_IS_ENABLED`
and the `HAL_StatusTypeDef` enum. ST had already factored the chip-specific
work into `SBSFU/Target/` and `SECoreBin/`, which every board port is expected
to rewrite. [`SAMD21_XPRO/HAL/samd21_hal.h`](SAMD21_XPRO/HAL/samd21_hal.h)
records the per-file list.

## Bring-up — measured 2026-09-26

[`bringup/`](bringup/) builds a self-test that links **the same** HAL and BSP
sources the bootloader will, reached sibling-relative rather than copied, and
reports through the SWD mailbox at `0x20000000`. Run it with
[`rigs/host/samd21_sbsfu_bringup.py`](../host/samd21_sbsfu_bringup.py).

All stages pass:

```
[ok] SysTick live          5010 cycles for 1000 NOPs
[ok] no MPU fitted         MPU_TYPE=0x00000000, DREGION=0
[ok] BSP_QSPI_Init         QSPI_OK
[ok] JEDEC ID              1F 45 01 (AT25DF081A)
[ok] flash size            1048576 bytes = 1024 KB
[ok] 64 KB block erase     QSPI_OK
[ok] erase verified blank  0 of 4096 bytes not 0xFF
[ok] cross-page write      QSPI_OK
[ok] cross-page read-back  0 of 32 bytes wrong
[ok] read 16/256/4096 B    0 mismatches

SPIF_BAUD = 2 -> SCK = 8.0 MHz
one  16 B read envelope:  1724 cycles (  35.9 us at 48 MHz)
one 512 B read envelope: 42394 cycles ( 883.2 us at 48 MHz)
```

**The two envelope figures are for classifying a capture, not for attacking
one.** They say the driver is polling-limited rather than bus-limited — about
1.71 µs per byte against 1.0 µs of bus time at 8 MHz — and that cost is
constant per byte, so envelope length is linear in transfer size. That is what
lets the F303 tell a 2-byte status poll (~3.4 µs) from a data read (~883 µs at
512 B), which it must do, because ST's `SFU_LL_FLASH_EXT_Read` polls
`BSP_QSPI_GetStatus()` before every data read and each poll is its own
envelope.

## What "unmodified" means here, and how to check it

ST's tree gives every board a full copy of `App/` and `Target/` — nineteen
near-identical ones. Copying that pattern would bury this port's actual
deviations in thousands of lines of duplicated ST code, and "unmodified" would
be something a reader has to take on trust.

So `SAMD21_XPRO/` holds **only files this port changes or owns**, and
everything else compiles straight out of the pinned checkout. A file that is
not in `SAMD21_XPRO/` cannot have been edited, because the build never reads a
local copy of it. `./diff_vs_stock.sh` reports the rest, normalising CRLF→LF
(ST ships CRLF; this repo pins LF) and nothing else:

```
  CHANGED  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_ext.c  (2 lines)
  CHANGED  2_Images_SBSFU/SBSFU/Target/sfu_low_level.{c,h}        rewritten
  CHANGED  2_Images_SBSFU/SBSFU/Target/sfu_low_level_flash_int.{c,h}  rewritten
  NEW      HAL/*, BSP/*
  same     app_sfu.h, mapping_export.h
```

The two-line `sfu_low_level_flash_ext.c` change is one `#include`. That file
holds the chip-select behaviour the entire attack rests on, and it is ST's.

### Bugs this found, all worth keeping

**A copied startup file.** `bringup/startup.c` began as a copy of
`rigs/fw_samd21_aes/startup.c`, which runs interrupts-off throughout and
therefore points every vector at a spin loop. This image calls `HAL_Init()`,
which enables the SysTick interrupt — so the first tick, 1 ms in, vectored
into `Default_Handler`. The mailbox froze at whatever step was running, which
read exactly like the SPI driver hanging. The fault handlers now record the
exception number and stacked PC instead of spinning.

**A green check that checked nothing.** That first run still printed `ok` for
the erase, the blank check, the cross-page write and the read-back — because
those mailbox words were zero-initialised, and zero is `QSPI_OK` and zero is
"no mismatches". Every result word now starts at `0xFFFFFFFF` and the host
prints `--` for any field the firmware never wrote. This is CLAUDE.md's rule
about asking what a green checker is not looking at, caught on the first run
of a new checker.

**A Makefile that built the wrong file.** The obvious spelling — `vpath %.c`
over every source directory, with object names from `$(notdir …)` — silently
compiled **ST's** `sfu_low_level.c` instead of this port's, because the two
share a basename and vpath resolves by search order. It failed loudly only
because ST's version names `RTC_HandleTypeDef`; had the deviations been
subtler it would have built clean and run STM32 code on a SAM D21. The
Makefile now generates one explicit rule per named source, keeps port and
stock objects in separate directories, and `$(error)`s if the two source
lists ever share a basename.

**A build that ignored its own override header, silently.** The chunk size is
the single most important number in this demo, and for a while it was not the
number the Makefile said it was. ST's sources were compiled in ST's own `App/`
directory, so their `#include "sfu_fwimg_internal.h"` found **ST's** copy
sitting next to them — a quoted include searches the including file's own
directory before any `-I`, and that is not overridable by `-I` order or by
`-iquote`. This port's copy, the one that makes `SFU_IMG_CHUNK_SIZE`
configurable, was never read. `CHUNK=64` and `CHUNK=512` produced
**byte-identical objects** while the build reported success at both.

Found by diffing the two objects rather than by reading the code. The fix is
to stage ST's `.c` files into a directory that holds **no headers**, so the
own-directory search finds nothing and resolution falls through to `-I`, where
`SAMD21_XPRO/` comes first. `make chunkcheck` now asserts the outcome from
inside that same staging directory — a probe compiled anywhere else would pass
while the real build was still wrong, which is precisely the failure it exists
to catch.

**ST's caller check, under GCC, tests a register the compiler has already
reused.** This is the one that stopped the demo, and it is a bug in the
shipped middleware rather than in the port.

Every entry point in `se_interface_bootloader.c` opens with
`__IS_SFU_RESERVED()`, which refuses a caller whose return address is outside
the SBSFU ROM region. It gets that address from `get_LR()`, which in the GCC
branch of `se_intrinsics.h` is a plain `static inline` around
`__asm volatile("MOV %0, LR")` — nothing marks it `always_inline`, and nothing
ties the read to function entry. At `-O2` the compiler is free to schedule
that MOV after LR has been reused, and then the check compares a junk value
against the ROM window and returns a bare `SE_ERROR`.

The symptom was that `SE_Decrypt_Append` failed on the first chunk of ST's own
verify loop while the identical call from `main()` succeeded, with both SE
init calls returning `SE_SUCCESS` and the loop bound plainly true. It took
four rounds of instrumentation to corner, and each round is a tracked patch
because each layer folds several failures into one undifferentiated
`SE_ERROR`: the loop's own steps (0002), the mbedTLS return code (0003), which
of the call gate's eight guards fired (0004), and finally the caller address
itself (0005). The gate was never entered; the LR being tested was
`0x20000c48`, an SRAM address no caller can have.

`SAMD21_XPRO/2_Images_SECoreBin/Inc/se_intrinsics.h` is a port copy of ST's
header with `get_LR` replaced by `__builtin_return_address(0)` — as a macro,
so it cannot answer for its own frame if the compiler declines to inline it.
The security property is restored rather than relaxed: before the change the
check was rejecting callers that were **inside** the region, at the
compiler's discretion.

Worth stating plainly, because it is the sort of thing that gets reported as a
port defect: nothing about the SAM D21 causes this. It needs only GCC, `-O2`
and a caller the optimiser happens to schedule badly. The same header is
compiled into every GCC build of this middleware.

**A build system that could not rebuild.** Three separate cases, all silent,
all found within an hour of each other: editing a diagnostic patch rebuilt
nothing (the staged `.c` was newer than ST's source, so `make` called it up to
date and the old instrumentation stayed in the binary); `make CHUNK=16` after
`make CHUNK=512` reported "Nothing to be done" because flags are not a
prerequisite; and a bare `make` built one staged file and stopped, because the
`$(eval)`-generated staging rules are defined long before `all:` and the first
of them became the default goal. The Makefile now lists the patch files as
prerequisites, stamps the flag set and compares it by content, and sets
`.DEFAULT_GOAL`. This is the same shape as the chunk-size bug above and as
CLAUDE.md's rule about green checkers: the build reported success and built
the wrong thing.

### Two collisions the port had to resolve

**`FLASH_PAGE_SIZE` means different things to the two vendors.** ST writes
`IS_ALIGNED(a) ((a) % FLASH_PAGE_SIZE == 0)` and means the **erase** unit — on
an STM32L4 a "page" is what you erase. Microchip's `samd21j18a.h:546` already
defines `FLASH_PAGE_SIZE` as **64**, and on the SAM D21 a page is what you
**write**; what you erase is a 256-byte **row**. ST's macro therefore compiles
unchanged against Microchip's header, means something different, and is wrong
by a factor of four — it would accept slot boundaries that cannot be erased
without destroying their neighbours. Nothing warns: both symbols exist, both
are integers, the arithmetic is valid. `IS_ALIGNED` is redefined against the
erase unit explicitly, and `SFU_LL_FLASH_INT_Erase_Size` re-checks at run time
rather than trusting callers to have used the macro.

**The CRC is software, and that is the correct answer.** The SAM D21 has a
hardware CRC (DSU.CRC32), so the obvious port uses it. But the only caller of
`SFU_LL_CRC_Calculate` anywhere in the tree is the YMODEM packet check, which
needs **CRC-16/CCITT** — and the DSU unit does CRC-32 with a fixed polynomial
and cannot be made to do CRC-16. The real choice was between a correct
software CRC-16 and a wrong hardware CRC-32; the wrong one would have been
self-consistent on the target, disagreed with every host, and looked like a
serial problem.

## Building

The SBSFU tree is **not** vendored here — it is ~350 MB of ST's code. Fetch it
pinned:

```bash
./fetch_sbsfu.sh
```

That clones the mirror at commit `bd73ec65`, sparse-checks out only the
subtrees this port compiles, and asserts the package is X-CUBE-SBSFU v2.7.0
(31-March-2025; Secure Engine V2.5.3, mbedTLS V3.6.2 ST-modified). A mirror
that moves fails the assertion instead of quietly building something else.

`patches/` holds every edit to a file ST **shares** between boards. Per-board
files live under `SAMD21_XPRO/`, mirroring ST's own `Projects/<board>/` layout
so a reviewer can diff them against `B-L475E-IOT01A`'s directly.

The bring-up image needs no SBSFU checkout at all — the HAL and BSP are this
port's own code:

```bash
wsl -- bash -lc 'cd /mnt/d/.../rigs/fw_samd21_sbsfu/bringup && make'
```

`arm-none-eabi-gcc` is WSL-only on this host, the same as `fw_samd21_aes`,
`fw_xmc1_aes`, `fw_nrf_aes` and `fw_ra2_aes`.

## Mitigations are a build option, not a separate rig

`research/targets/samd21j18a.md` attacked all four NVMCTRL read-path settings
rather than assuming them, and two of them hold. Both are reachable from the
Makefile so the same bootloader can be attacked in the shipped configuration
and in either mitigated one:

| build | `NVMCTRL.CTRLB` | dossier result on the byte S-box |
|---|---|---|
| default | `READMODE=NO_MISS_PENALTY`, cache on, `RWS=1` | 15/16 key bytes at 400 000 traces |
| `MITIGATE=deterministic` | `READMODE=DETERMINISTIC` | 0/16, 1.60× runtime |
| `MITIGATE=cachedis` | `CACHEDIS=1` | 0/16, 1.21× runtime |

`READMODE=LOW_POWER` is deliberately not offered as a "mitigation": the
dossier measured it **worse** than the shipped setting — all sixteen key bytes
at 100 000 traces, and at zero wait states.

## What is not settled

* **`MBEDTLS_AES_ROM_TABLES` is no longer believed — it is read off the
  build.** `make` emits `build/tables.txt` from the symbol table, and it says
  `RT0` at `0x168c` and `RSb` at `0x1a8c`, both in flash, with no `RT1`/`RT2`/
  `RT3` because ST's config also sets `MBEDTLS_AES_FEWER_TABLES`. Had the
  tables been generated into SRAM there would be no flash-cache channel here
  at all, because the SAM D21's cache serves the NVM controller only. The
  caveat [`BOOTLOADER_SPI_ORACLE.md`](../../research/exposure/BOOTLOADER_SPI_ORACLE.md)
  §7 records for the L475 is therefore closed for this part and still open for
  that one.
* **The install does not finish.** The verify pass runs end to end and reaches
  the tag check; what follows it does not complete, and the board reports
  `Installation procedure cannot be finalized!`. The oracle does not depend on
  it — the pass being timed is over before that point — but a demo that
  claims to be a working bootloader has to get past it, and this one does not
  yet.
* **The measurement is taken through `DIRECT_INSTALL`.** `main()` calls
  `SFU_IMG_TriggerImageInstallation` itself rather than reaching it through
  SBSFU's state machine, which stops earlier for a separate reason. It is the
  same ST code over the same image in the same serial flash, so the bus
  traffic is the product's; the checks the state machine would have run
  around the install are not.
* **One pass per upload.** ST's installer erases the download slot when the
  install fails, so each pass consumes the staged image and the next needs a
  fresh YMODEM upload — which is most of the wall-clock cost of a campaign.
* **The bring-up self-test erases the first 64 KB of the serial flash.** It is
  not read-only and should not be run against a board mid-campaign.

## Queued experiment: does the dark set move with instruction alignment?

**This is the one thing waiting on this board.** Everything it needs
besides the hardware is already in the tree; it was left undone only
because it needs a re-capture.

### The question

The recovery saturates at 11 of 16 key bytes and leaves a 2^40 search.
The five it never gets, `[0, 5, 7, 8, 12]`, are not under-sampled: no
usable byte pair touches them, their best pair sits at the noise floor
while every covered byte's best is 68–80, and it is not a distance
effect. What the five share is that **four of them are the table loads
whose own instruction is the last halfword of an 8-byte line** — all
four such loads are dark and none of the other twelve is, except byte 0
(p = 0.003). The proposed mechanism is that this cache is unified, so
the instruction line fetched right after the load absorbs the load's
miss cost and its hit-or-miss stops changing the block time.

Full argument and its weaknesses:
[`../../results/bootloader_spi/samd21/dark_bytes.py`](../../results/bootloader_spi/samd21/dark_bytes.py)
and [`../../research/targets/samd21j18a.md`](../../research/targets/samd21j18a.md)
§8.

### Running it

Claim the board first (`bench/AGENTS.md`). Then:

```bash
python bench/bench.py claim samd21 --for "dark-byte alignment test" --minutes 180
```

**1. Baseline, to prove the toolchain still reproduces what is on
record.** The build is deterministic and must put `RSb` at
`0x00001a8c`, which is what the existing capture records — `build/`
holds one variant at a time and has held the `RAMTABLES=1` twin before
now, so check this rather than assuming it.

```bash
wsl -- bash -lc 'cd rigs/fw_samd21_sbsfu && make CHUNK=16 DIRECT_INSTALL=1 ORACLE=1'
```

**2. Shift the round by one halfword.** Any change that moves the final
round's loads without changing what it computes: a `nop` early in
`mbedtls_internal_aes_decrypt`, an `-falign-functions` bump, or a
different `-O` level. The goal is that **a different four loads land at
the end of an 8-byte line** — check before capturing, because if the
same four land there the experiment says nothing:

```bash
wsl -- bash -lc 'cd rigs/fw_samd21_sbsfu && arm-none-eabi-objdump -d --no-show-raw-insn build/sbsfu.elf > build/sbsfu.dis'
python results/bootloader_spi/l152_realistic/emitted_order.py \
    rigs/fw_samd21_sbsfu/build/sbsfu.dis --isa thumb1 \
    --word-locs sp12,sp16,r6,ip --base-reg r3 --mask-reg r2 \
    --start-addr <first load of the final round> --preset r4=mask --to-output
```

That prints a `load addresses:` line. The `--word-locs`, `--start-addr`
and `--preset` values are **this build's** and a rebuild can change
them; the script reports how many of the sixteen loads it resolved and
refuses to guess, so if it comes back short, re-read the round and
update them.

**3. Capture, with the table address recorded.** Same driver as the
original campaign.

```bash
python rigs/host/sbsfu_oracle.py --board samd21 --rig fw_samd21_sbsfu \
    --size 32768 --passes 40 --append \
    --out results/bootloader_spi/samd21/oracle_align.npz
```

**4. Score it, and ask whether the dark set followed the alignment.**

```bash
python results/bootloader_spi/samd21/attack_oracle.py \
    results/bootloader_spi/samd21/oracle_align.npz          # which bytes are dark now
python results/bootloader_spi/samd21/dark_bytes.py \
    --loads <the line from step 2> --dark <the bytes from step 4>
```

`dark_bytes.py` checks every address it is given is really an `ldrb` in
the disassembly and refuses otherwise, so a stale load table cannot
produce a tidy wrong answer.

### What each outcome means

| | |
|---|---|
| the dark set moves with the alignment | **which key bytes leak is something the compiler chooses.** This part's 2^40 is an accident of one binary, not a property of the silicon, and the same is true of every trace count quoted for a build |
| the dark set does not move | the hypothesis is dead; the five are something else, and the 2^40 is a property of the part |
| a different number of bytes goes dark | also informative — it ties the count to how many loads end a line |

Either way, **amend
[`../../research/FINDINGS_LEDGER.md`](../../research/FINDINGS_LEDGER.md)**,
whose row currently records this as a hypothesis with p = 0.003 and
says explicitly that it is untested.
