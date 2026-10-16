# X-CUBE-SBSFU on the B-L475E-IOT01A

A third board for the SPI/AES timing oracle that
[`research/exposure/BOOTLOADER_SPI_ORACLE.md`](../../research/exposure/BOOTLOADER_SPI_ORACLE.md)
screens for: ST's X-CUBE-SBSFU in its `2_Images_ExtFlash` configuration,
staging an AES-CBC-encrypted image in an off-chip serial flash that the
bootloader reads back chunk by chunk, decrypting between reads.

The difference from the two ports next door is that this is **the board ST
wrote that configuration for**. `Projects/B-L475E-IOT01A/Applications/2_Images_ExtFlash`
is the project the SAM D21 port was derived from and the one the L152 port
still compiles its application layer out of; here it runs on the part it
names. ST supplies this board's `Target/`, its `SECoreBin/`, its GCC linker
scripts and its startup file, so there is no port layer at all -- what this
directory holds is five headers with one hunk each, one new source file, and
five tracked patches.

## Status

| | |
|---|---|
| Vendor sources | `../fw_samd21_sbsfu/fetch_sbsfu.sh` for X-CUBE-SBSFU v2.7.0. **No second fetch**: the package ships this board's STM32L4 HAL, CMSIS device headers and BSP, so there is no CubeL4 pin to keep in step |
| Keys | `./gen_keys.sh`, ST's own prebuild step reduced to this scheme. **Two key pairs**, because the project is configured for two active images |
| Compiles | **72 translation units, first attempt**: 1 port, 21 HAL, 2 BSP, 19 SBSFU, 7 Secure Engine, 23 mbedTLS |
| Links | `build/sbsfu.elf`, 145 988 B text, 200 data, 26 672 bss at `CHUNK=512 RAMTABLES=0` |
| **AES tables in flash** | confirmed from the symbol table, not from the config: `RT0` at `0x0802a488`, `RSb` at `0x0802ac88`, **both at `mod 32 == 8`** -- which matters on this part, see below |
| **Boots on silicon** | **yes.** ST's banner, `System Security Check successfully passed`, `SECURE ENGINE INITIALIZATION SUCCESSFUL`, then the state machine and the YMODEM local loader |
| **Image staging** | **works.** A 64 KB image built with ST's own `prepareimage` goes in over SBSFU's YMODEM loader into the on-board MX25R6435F |
| **Install pass** | **runs to completion.** `VerifyFwSignatureBeforeDecrypt` reads every chunk back over QSPI, decrypts and hashes it, verifies the tag, and SBSFU executes the image |
| **Self-instrumented timing** | **working.** 127 intervals for a 128-chunk body, zero dropped, zero busy-poll retries, `DWT->CYCCNT` proved live in the same dump |
| **RAM twin** | **taken, and it separates.** Across-chunk spread **83.1 cycles** with the tables in flash against **22.5** with them in SRAM, on byte-identical bodies, against an instrument floor of **18.5** |
| Key recovered | **yes, both ends of the cipher.** `4f454d5f4b45595f434f4d50414e5931` from **round 1** at 3 833 intervals (122 656 AES blocks, 7.5 passes, ~6 min of bench) plus a 2^23 search, and again from **round 10** at 19 162 intervals with no search at all -- [`results/bootloader_spi/l475/README.md`](../../results/bootloader_spi/l475/README.md) §4 |
| Bus-side timing | not attempted. nCS is driven by the QUADSPI peripheral here, so the F303 probe the other two rigs use needs a different attachment and a reason to bother |

## Why self-instrumented, and why that is not a shortcut

On the L152 and the SAM D21 the serial flash hangs off an SPI peripheral with
chip-select on an ordinary GPIO, so the driver's own C opens and closes every
envelope and a NUCLEO-F303RE clipped to that line times the gaps from
outside. On this board the MX25R6435F is on **QUADSPI**, and nCS is driven by
the IP per command. The envelope is still one per read and still visible to
anyone with a probe, but the victim cannot produce the edge itself.

So this rig starts from the other side: the bootloader times its own gap, in
`DWT->CYCCNT`, between the return of `BSP_QSPI_Read` and the command that
opens the next chunk's status poll.
[`B_L475E_IOT01A/Instr/sfu_instr.h`](B_L475E_IOT01A/Instr/sfu_instr.h) has the
argument in full. The short version is that the software bracket misses a
fixed head and a fixed tail -- the HAL's wait-for-complete before the clock
starts, its command setup after the clock stops -- and a fixed offset is
invisible to an attack that scores differences between intervals. That makes
this an **upper bound on a bus-side attacker**, not a different attack: less
noise, the same signal, and the cheapest way to find out whether wiring a
probe to this board is worth the afternoon.

It is not a substitute for the bus-side capture. "An attacker outside the
package can do this" needs the outside measurement, and this rig cannot
make that claim.

## How close to stock this is

The brief, as on the other two boards, was to keep ST's shipped
configuration wherever a real integrator would.

| what changes | why it is what a user would do |
|---|---|
| `MBEDTLS_AES_ROM_TABLES` uncommented | the flash-saving option mbedTLS documents. **This is the port's largest deviation and it is the same one both other rigs make.** ST ships it commented out, so stock SBSFU computes its AES tables into `.bss` and has no flash-table channel on this path at all. `make RAMTABLES=1` restores ST's default, which makes one build serve as both the shipped configuration and the RAM twin |
| protections off through `SECBOOT_DISABLE_SECURITY_IPS` | ST's own development switch. In the shipped configuration this bootloader APPLIES its option bytes on first boot -- RDP level 1, write protection over the SB_SFU area, and DAP protect, which disconnects the debugger. All recoverable, none of it what you want on a board that is carrying another campaign's firmware |
| Secure Engine isolation off | **the structural limit of this rig**, not a preference. See below |
| `SFU_IMG_CHUNK_SIZE` | **unchanged at ST's 512.** Both other ports had to bring it down; this one does not, and that is a result rather than luck -- see below |
| `SB_ROM_region` grown to 192 KB, slot 2 moved up | forced by the single-image link. Slot 1, the pair the timed install actually uses, keeps ST's addresses |

Everything else is ST's: the crypto scheme stays at the shipped
`SECBOOT_ECCDSA_WITH_AES128_CBC_SHA256`, the loader stays at
`SECBOOT_USE_LOCAL_LOADER`, the clock stays at 80 MHz off the MSI PLL with
`FLASH_LATENCY_4`, and `sfu_fwimg_no_swap.c` -- the read / decrypt / hash
loop the whole campaign targets -- carries two instrumentation calls outside
its loop and nothing else. `./diff_vs_stock.sh` prints the complete list.

### One image, not two, and what it costs

ST builds this product as **two binaries**: SECoreBin, which holds the
Secure Engine and mbedTLS and is linked at absolute addresses behind the L4's
Firewall, and SBSFU, which links against a prebuilt blob of it. This rig
links one ELF, because the two-binary flow is work it has not done.

That decision is why `SFU_ISOLATE_SE_WITH_FIREWALL` is off, and the file that
turns it off
([`B_L475E_IOT01A/2_Images_SECoreBin/Inc/se_low_level.h`](B_L475E_IOT01A/2_Images_SECoreBin/Inc/se_low_level.h))
explains the chain: behind the firewall the SE cannot call out of its own
segment, so ST gives it a private `HAL_GetTick`, and in one address space
that is a duplicate symbol. The same applies to the fault handlers and to
ST's slot address tables, both of which exist twice in the project on
purpose.

What it costs the measurement, stated so nobody has to guess: with isolation
on, each chunk's two SE calls go through the call gate's firewall
open-and-close. That is a fixed instruction sequence with no dependence on
the chunk's contents, so it adds a constant to every interval -- the same
shape of term as the head and tail above. The AES runs out of the same flash
through the same accelerator either way. **Should not move the channel** is a
prediction, and it is in *what this does not settle* below rather than in the
status table.

### Why the chunk size can stay at ST's 512

The SAM D21 port had to take `SFU_IMG_CHUNK_SIZE` from 512 down to 64,
because at 512 bytes thirty-two AES block decryptions hide behind one
chip-select envelope and its 64-byte unified cache needs the chunk small for
a collision attack to see anything.

Simulated on **this part's measured geometry** -- a 256 B 8-way data cache
over a 32-byte conflict period on top of an 8-byte read latch, from
[`research/targets/stm32l475.md`](../../research/targets/stm32l475.md) -- the
chunk size does not matter here, and in two different ways:

| table the attack indexes | chunk 16 | chunk 512 |
|---|---|---|
| `RT0`, 1 KB, rounds 1-9 | round 1 24/24 | round 1 24/24 |
| `RSb`, 256 B, round 10 | 0/16 | 0/16 |

([`results/bootloader_spi/sim_spi_oracle_l475_ttable.json`](../../results/bootloader_spi/sim_spi_oracle_l475_ttable.json)
and `_sbox.json`.) Traces-to-key is set by AES blocks, and a bigger chunk
buys proportionally more blocks per read, so the pass count comes out the
same either way -- while a 512-byte chunk is four envelopes' worth of SPI
traffic instead of 128 and therefore far faster per block on the wire.

The second column of that table is the interesting one, and **it is wrong
about this build** -- measured, see
[`results/bootloader_spi/l475/README.md`](../../results/bootloader_spi/l475/README.md)
§4d. The argument it rests on is that a 256 B data cache holds the 256 B `RSb`
whole once rounds 1-9 have filled it, so round 10 has nothing key-dependent
left to miss on. Rounds 1-9 do not fill `RSb` here: with
`MBEDTLS_AES_FEWER_TABLES` they read `RT0`, 1 KB, 144 times a block, and
`RSb` is touched only by the final round. They evict it. The simulation's
`sbox` row models a cipher where every round reads the one 256 B table, which
is the byte-S-box build the AES matrix rig measures and not this one, and on
silicon round 10 here gives up the whole key at 19 162 intervals.

Round 1 is still the cheaper attack -- 3 833 intervals against 19 162, and it
needs no plaintext -- so the conclusion survives its argument. The dossier's
§5f alignment clause (`RSb` links at `0x0802ac88`, `mod 32 == 8`, nine
conflict groups rather than eight) was the reason this file gave for scoring
round 10 anyway, and scoring it was right for a different reason. `make`
prints the addresses and the phase into `build/tables.txt`, which is where
the trace counts above take them from.

## Bring-up, and the five things that had to be found on the way

Each of these is in a patch or a script comment where the next reader will
hit it. Listed here because together they are what a single-image build of
this product costs.

1. **The link succeeded with no cipher in it.** ST's SBSFU linker script
   places the Secure Engine as a prebuilt blob (`KEEP(*(SE_CORE_Bin))`), so
   compiling the SE from source leaves its sections with no output section,
   `--gc-sections` collects them, and the link reports 82 416 bytes of text
   and no undefined reference -- because SBSFU reaches the call gate through
   an address taken from a linker symbol, never through a symbol reference.
   `B_L475E_IOT01A/2_Images_SBSFU/l475_sbsfu.ld` adds the three placements
   ST's SECoreBin script has.
2. **The call gate has to start at `0x08000204`, not at `0x08000200`.** ST
   pads four `BYTE(0)` dummies in front of it with a comment saying so. An
   earlier version of that script used `ALIGN(4)` instead, which at offset
   zero does nothing: the board printed ST's banner, passed its security
   check, and took a Hard fault on the first SE call.
3. **The Secure Engine re-initialised the whole image's RAM.** `se_startup.c`
   calls `__gcc_data_init` on the first SE call, which zeroes `_sbss.._ebss`
   and re-copies `_sdata.._edata` -- the SECoreBin image's RAM in ST's build,
   the WHOLE bootloader's in one ELF. The symptom was `SystemCoreClock`
   reading 4 000 000 while `RCC_CFGR` said the core was on the 80 MHz PLL,
   and a UART programmed for the clock the part had left behind: one garbage
   byte at 115 200 baud and nothing else. `patches/0005`.
4. **ST's slot tables and fault handlers are defined twice on purpose.**
   `sfu_fwimg_regions.h` instantiates its `const` tables under
   `#if defined(SFU_FWIMG_COMMON_C) || defined(SE_LOW_LEVEL_C) || ...`, which
   is how each of ST's two binaries gets exactly one copy. `patches/0003`,
   and note that `-fcommon` does not help -- these are initialised
   definitions and `-fcommon` merges only tentative ones.
5. **`-nostartfiles` cannot be used here**, unlike on the L152: ST's startup
   for this board calls `__libc_init_array`, which needs `_init` from
   `crti.o`. ST's own CubeIDE project does not pass the flag either.

The L4 **does** have the Firewall peripheral, so none of this is the L152's
"the part lacks the hardware". It is the cost of one ELF.

## Build

```bash
../fw_samd21_sbsfu/fetch_sbsfu.sh          # once
./gen_keys.sh                              # once
wsl -- bash -lc 'cd <this dir> && make stockcheck && make check && make all'
```

| target | what it does |
|---|---|
| `check` | compiles every translation unit and links nothing |
| `all` | links `build/sbsfu.elf`, and writes `build/tables.txt` |
| `chunkcheck` | asserts `SFU_IMG_CHUNK_SIZE` **as ST's sources resolve it**, which is not the same as what the Makefile intended -- see [`chunkprobe.c`](chunkprobe.c) |
| `stockcheck` | checks the pinned tree is present **and complete**, because a sparse checkout that was interrupted leaves directories that exist and are empty |

| knob | default | note |
|---|---|---|
| `CHUNK` | 512 | ST's value, and the simulation says it costs nothing here |
| `RAMTABLES` | 0 | 1 is ST's shipped configuration and the RAM twin at once. Build it as `make RAMTABLES=1 BUILD=build_ram`: the twin's `tables.txt` would otherwise overwrite the flash build's, and a capture whose table addresses have been overwritten is a capture with no trace count |
| `SLOTS` | 3072 | intervals one pass can record. 944 is the whole download slot at chunk 512 |
| `ORACLE` | 0 | 1 turns ST's verbose trace off, so nothing prints inside the timed pass |
| `PROTECT` | bench | `stock` is refused, with the reason |
| `OPT` | -O2 | |

Flash it with `hardware/boards.py`, and drive a capture with
[`rigs/host/sbsfu_instr.py`](../host/sbsfu_instr.py):

```bash
python rigs/host/sbsfu_instr.py --board l475 --passes 8 --size 262144 \
    --tamper --out results/bootloader_spi/l475/pilot.npz
```

**NOTE:** the board this was brought up on arrived carrying
`flashsim-hil L475`, the AES matrix rig from
[`rigs/fw_l4_aes/`](../fw_l4_aes/). The pre-flash image is kept at
`results/l475/l475_image_before_sbsfu_20261015.bin`; reflash from that rig
when the matrix campaign wants the board back.

## What this does not settle

* **Whether `RSb`'s PHASE matters is not measured.** §4d of the results file
  shows the simulated round-10 null does not describe this cipher at all, for
  a reason that is not alignment, so the §5f question -- whether the same
  table at `mod 32 == 0` would behave differently -- needed a second link of
  this image and did not get one.
* **One optimisation level.** `OPT=-O3` has not been built or captured, and
  the dossier's §5f measured `-O3` costing that part's attacker at least 3x
  on a different cipher, so it is not safe to assume either direction.
* **Nothing has been measured with the protections on.** The firewall's
  open-and-close per SE call is argued to be a constant; it is not measured
  to be one, and a stock-protection build needs the two-binary flow.
* **The bus side is untouched.** Whether a probe on this board's QSPI lines
  sees what the victim's own clock sees, and at what cost in traces, is the
  measurement this rig was built to make cheap rather than the one it makes.
* **The largest workable `--size` is not known.** 64 KB and 256 KB both run
  (the recovery used 256 KB, 511 intervals a pass); 482 816 B and 482 304 B
  both transfer and then do not install, and the loader's own length check
  passes both, so what refuses them is downstream of it and unidentified.
  The 944-intervals-a-pass figure this file used to quote does not run.
