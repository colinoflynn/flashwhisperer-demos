"""Where will the AES tables *be* at run time - flash, or RAM?

`fwscan` answers "does this image contain AES lookup tables, and of what
shape?".  That is a property of the **library**.  Every break in this repo,
though, rests on a property of the **build**: the tables are read out of flash,
through a wide slow array with wait states and a row latch.  The same library,
the same source, the same ciphertext - one linker line apart - is either a
full key in 20 000 timings or a flat line
(`hardware/ST_CRYPTOLIB.md` §4).  No functional test can see the difference.

This module asks the placement question, from three kinds of artefact, with
three very different degrees of certainty:

  1. **Linked ELF (+ map)** - exact.  Section headers carry the run-time
     address (`sh_addr`) even for `.data`, whose *contents* live in flash but
     whose *address* is RAM.  Find the table bytes inside an allocatable
     section, add `sh_addr`, classify the address against a part memory map.

  2. **Raw `.bin`** - inference, and the interesting case.  A table destined
     for RAM is *still in the flash image*, as a `.data` initialiser that the
     reset handler copies.  "The table bytes are in the image" therefore does
     not separate safe from broken.  Four signals do, in the order they are
     trusted:

       * the **startup copy loop**: `(src, dst, len)` sits in the reset
         handler's literal pool, so a table offset inside `[src, src+len)`
         maps to a *run-time* address `dst + (off - src)`;
       * the **literal pool**: Cortex-M code loads a table base from a
         PC-relative literal, and that literal holds the *run-time* address.
         A confirmed `LDR Rt,[PC,#n]` whose literal is `0x080xxxxx` means the
         table is read from flash;
       * **group relocation**: with no copy loop at all, the literal pool still
         holds N addresses whose relative spacing matches the tables' spacing in
         the image, so one shared delta recovers the run-time base;
       * an **anchor**: GCC merges adjacent `.rodata` and reaches a table with a
         constant displacement from one base, so a literal within
         `LDRB.W Rt,[Rn,#imm12]` range counts too.

     Each alone has a failure mode; §"the aliasing trap" below is the one that
     cost a false positive here.  When none of the four fires, the verdict is
     UNDETERMINED - never EXPOSED by default.

  3. **Object / archive (`.o`, `.a`)** - before linking, the address does not
     exist yet.  The only correct verdict is conditional: *safe iff the
     integrator adds a linker rule*.  A tool can say which rule, and can check
     a supplied linker script for it - which is exactly the check that would
     have caught ST shipping 2 277 linker scripts, none of which maps
     `CMOX_CTA_PROTECTED_DATA`.

### The aliasing trap

The reset handler's `_sidata` (the load address of `.data`) is a flash address
literal, and it points at the *first byte of the .data initialiser* - which is
frequently the first table, when the tables are the thing that was moved to
RAM.  A naive "is there a literal equal to base+offset?" therefore fires on the
copy loop itself and calls the fixed build broken.  Measured on
`rigs/fw_g4_st` built with `link_cta.ld`: `_sidata = 0x080019e0` and
`AES_sbox`'s initialiser is at file offset `0x19e0`.  `_sdata` is the mirror
image: it aliases that same first table's *run-time* address, so a literal
matching it is not evidence the cipher reads RAM either.  Both are excluded.

    python -m flashleak placement fw.elf
    python -m flashleak placement fw.bin --part stm32f4
    python -m flashleak placement libSTM32Cryptographic_CM4.a --ld link.ld
"""
from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

from . import fwscan

# --------------------------------------------------------------------------
# Part memory maps.
#
# "Is the address 0x08xxxxxx?" is the wrong rule, and it is wrong on exactly
# the parts that matter.  Three levels, because two are not enough:
#
#   EXPOSED     read through the flash interface - wait states, a 64/128-bit
#               row latch, and whatever ART/prefetch sits on top.  This is the
#               channel this project measures; it is present even with every
#               cache bit cleared (research/targets/stm32g474_art_geometry.md).
#   SAFE        SRAM or a tightly-coupled memory with no wait states and no
#               cache in front of it.  RAM has no row latch; this is the fix.
#   CACHED_RAM  RAM that is cacheable by a Cortex-M7 L1 D-cache (H7 AXI-SRAM at
#               0x24000000, F7 SRAM1 at 0x20010000).  Moving a table here does
#               remove the flash wait-state channel, but it does NOT make the
#               table access time data-independent: that is the classical
#               cache-timing surface.  Calling it "safe" would be a lie, and
#               this project has not measured it, so it gets its own level.
# --------------------------------------------------------------------------

EXPOSED = "EXPOSED"
SAFE = "SAFE"
CACHED_RAM = "CACHED_RAM"
UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Region:
    name: str
    start: int
    size: int
    exposure: str
    note: str = ""

    @property
    def end(self) -> int:
        return self.start + self.size

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end


@dataclass(frozen=True)
class Part:
    name: str
    regions: tuple[Region, ...]
    note: str = ""
    # What actually closes the channel ON THIS PART, where the bench has
    # measured it.  This exists because "EXPOSED" alone sends integrators to
    # the wrong knob: on most parts here disabling the accelerator reduces the
    # channel without closing it, and on the CC1352 it makes it STRONGER.
    # Printed with an EXPOSED verdict.  Empty means "not measured on this part"
    # and nothing is printed - silence rather than a plausible guess.
    mitigation: str = ""

    def classify(self, addr: int) -> Region | None:
        for r in self.regions:
            if r.contains(addr):
                return r
        return None


_M = 1 << 20
_K = 1 << 10

# STM32F4 (F429ZI on this bench): ART with a 128-byte data cache, 1 MB..2 MB
# flash at 0x08000000, SRAM1+2 at 0x20000000, CCM at 0x10000000 (core-coupled,
# not reachable by DMA, but perfectly good for tables).
_F4 = Part("stm32f4", (
    Region("flash (AXI/ART)", 0x0800_0000, 2 * _M, EXPOSED,
           "wait states + 128-bit line + 128 B ART data cache"),
    Region("flash (boot alias)", 0x0000_0000, 2 * _M, EXPOSED,
           "same array through the boot remap"),
    Region("CCM SRAM", 0x1000_0000, 64 * _K, SAFE, "core-coupled, 0 wait states"),
    Region("SRAM1/2", 0x2000_0000, 192 * _K, SAFE, "0 wait states, no cache"),
    Region("SRAM3 (backup)", 0x4002_4000, 4 * _K, SAFE),
    Region("FSMC/FMC external", 0x6000_0000, 0x2000_0000, UNKNOWN,
           "external memory: timing depends on the controller, not modelled here"),
), note="measured here: S-box and T-table both leak with the data cache ON")

# STM32F2 is the same shape with a 1 MB flash.
_F2 = Part("stm32f2", (
    Region("flash (ART)", 0x0800_0000, 1 * _M, EXPOSED, "128 B ART data cache"),
    Region("flash (boot alias)", 0x0000_0000, 1 * _M, EXPOSED),
    Region("SRAM1/2", 0x2000_0000, 128 * _K, SAFE),
), note="no CCM")

# STM32G4 (G474RE): ART with a 256-byte data cache - exactly the size of the
# S-box, which is why the S-box goes resident and a 1 KB T-table cannot.  CCM
# lives at 0x10000000 and is also mirrored into 0x20000000 on this family.
_G4 = Part("stm32g4", (
    Region("flash (ART)", 0x0800_0000, 512 * _K, EXPOSED,
           "64-bit read + 1-entry row latch; leaks with the whole ART disabled"),
    Region("flash (boot alias)", 0x0000_0000, 512 * _K, EXPOSED),
    Region("CCM SRAM", 0x1000_0000, 32 * _K, SAFE, "core-coupled"),
    Region("SRAM1/2 (+CCM alias)", 0x2000_0000, 128 * _K, SAFE),
), note="ST's own cryptolib broke here with prefetch, I-cache and D-cache all off")

# STM32F3 (F303): no data cache at all, and hardware/FLASH_READ_LATCH work
# found no read latch either - but it still has wait states, so a table in
# flash is still EXPOSED as a matter of policy.  The F3 data path measured
# bit-exactly constant time; the instruction path did not.
_F3 = Part("stm32f3", (
    Region("flash (prefetch only)", 0x0800_0000, 512 * _K, EXPOSED,
           "wait states + prefetch buffer; no data cache, no read latch measured"),
    Region("flash (boot alias)", 0x0000_0000, 512 * _K, EXPOSED),
    Region("CCM SRAM", 0x1000_0000, 16 * _K, SAFE),
    Region("SRAM", 0x2000_0000, 80 * _K, SAFE),
), note="data path measured inert on F303; the instruction path is not")

_F1 = Part("stm32f1", (
    Region("flash", 0x0800_0000, 1 * _M, EXPOSED, "wait states + prefetch buffer"),
    Region("flash (boot alias)", 0x0000_0000, 1 * _M, EXPOSED),
    Region("SRAM", 0x2000_0000, 96 * _K, SAFE),
))

_L5 = Part("stm32l5", (
    Region("flash (secure alias)", 0x0C00_0000, 512 * _K, EXPOSED,
           "8 KB unified instruction+data cache"),
    Region("flash (non-secure)", 0x0800_0000, 512 * _K, EXPOSED),
    Region("SRAM1", 0x2000_0000, 192 * _K, SAFE),
    Region("SRAM2", 0x2003_0000, 64 * _K, SAFE),
), note="full key recovered here with the 8 KB cache DISABLED")

_L4 = Part("stm32l4", (
    Region("flash (ART)", 0x0800_0000, 1 * _M, EXPOSED, "256 B ART data cache"),
    Region("flash (boot alias)", 0x0000_0000, 1 * _M, EXPOSED),
    Region("SRAM1", 0x2000_0000, 96 * _K, SAFE),
    Region("SRAM2 (CCM-capable)", 0x1000_0000, 32 * _K, SAFE),
))

# STM32F7: this is where "0x20000000 means RAM means safe" breaks down in the
# *other* direction.  0x20000000 is DTCM - tightly coupled, never cached, the
# genuinely safe place.  0x20010000 onwards is SRAM1/2, which IS cacheable by
# the Cortex-M7 L1 D-cache.  Flash appears twice: at 0x08000000 through the AXI
# (cacheable, ART) and at 0x00200000 through the ITCM bus.
# STM32F7.  The DTCM/SRAM1 boundary MOVES WITHIN THE FAMILY, and it moves
# across exactly the addresses a table lands at: on an F746 the DTCM is 64 KB,
# so 0x20010000 is cacheable SRAM1; on an F769 the DTCM is 128 KB, so the same
# address is DTCM.  `rigs/fw_f7/link.ld` puts RAM at 0x20010000 precisely
# because that is *not* DTCM on the board here.  There is no family-wide answer,
# which is why `stm32f7` means F746 and `stm32f76x` is separate.
_F7 = Part("stm32f7", (
    Region("flash (ITCM alias)", 0x0020_0000, 1 * _M, EXPOSED, "ART accelerator"),
    Region("flash (AXIM)", 0x0800_0000, 2 * _M, EXPOSED, "L1 cacheable, wait states"),
    Region("ITCM RAM", 0x0000_0000, 16 * _K, SAFE),
    Region("DTCM (F746: 64 KB)", 0x2000_0000, 64 * _K, SAFE,
           "tightly coupled, bypasses the L1 D-cache entirely"),
    Region("SRAM1", 0x2001_0000, 240 * _K, CACHED_RAM,
           "cacheable by the M7 L1 D-cache - not the flash channel, but not flat either"),
    Region("SRAM2", 0x2004_C000, 16 * _K, CACHED_RAM),
), note="F746 map; on an F76x the DTCM is 128 KB and 0x20010000 is DTCM instead")

_F76X = Part("stm32f76x", (
    Region("flash (ITCM alias)", 0x0020_0000, 2 * _M, EXPOSED, "ART accelerator"),
    Region("flash (AXIM)", 0x0800_0000, 2 * _M, EXPOSED, "L1 cacheable, wait states"),
    Region("ITCM RAM", 0x0000_0000, 16 * _K, SAFE),
    Region("DTCM (F76x: 128 KB)", 0x2000_0000, 128 * _K, SAFE),
    Region("SRAM1", 0x2002_0000, 368 * _K, CACHED_RAM),
    Region("SRAM2", 0x2007_C000, 16 * _K, CACHED_RAM),
), note="same addresses as stm32f7, opposite verdict at 0x20010000")

# STM32H7 (H723 on this bench).  DTCM at 0x20000000, AXI-SRAM at 0x24000000 --
# a tool that checks "not 0x08xxxxxx" calls both of these safe, and one of them
# is behind the L1 D-cache.
_H7 = Part("stm32h7", (
    Region("ITCM RAM", 0x0000_0000, 64 * _K, SAFE),
    Region("flash (AXIM)", 0x0800_0000, 2 * _M, EXPOSED,
           "wait states + 256-bit read; L1 cacheable"),
    Region("DTCM", 0x2000_0000, 128 * _K, SAFE,
           "tightly coupled, not cached - the safe destination on this part"),
    Region("AXI SRAM (D1)", 0x2400_0000, 512 * _K, CACHED_RAM,
           "cacheable by the M7 L1 D-cache"),
    Region("SRAM1/2 (D2)", 0x3000_0000, 288 * _K, CACHED_RAM),
    Region("SRAM4 (D3)", 0x3800_0000, 64 * _K, CACHED_RAM),
    Region("backup SRAM", 0x3880_0000, 4 * _K, CACHED_RAM),
    Region("QSPI/OCTOSPI XIP", 0x9000_0000, 256 * _M, EXPOSED,
           "execute-in-place from external flash: slower still"),
), note="0x20000000 is DTCM here, not general SRAM; 0x24000000 is cached")

# Nordic nRF52 / nRF53.  Not an STM32, and the reason it is here is that the
# flash base is **0x00000000**, so "is it 0x08xxxxxx?" says SAFE about a table
# sitting in flash.  The nRF52840's NVMC cache is an *instruction* cache (2-way,
# 2 x 512 B); data reads go to the array with wait states, which is the F3-shaped
# case: no data cache, still a channel.  Not measured on this bench - the
# classification is from the memory map, and the exposure from the mechanism.
_NRF52 = Part("nrf52", (
    Region("flash (NVMC)", 0x0000_0000, 1 * _M, EXPOSED,
           "wait states; the NVMC cache is instruction-side only"),
    Region("RAM", 0x2000_0000, 256 * _K, SAFE),
), note="flash at 0x00000000: an address-prefix rule fails on this part",
   mitigation="No register reaches the read latch on this part - there is no "
              "FLASH_ACR equivalent and no wait-state field anywhere. Every "
              "ICACHECNF setting leaks identically. Tables in RAM is the only "
              "measured fix.")

_NRF53 = Part("nrf53", (
    Region("flash (application core)", 0x0000_0000, 1 * _M, EXPOSED),
    Region("RAM", 0x2000_0000, 512 * _K, SAFE),
), note="same shape as nrf52")

# STM32L152RE: 512 KB flash at 0x08000000, 80 KB SRAM.  Measured on this bench
# (research/targets/stm32l152.md): a 1-entry 8-byte row latch, i.e. the same structure
# as the G4 at the same granularity as its 64-bit flash.
_L1 = Part("stm32l1", (
    Region("flash", 0x0800_0000, 512 * _K, EXPOSED,
           "64-bit read + 1-entry 8-byte row latch (measured)"),
    Region("EEPROM (data)", 0x0808_0000, 16 * _K, EXPOSED,
           "same flash interface; not a table home anyone chooses, but it is read "
           "through the same wait states"),
    Region("SRAM", 0x2000_0000, 80 * _K, SAFE),
), note="measured: research/targets/stm32l152.md")

# Renesas RA2A1 (R7FA2A1AB3CFM), Cortex-M23.  Measured on this bench
# (research/targets/ra2a1.md).  Two things are unlike every ST part:
# code flash is at 0x00000000, so an 0x08xxxxxx prefix rule misses it entirely;
# and it is the first part here where the accelerator's own enable really does
# remove the data-side reuse (FCACHEEN = 0 -> no latch behind it at all).
# The flash is still EXPOSED, because the shipped/firmware default enables the
# cache and no static tool can see a register write.
_RA2A1 = Part("ra2a1", (
    Region("code flash", 0x0000_0000, 256 * _K, EXPOSED,
           "FCACHE (1 entry x 16 B) + MEMWAIT/FLWT wait states; leaks as shipped, "
           "but FCACHEEN = 0 closes it completely (measured)"),
    Region("data flash", 0x4010_0000, 8 * _K, EXPOSED,
           "same flash interface"),
    Region("SRAM", 0x2000_0000, 32 * _K, SAFE),
), note="flash at 0x00000000: an address-prefix rule fails on this part. "
        "measured: research/targets/ra2a1.md",
   mitigation="FCACHEE.FCACHEEN=0 closes it completely - no latch survives "
              "behind the register, unlike every ST part here. MEMWAIT=0 "
              "(requires ICLK<=32 MHz) also works. But on this Cortex-M23 the "
              "cipher must ALSO avoid a branching xtime(), which no flash "
              "setting fixes.")

# TI CC1352R1F3 (CC13x2 / CC26x2), Cortex-M4.  Measured on this bench
# (research/targets/cc1352.md).  The reason this part gets a long note is that
# it is the one part here where "disable the accelerator" is ACTIVELY WRONG:
# VIMS_CTL.MODE = OFF leaves a 16-byte read latch and makes the S-box channel
# STRONGER (sigma 1.539 -> 4.289, full key in 5 000 traces instead of 10 000).
# What closes it is a different bit, VIMS_CTL.IDCODE_LB_DIS, and only while MODE
# is off as well.  None of that is visible to a static tool, so flash is EXPOSED
# regardless of what the firmware does with VIMS.
_CC13X2 = Part("cc13x2", (
    Region("flash", 0x0000_0000, 352 * _K, EXPOSED,
           "VIMS 8 KB data-capable cache + a 1-entry 16 B Icode/Dcode line "
           "buffer; MODE=OFF does NOT close it, IDCODE_LB_DIS=1 does (measured)"),
    Region("ROM (boot + driverlib)", 0x1000_0000, 32 * _K, UNKNOWN,
           "TI's ROM, including a driverlib copy; read through VIMS, but no "
           "table of ours lands here and it was not measured"),
    Region("GPRAM", 0x1100_0000, 8 * _K, UNKNOWN,
           "the SAME 8 KB array as the VIMS cache, mapped as RAM only while "
           "VIMS_CTL.MODE = GPRAM. A table here is plausibly latch-free, but "
           "(a) it exists only in one VIMS mode, which a static tool cannot "
           "see, and (b) reads to 0x11000000 were NOT measured on this bench. "
           "UNKNOWN rather than SAFE, deliberately"),
    Region("SRAM", 0x2000_0000, 80 * _K, SAFE),
), note="flash at 0x00000000: an address-prefix rule fails on this part. "
        "measured: research/targets/cc1352.md",
   mitigation="DO NOT just clear VIMS_CTL.MODE: MODE=OFF leaves the 16 B line "
              "buffer and makes the S-box channel STRONGER (sigma 1.539 -> 4.289, "
              "full key in 5 000 traces instead of 10 000). What closes it is "
              "MODE=OFF *plus* VIMS_CTL.IDCODE_LB_DIS=1 - both, and the second "
              "is inert on its own. Alternatives: PRCM_CPUCLKDIV=/2 (bit-exact "
              "in CACHE mode only), or tables in SRAM.")

# A deliberately conservative fallback for an unknown part.  It knows only the
# two things that are true of every Cortex-M STM32-alike, and says UNKNOWN for
# everything else rather than guessing.
_GENERIC = Part("generic", (
    Region("internal flash", 0x0800_0000, 16 * _M, EXPOSED,
           "assumed: STM32-style flash base"),
    Region("code region (boot alias / XIP)", 0x0000_0000, 0x1000_0000, EXPOSED,
           "the Cortex-M Code region: flash or an XIP alias on every part seen here"),
    Region("SRAM region", 0x2000_0000, 0x2000_0000, UNKNOWN,
           "the Cortex-M SRAM region - but DTCM, CCM and CACHED AXI-SRAM all "
           "live here on different parts; pass --part to decide"),
    Region("external QSPI XIP", 0x9000_0000, 256 * _M, EXPOSED),
), note="no part given: the SRAM region cannot be classified without one")

PARTS: dict[str, Part] = {p.name: p for p in
                          (_F1, _F2, _F3, _F4, _F7, _F76X, _G4, _H7, _L1, _L4,
                           _L5, _NRF52, _NRF53, _RA2A1, _CC13X2, _GENERIC)}

# Aliases an integrator would actually type.
_ALIASES = {
    "f429": "stm32f4", "stm32f429": "stm32f4", "f4": "stm32f4",
    "f2": "stm32f2", "f1": "stm32f1", "f3": "stm32f3", "f303": "stm32f3",
    "f7": "stm32f7", "f746": "stm32f7", "f745": "stm32f7",
    "f767": "stm32f76x", "f769": "stm32f76x", "f777": "stm32f76x", "f76x": "stm32f76x",
    "g4": "stm32g4", "g474": "stm32g4",
    "h7": "stm32h7", "h723": "stm32h7", "h743": "stm32h7",
    "l1": "stm32l1", "l152": "stm32l1", "l152re": "stm32l1",
    "l4": "stm32l4", "l5": "stm32l5", "l552": "stm32l5",
    "nrf52840": "nrf52", "nrf52832": "nrf52", "nrf5340": "nrf53",
    "ra2": "ra2a1", "r7fa2a1": "ra2a1", "r7fa2a1ab": "ra2a1",
    "cc1352": "cc13x2", "cc1352r1": "cc13x2", "cc1352r1f3": "cc13x2",
    "cc2652": "cc13x2", "cc26x2": "cc13x2", "cc1312": "cc13x2",
    "": "generic", "none": "generic",
}


def resolve_part(name: str | None) -> Part:
    if not name:
        return _GENERIC
    key = name.strip().lower()
    key = _ALIASES.get(key, key)
    if key not in PARTS:
        raise KeyError(f"unknown part {name!r}; known: {', '.join(sorted(PARTS))}")
    return PARTS[key]


# --------------------------------------------------------------------------
# Table fingerprints.  Reuse fwscan's, so there is exactly one source of truth
# for what an AES table looks like, and group the many rotations/endiannesses
# down to one entry per distinct byte range.
# --------------------------------------------------------------------------

@dataclass
class TableHit:
    name: str
    offset: int               # offset within the buffer scanned
    length: int               # nominal table size in bytes


_TABLE_SIZE = {
    "AES S-box": 256, "AES inverse S-box": 256, "Rcon": 10,
    "gfm2_sb (Gladman)": 256, "gfm3_sb (Gladman)": 256,
}


def _table_size(name: str) -> int:
    if name in _TABLE_SIZE:
        return _TABLE_SIZE[name]
    if name.startswith(("Te", "Td")):
        return 1024
    return 256


def find_tables(data: bytes, want_rcon: bool = False) -> list[TableHit]:
    """Every AES table instance in `data`, one hit per (name, offset)."""
    hits: list[TableHit] = []
    for name, pat in fwscan.patterns():
        if name == "Rcon" and not want_rcon:
            continue
        for m in re.finditer(re.escape(pat), data):
            hits.append(TableHit(name, m.start(), _table_size(name)))
    hits.sort(key=lambda h: (h.offset, h.name))
    return hits


# --------------------------------------------------------------------------
# Minimal ELF32 reader.  No external dependency: pyelftools is not a
# requirement of this repo and this needs ~80 lines.
# --------------------------------------------------------------------------

SHF_ALLOC, SHF_WRITE, SHF_EXECINSTR = 0x2, 0x1, 0x4
SHT_NOBITS, SHT_SYMTAB, SHT_PROGBITS = 8, 2, 1
ET_REL, ET_EXEC, ET_DYN = 1, 2, 3


@dataclass
class ElfSection:
    name: str
    sh_type: int
    flags: int
    addr: int
    offset: int
    size: int
    entsize: int
    link: int

    @property
    def alloc(self) -> bool:
        return bool(self.flags & SHF_ALLOC)

    @property
    def has_bytes(self) -> bool:
        return self.sh_type != SHT_NOBITS and self.size > 0


@dataclass
class ElfSym:
    name: str
    value: int
    size: int
    shndx: int
    info: int


@dataclass
class Elf:
    etype: int
    machine: int
    little: bool
    sections: list[ElfSection]
    symbols: list[ElfSym]
    segments: list[tuple[int, int, int, int]]   # (vaddr, paddr, filesz, offset)
    data: bytes

    def section(self, idx: int) -> ElfSection | None:
        return self.sections[idx] if 0 <= idx < len(self.sections) else None

    def body(self, s: ElfSection) -> bytes:
        return b"" if not s.has_bytes else self.data[s.offset:s.offset + s.size]


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def parse_elf(data: bytes) -> Elf:
    if not is_elf(data):
        raise ValueError("not an ELF file")
    if data[4] != 1:
        raise ValueError("only ELF32 is supported (Cortex-M artefacts)")
    little = data[5] == 1
    e = "<" if little else ">"
    etype, machine = struct.unpack_from(e + "HH", data, 16)
    phoff, shoff = struct.unpack_from(e + "II", data, 28)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from(e + "HHHHH", data, 42)

    raw = []
    for i in range(shnum):
        o = shoff + i * shentsize
        (nameoff, sh_type, flags, addr, off, size, link, _info,
         _align, entsize) = struct.unpack_from(e + "10I", data, o)
        raw.append((nameoff, sh_type, flags, addr, off, size, link, entsize))

    strtab_off, strtab_size = raw[shstrndx][4], raw[shstrndx][5] if shnum else (0, 0)

    def cstr(base: int, off: int) -> str:
        end = data.find(b"\0", base + off)
        return data[base + off:end].decode("latin-1")

    sections = [ElfSection(cstr(strtab_off, n), t, f, a, o, sz, es, lk)
                for (n, t, f, a, o, sz, lk, es) in raw]

    symbols: list[ElfSym] = []
    for s in sections:
        if s.sh_type != SHT_SYMTAB or not s.entsize:
            continue
        strs = sections[s.link]
        for i in range(s.size // s.entsize):
            o = s.offset + i * s.entsize
            nameoff, value, size, info, _other, shndx = struct.unpack_from(e + "IIIBBH", data, o)
            symbols.append(ElfSym(cstr(strs.offset, nameoff), value, size, shndx, info))

    segments = []
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_off, p_vaddr, p_paddr, p_filesz = struct.unpack_from(e + "5I", data, o)
        if p_type == 1:                                    # PT_LOAD
            segments.append((p_vaddr, p_paddr, p_filesz, p_off))

    return Elf(etype, machine, little, sections, symbols, segments, data)


# --------------------------------------------------------------------------
# Thumb-2 address-literal recovery, for the raw-.bin case.
# --------------------------------------------------------------------------

def image_words(data: bytes) -> list[int]:
    n = len(data) // 4
    return list(struct.unpack("<%dI" % n, data[:n * 4]))


def ldr_literal_sites(data: bytes, base: int) -> dict[int, list[int]]:
    """Map *loaded value* -> the image offsets of the `LDR Rt,[PC,#n]` that load it.

    Two encodings matter on Cortex-M:
      T1  0100 1ttt iiiiiiii          LDR Rt,[PC,#imm8*4]      (Rt = r0..r7)
      T2  1111 1000 1101 1111 tttt iiiiiiiiiiii   LDR.W Rt,[PC,#imm12]

    The literal address is `align4(pc) + imm`, with `pc = addr_of_insn + 4`.
    This is a *decode*, not a disassembly: data bytes that happen to look like
    an LDR produce spurious sites.  That is tolerable because the value is then
    required to equal a table address, which data will not do by accident.
    """
    out: dict[int, list[int]] = {}
    n = len(data)
    for off in range(0, n - 1, 2):
        hw = data[off] | (data[off + 1] << 8)
        imm = None
        if (hw & 0xF800) == 0x4800:                                   # T1
            imm = (hw & 0xFF) * 4
        elif (hw & 0xFF7F) == 0xF85F and off + 4 <= n:                # T2 (U bit in 0x0080)
            hw2 = data[off + 2] | (data[off + 3] << 8)
            imm = hw2 & 0xFFF
            if not (hw & 0x0080):
                imm = -imm
        if imm is None:
            continue
        pc = (off + 4) & ~3
        lit = pc + imm
        if 0 <= lit <= n - 4:
            val = int.from_bytes(data[lit:lit + 4], "little")
            out.setdefault(val, []).append(off)
    return out


def movw_movt_values(data: bytes, window: int = 24) -> dict[int, list[int]]:
    """Map value -> offsets, for 32-bit addresses built with MOVW/MOVT.

    Some builds (notably `-mslow-flash-data`, and Clang at higher optimisation)
    materialise a table base as a MOVW/MOVT pair with no literal pool entry at
    all.  Without this the raw-.bin literal test would return a false negative
    on such a build.
    """
    def _imm16(hw1: int, hw2: int) -> tuple[int, int]:
        i = (hw1 >> 10) & 1
        imm4 = hw1 & 0xF
        imm3 = (hw2 >> 12) & 7
        imm8 = hw2 & 0xFF
        rd = (hw2 >> 8) & 0xF
        return rd, (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8

    out: dict[int, list[int]] = {}
    n = len(data)
    lows: dict[int, tuple[int, int]] = {}          # rd -> (offset, value)
    for off in range(0, n - 3, 2):
        hw1 = data[off] | (data[off + 1] << 8)
        hw2 = data[off + 2] | (data[off + 3] << 8)
        if (hw1 & 0xFBF0) == 0xF240 and not (hw2 & 0x8000):           # MOVW
            rd, v = _imm16(hw1, hw2)
            lows[rd] = (off, v)
        elif (hw1 & 0xFBF0) == 0xF2C0 and not (hw2 & 0x8000):         # MOVT
            rd, v = _imm16(hw1, hw2)
            prev = lows.get(rd)
            if prev and 0 < off - prev[0] <= window:
                out.setdefault((v << 16) | prev[1], []).append(prev[0])
    return out


# --------------------------------------------------------------------------
# The startup copy loop: (src in flash, dst in RAM, len)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class CopyRegion:
    src: int            # load address (flash)
    dst: int            # run-time address (RAM)
    length: int
    evidence: str

    def map(self, addr: int) -> int | None:
        """Flash load address -> run-time address, if it falls in this region."""
        if self.src <= addr < self.src + self.length:
            return self.dst + (addr - self.src)
        return None


def find_copy_regions(data: bytes, base: int, part: Part,
                      window: int = 12) -> list[CopyRegion]:
    """Recover `.data`-style load/run pairs from the reset handler's literals.

    A GCC/Clang/IAR startup carries the three values in one literal pool:
    `_sidata` (flash), `_sdata` and `_edata` (RAM).  Their *order* differs by
    toolchain, so all orderings within a small window are tried and filtered on
    physical plausibility:

      * `src` is inside the image and in an EXPOSED (flash) region;
      * `dst` and `end` are both in a RAM-ish region with `end > dst`;
      * the initialiser `[src, src+len)` fits inside the image;
      * `len` is a multiple of 4 and smaller than the RAM region.

    That filter alone is not enough, and the failure is instructive.  The
    *bss-clear* loop has the same shape - `(_sbss, _ebss)` are two RAM words in
    the same literal pool - so any nearby flash word completes a plausible
    triple, and on `rigs/fw_f7` one such phantom region swallowed the S-box
    and turned a flash table into a "SAFE" verdict: a **false negative**, the
    worst kind of error this tool can make.

    So the candidates are not merely ranked, they are *chained*.  In every
    GCC/Clang/IAR layout seen here the image is
    `vectors | text+rodata | init_1 | init_2 | ... | init_k <EOF>`: the load
    regions tile the tail of the image contiguously and the last one ends at
    the end of the image.  Accepting only a chain with that property discards
    the bss phantom, which is anchored nowhere.
    """
    n = len(data)
    # Candidate constants, positioned so "in the same literal pool" still means
    # something.  A start-up compiled with `-mslow-flash-data` has NO literal
    # pool at all: `_sdata`/`_edata`/`_sidata` become MOVW/MOVT pairs, and a
    # word scan finds nothing.  Merging both sources is what keeps the copy loop
    # visible on such a build.
    words = image_words(data)
    pos_val = [(i, v) for i, v in enumerate(words)]
    for v, offs in movw_movt_values(data).items():
        for o in offs:
            pos_val.append((o // 4, v))
    pos_val.sort()
    words = [v for _p, v in pos_val]
    ram = [r for r in part.regions if r.exposure in (SAFE, CACHED_RAM, UNKNOWN)
           and r.start >= 0x1000_0000]
    flash = [r for r in part.regions if r.exposure == EXPOSED]

    def in_ram(a: int) -> bool:
        return any(r.contains(a) for r in ram) or 0x2000_0000 <= a < 0x4000_0000
    def in_flash(a: int) -> bool:
        return any(r.contains(a) for r in flash) or base <= a < base + 0x1000_0000

    cands: dict[tuple[int, int, int], str] = {}
    for i in range(len(words)):
        lo, hi = max(0, i - window), min(len(words), i + window + 1)
        pool = [(j, words[j]) for j in range(lo, hi)]
        for _, src in pool:
            if not in_flash(src) or not (base <= src < base + n):
                continue
            for _, dst in pool:
                if not in_ram(dst):
                    continue
                for _, end in pool:
                    if not in_ram(end) or end <= dst:
                        continue
                    L = end - dst
                    if L % 4 or L > 4 * _M or src % 4 or dst % 4:
                        continue
                    if src - base + L > n:
                        continue
                    tail = n - (src - base + L)
                    key = (src, dst, L)
                    if key not in cands or tail == 0:
                        cands[key] = ("initialiser ends at end of image" if tail == 0
                                      else f"initialiser ends {tail} bytes before end of image")

    regions = [CopyRegion(s, d, L, ev) for (s, d, L), ev in cands.items()]
    if not regions:
        return []
    loaded = set(ldr_literal_sites(data, base)) | set(movw_movt_values(data))

    def rank(r: CopyRegion) -> tuple:
        # the source literal being *loaded* by a PC-relative LDR is real
        # evidence: the reset handler does `ldr r3,[pc,#n]`, whereas a phantom
        # triple is three unrelated words that merely have the right shape.
        return (r.src in loaded, r.length)

    by_end: dict[int, list[CopyRegion]] = {}
    for r in regions:
        by_end.setdefault(r.src + r.length, []).append(r)

    # Walk backwards from the end of the image, taking the best-ranked region
    # that ends where the previous one begins.  Stop when nothing fits.
    chain: list[CopyRegion] = []
    cursor = base + n
    seen: set[int] = set()
    while cursor in by_end and cursor not in seen:
        seen.add(cursor)
        best = max(by_end[cursor], key=rank)
        chain.append(best)
        cursor = best.src
    if chain:
        return chain

    # No region ends at the end of the image: the image is padded, truncated or
    # exotic.  Fall back to the old ranking, and say so via `evidence`.
    regions.sort(key=rank, reverse=True)
    kept: list[CopyRegion] = []
    for r in regions:
        if any(r.dst < k.dst + k.length and k.dst < r.dst + r.length for k in kept):
            continue
        kept.append(r)
    return kept[:4]


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def find_zero_regions(data: bytes, part: Part, window: int = 12) -> list[tuple[int, int]]:
    """Recover `(_sbss, _ebss)` pairs - the zero-fill loop - from literals.

    Worth having for one reason: a build whose tables are in flash *and* which
    owns a table-sized zeroed RAM buffer may be copying the tables there at
    run time and reading them through a pointer.  `rigs/fw_f4_ctguard` and
    `rigs/fw_f7_rsm DTCM=1` both do exactly that, and both measure flat on
    silicon while every static signal says "tables in flash".  The tool cannot
    decide it, but it can stop being quietly confident about it.
    """
    # Only the reset handler, and only literals that are really loaded.  Without
    # both constraints this fires on ordinary table data: a first attempt here
    # "found" a 4 MB zero region at 0x70180e08 in every image, which is table
    # bytes read as a word.  A detector that fires on everything says nothing.
    head = data[:4096]
    loaded = set(ldr_literal_sites(head, 0))
    words = image_words(head)
    ram = [r for r in part.regions if r.exposure in (SAFE, CACHED_RAM)]

    def in_ram(a: int) -> bool:
        return any(r.contains(a) for r in ram)

    out: set[tuple[int, int]] = set()
    for i, a in enumerate(words):
        if not in_ram(a) or a % 4 or a not in loaded:
            continue
        for j in range(max(0, i - window), min(len(words), i + window + 1)):
            b = words[j]
            if b % 4 or not in_ram(b) or b not in loaded or not (a < b < a + 4 * _M):
                continue
            out.add((a, b - a))
    # keep only maximal, non-overlapping extents
    best: list[tuple[int, int]] = []
    for start, size in sorted(out, key=lambda t: -t[1]):
        if any(s <= start and start + size <= s + n for s, n in best):
            continue
        best.append((start, size))
    return best[:4]


@dataclass
class Placement:
    table: str
    file_offset: int | None
    runtime_addr: int | None
    region: str
    exposure: str
    section: str = ""
    symbol: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class Report:
    path: str
    kind: str                       # elf | bin | object | archive | linker-script
    part: str
    verdict: str                    # EXPOSED | SAFE | CONDITIONAL | UNDETERMINED | NO-TABLES
    placements: list[Placement] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    confidence: str = ""


def _roll_up(placements: list[Placement]) -> str:
    if not placements:
        return "NO-TABLES"
    ex = {p.exposure for p in placements}
    if EXPOSED in ex:
        return "EXPOSED"
    if UNKNOWN in ex:
        return "UNDETERMINED"
    if CACHED_RAM in ex:
        return "CACHED_RAM"
    return "SAFE"


# --------------------------------------------------------------------------
# Case 1: a linked ELF.  Exact.
# --------------------------------------------------------------------------

def analyse_elf(data: bytes, part: Part, path: str = "<elf>") -> Report:
    elf = parse_elf(data)
    if elf.etype == ET_REL:
        return analyse_object(data, part, path)

    rep = Report(path, "elf", part.name, "NO-TABLES")
    rep.confidence = ("exact - the run-time address is in the section header; "
                      "the only judgement left is which region is safe on this part")

    # Symbol lookup by address, for naming.
    by_addr: dict[int, str] = {}
    for s in elf.symbols:
        if s.name and s.size:
            by_addr[s.value] = s.name

    for sec in elf.sections:
        if not sec.alloc or not sec.has_bytes:
            continue
        body = elf.body(sec)
        for hit in find_tables(body):
            addr = sec.addr + hit.offset
            reg = part.classify(addr)
            rep.placements.append(Placement(
                table=hit.name,
                file_offset=sec.offset + hit.offset,
                runtime_addr=addr,
                region=reg.name if reg else "unmapped",
                exposure=reg.exposure if reg else UNKNOWN,
                section=sec.name,
                symbol=by_addr.get(addr, ""),
                evidence=[f"section {sec.name} sh_addr={sec.addr:#010x} "
                          f"+ {hit.offset:#x}"],
            ))
        # A NOBITS (.bss) section can still *become* a table at run time; see
        # the note emitted below.

    # LMA != VMA: say so, because it is the whole subtlety of the .bin case.
    for sec in elf.sections:
        if not sec.alloc or not sec.has_bytes or not (sec.flags & SHF_WRITE):
            continue
        lma = _lma_of(elf, sec)
        if lma is not None and lma != sec.addr and any(
                p.section == sec.name for p in rep.placements):
            rep.notes.append(
                f"{sec.name}: LMA {lma:#010x} (flash) -> VMA {sec.addr:#010x} (run time). "
                "The table bytes ARE in the flash image; they are copied at reset. "
                "This is exactly why a raw-.bin scan cannot use 'the bytes are present'.")

    nobits = [s for s in elf.sections
              if s.alloc and s.sh_type == SHT_NOBITS and s.size >= 256]
    if nobits and any(p.exposure == EXPOSED for p in rep.placements):
        big = ", ".join(f"{s.name} ({s.size} B @ {s.addr:#010x})" for s in nobits[:4])
        rep.notes.append(
            "flash-resident tables coexist with zero-initialised RAM buffers "
            f"({big}). If the build copies the tables into one of those at start-up "
            "and reads them through a pointer, the run-time placement is a RUNTIME "
            "decision this analysis cannot settle. rigs/fw_f4_ctguard is "
            "precisely that shape.")

    rep.verdict = _roll_up(rep.placements)
    return rep


def _lma_of(elf: Elf, sec: ElfSection) -> int | None:
    for vaddr, paddr, filesz, _off in elf.segments:
        if vaddr <= sec.addr and sec.addr + sec.size <= vaddr + max(filesz, sec.size):
            return paddr + (sec.addr - vaddr)
    return None


# --------------------------------------------------------------------------
# Case 2: a raw .bin.  The interesting one.
# --------------------------------------------------------------------------

def analyse_bin(data: bytes, part: Part, base: int | None = None,
                path: str = "<bin>") -> Report:
    rep = Report(path, "bin", part.name, "NO-TABLES")

    vec = fwscan.find_vector_table(data)
    base_guessed = False
    if base is None:
        if vec:
            base = vec[0]
            rep.notes.append(f"flash base {base:#010x} taken from the Cortex-M "
                             "vector table at offset 0")
        else:
            base = 0x0800_0000
            base_guessed = True
            rep.notes.append("no Cortex-M vector table at offset 0: assuming flash "
                             f"base {base:#010x}. If this image is a partial dump, an "
                             "XIP image from external QSPI, or position-independent, "
                             "every address below is wrong - pass --base.")

    hits = find_tables(data)
    if not hits:
        rep.confidence = "no AES tables found; nothing to place"
        return rep

    copies = find_copy_regions(data, base, part)
    for c in copies:
        if c.length < 256:
            continue        # cannot hold an AES table; the bss-clear loop looks
                            # like this and is only noise in the report
        rep.notes.append(f"start-up copy: {c.src:#010x} -> {c.dst:#010x}, "
                         f"{c.length} bytes ({c.evidence})")
    if not copies:
        rep.notes.append("no start-up copy loop recovered. Either the build has no "
                         "initialised .data at all, or the literal-pool heuristic "
                         "missed it; a table in the image therefore cannot be shown "
                         "to be a RAM initialiser.")

    lits = ldr_literal_sites(data, base)
    movs = movw_movt_values(data)
    raw_words = set(image_words(data))
    # `_sidata` aliases the first table in .data when the tables are what moved;
    # `_sdata` aliases its run-time address for exactly the same reason. Both
    # are literals the copy loop needs and neither says anything about where the
    # *cipher* reads. Excluded symmetrically.
    copy_srcs = {c.src for c in copies}
    copy_dsts = {c.dst for c in copies}

    # Group relocation: the strongest signal when there is no copy loop at all.
    # If the build moved the tables somewhere, the linker resolved every table
    # symbol to the new base, so the literal pool holds N addresses whose
    # *relative spacing matches the tables' spacing in the image*.  One shared
    # delta therefore explains all of them at once, and it is recoverable
    # without knowing anything about the start-up code.
    #
    # This is what catches a section given `> CCM AT > FLASH` with no copy loop
    # - a real and easy mistake, and the one in ST's own published snippet.
    loaded = (set(lits) | set(movs)) - copy_srcs - copy_dsts

    # Veto: if ANY table in the group is demonstrably read where it is stored --
    # a PC-relative literal holding its own flash address - then the group did
    # not move, and any delta that seems to fit the others is a coincidence.
    #
    # `rigs/fw_f4` is the case that forced this.  `aes.c` keeps
    # `te0_ram[256] .. te3_ram[256]` in .bss at exactly the same 1 KB spacing as
    # `Te0..Te3` in flash, so those four .bss addresses look like a perfect
    # four-table relocation - while `SBOX`'s own flash address sits in a
    # literal two instructions away.  Without the veto the tool reported the
    # four T-tables at their .bss shadow addresses.
    stored_in_place = any((base + h.offset) in loaded for h in hits)

    delta_support: dict[int, int] = {}
    if not stored_in_place:
        for hit in hits:
            for v in loaded:
                d = v - (base + hit.offset)
                if d % 4:                     # a group move preserves alignment
                    continue
                delta_support[d] = delta_support.get(d, 0) + 1
    best_delta = None
    if delta_support:
        # Ties happen, and they are not random: when the tables are laid out
        # end to end, `d` and `d + table_size` fit equally well - one maps each
        # table onto its own address, the other onto its neighbour's.  Break the
        # tie on the tightest packing (the lowest highest-mapped address), which
        # is the un-shifted reading; then prefer "nothing moved" (d = 0).
        def _key(kv):
            d_, sup_ = kv
            top = max(base + h.offset + d_ for h in hits)
            return (sup_, -top, d_ == 0)

        d, sup = max(delta_support.items(), key=_key)
        if sup >= 2 and part.classify(base + hits[0].offset + d) is not None:
            best_delta = d
            if d:
                rep.notes.append(
                    f"literal pool is consistent with the whole table group being "
                    f"relocated by {d:+#x}: {sup} of {len(hits)} table addresses "
                    f"appear as loaded literals at that offset. Run-time base "
                    f"{base + hits[0].offset + d:#010x}.")
                # Same arithmetic, different reading: if `base + d` is itself a
                # plausible flash base, the more likely story is not that the
                # tables moved but that the *supplied base is wrong*.  Worth
                # saying out loud, because a wrong base silently invalidates
                # every address in the report.
                alt = base + d
                alt_reg = part.classify(alt)
                if (alt % 0x100 == 0 and alt_reg is not None
                        and alt_reg.exposure == EXPOSED and alt != base):
                    rep.notes.append(
                        f"...but {alt:#010x} is itself a plausible flash base on "
                        f"this part. If the image is mapped there rather than at "
                        f"{base:#010x}, nothing moved and every address above is "
                        f"off by {d:+#x}. Re-run with --base {alt:#x}.")

    for hit in hits:
        load_addr = base + hit.offset
        run_addr, via = load_addr, "in-place (not inside any copied region)"
        for c in copies:
            mapped = c.map(load_addr)
            if mapped is not None:
                run_addr, via = mapped, (f"inside the .data initialiser "
                                         f"{c.src:#010x}+{c.length:#x} -> {c.dst:#010x}")
                break

        ev = [f"table bytes at file offset {hit.offset:#x} (load address {load_addr:#010x})",
              via]

        # Literal-pool evidence, both directions.  Exclude literals that are a
        # recognised copy-loop source: `_sidata` aliases the first table in
        # .data and would otherwise fire on the FIXED build.
        def _refs(addr: int) -> tuple[int, int, bool]:
            n_ldr = len(lits.get(addr, ()))
            n_mov = len(movs.get(addr, ()))
            return n_ldr, n_mov, addr in raw_words

        fl_ldr, fl_mov, fl_word = _refs(load_addr)
        rn_ldr, rn_mov, rn_word = _refs(run_addr) if run_addr != load_addr else (0, 0, False)
        aliased = load_addr in copy_srcs
        aliased_dst = run_addr in copy_dsts

        if aliased_dst and (rn_ldr or rn_mov):
            ev.append(f"{rn_ldr + rn_mov} literal reference(s) to {run_addr:#010x} "
                      "IGNORED: that address is a recognised copy-loop destination "
                      "(_sdata), which aliases the first table in .data")
            rn_ldr = rn_mov = 0
        if aliased and fl_ldr:
            ev.append(f"{fl_ldr} literal load(s) of {load_addr:#010x} IGNORED: that "
                      "address is a recognised copy-loop source (_sidata), which "
                      "aliases the first table in .data")
            fl_ldr = 0
        if fl_ldr or fl_mov:
            ev.append(f"code loads the FLASH address {load_addr:#010x}: "
                      f"{fl_ldr} PC-relative literal load(s), {fl_mov} MOVW/MOVT pair(s)")
        if rn_ldr or rn_mov:
            ev.append(f"code loads the RAM address {run_addr:#010x}: "
                      f"{rn_ldr} PC-relative literal load(s), {rn_mov} MOVW/MOVT pair(s)")
        if not (fl_ldr or fl_mov or rn_ldr or rn_mov):
            ev.append("no PC-relative literal or MOVW/MOVT holds either candidate "
                      "address: the table may be reached by a computed offset from "
                      "another object, or the code may be compressed")
            if fl_word or rn_word:
                ev.append(f"(a bare 32-bit word matching "
                          f"{'the flash' if fl_word else 'the RAM'} address does occur, "
                          "but no instruction decode confirms it is loaded)")

        # A literal need not hold the table's own address.  GCC merges adjacent
        # `.rodata` and addresses the lot from one anchor, reaching the table
        # with a constant displacement: `LDRB.W Rt,[Rn,#imm12]` covers 0..4095.
        # Without this, TinyCrypt-shaped code - `ldr r4,<.rodata>` then
        # `ldrb r3,[r4,#44]` - produces no literal match at all, and three
        # builds whose keys fell on silicon came back UNDETERMINED.
        anchors = [v for v in loaded
                   if 0 < load_addr - v <= 4095 and
                   part.classify(v) is not None and
                   part.classify(v).exposure == (part.classify(load_addr).exposure
                                                 if part.classify(load_addr) else None)]
        anchor = max(anchors) if anchors else None

        reloc = (base + hit.offset + best_delta) if best_delta else None
        reloc_hit = bool(reloc is not None and reloc != run_addr and reloc in loaded)
        if reloc is not None and reloc != run_addr:
            ev.append(f"group relocation puts it at {reloc:#010x}" +
                      (" (confirmed by a literal)" if reloc_hit else
                       " (by group consistency; no literal for this table)"))

        # Precedence, strongest evidence first.
        confident = True
        if (rn_ldr or rn_mov) and run_addr != load_addr:
            addr, why = run_addr, ("the copy loop maps it to RAM AND code loads that "
                                   "RAM address - two independent signals agreeing")
        elif fl_ldr or fl_mov:
            addr, why = load_addr, "code loads the flash address"
        elif run_addr != load_addr:
            addr, why = run_addr, "copy-loop mapping, unconfirmed by any literal"
        elif reloc is not None:
            addr, why = reloc, ("literal pool says the table group was relocated; "
                                "no start-up copy loop covers it, so this build may "
                                "also be missing its initialiser")
            confident = reloc_hit
        elif anchor is not None:
            addr, why = load_addr, (
                f"no literal holds {load_addr:#010x} itself, but one holds "
                f"{anchor:#010x} and the table is {load_addr - anchor} bytes past it "
                "-- within Thumb-2 `LDRB.W Rt,[Rn,#imm12]` range, so it is reached "
                "from that anchor")
            ev.append("this is the GCC pattern of merging adjacent .rodata and "
                      "addressing everything from one base: TinyCrypt's "
                      "`tc_aes128_set_encrypt_key` reads its S-box as [r4,#44]")
        else:
            addr, why = load_addr, "no copy loop and no literal: assumed in place"
            confident = False
        ev.append(f"decision: {why}")

        reg = part.classify(addr)
        exposure = reg.exposure if reg else UNKNOWN
        if not confident and exposure == EXPOSED:
            exposure = UNKNOWN
            ev.append("downgraded to UNDETERMINED: nothing in the image confirms that "
                      "this table is read where it is stored, so 'stays in flash' "
                      "would be an assumption, not a finding")

        # An address computed from a guessed base is a guess.  Only a signal
        # that would have *failed* under a wrong base counts as corroboration:
        # a literal that matches, or a copy region that tiles the tail of the
        # image exactly.  Everything else is arithmetic on an assumption.
        if base_guessed and confident:
            corroborated = bool(fl_ldr or fl_mov or rn_ldr or rn_mov or reloc_hit)
            if not corroborated and exposure != UNKNOWN:
                exposure = UNKNOWN
                ev.append("downgraded to UNDETERMINED: the flash base was assumed "
                          "(no vector table) and nothing in the image confirms it. "
                          "Re-run with --base once you know where this image is "
                          "mapped.")

        rep.placements.append(Placement(
            table=hit.name, file_offset=hit.offset, runtime_addr=addr,
            region=reg.name if reg else "unmapped", exposure=exposure, evidence=ev))

    rep.verdict = _roll_up(rep.placements)
    rep.confidence = ("inferred - the run-time address is reconstructed from the "
                      "start-up copy loop and the literal pool, not read off a "
                      "section header")

    if rep.verdict == EXPOSED:
        zeros = [(s, n_) for s, n_ in find_zero_regions(data, part) if n_ >= 256]
        biggest = max((n_ for _s, n_ in zeros), default=0)
        need = sum(h.length for h in hits)
        if biggest >= need:
            where = ", ".join(f"{s:#010x}+{n_}" for s, n_ in zeros[:3])
            rep.notes.append(
                f"zero-filled RAM of at least {biggest} bytes ({where}) - enough to "
                f"hold the {need} bytes of tables found. If this build copies them "
                "there at start-up and reads them through a pointer, the run-time "
                "placement is a RUNTIME decision and the EXPOSED verdict above is "
                "about the stored copy, not necessarily the one that is read. "
                "rigs/fw_f4_ctguard and rigs/fw_f7_rsm DTCM=1 are both this "
                "shape and both measure flat on silicon.")
    return rep


# --------------------------------------------------------------------------
# Case 3: an object file or a static archive, before linking.
# --------------------------------------------------------------------------

# Sections whose name says "the integrator must place me", keyed to the rule.
KNOWN_OPT_IN_SECTIONS = {
    "CMOX_CTA_PROTECTED_DATA":
        "ST X-CUBE-CRYPTOLIB: CTA = Cache Timing Attack. ST's wiki tells the "
        "integrator to map this section into non-cacheable RAM; none of the 2 277 "
        "linker scripts in the package does.",
}


@dataclass
class LinkerRule:
    section: str
    found: bool
    output_section: str = ""
    region: str = ""
    lines: list[str] = field(default_factory=list)
    dialect: str = ""


def analyse_object(data: bytes, part: Part, path: str = "<obj>") -> Report:
    """A relocatable .o: section names and flags are visible, addresses are not."""
    elf = parse_elf(data)
    rep = Report(path, "object", part.name, "NO-TABLES")
    rep.confidence = ("conditional - a relocatable object has no addresses. "
                      "The verdict is a function of the linker script.")
    for sec in elf.sections:
        if not sec.alloc or not sec.has_bytes:
            continue
        body = elf.body(sec)
        for hit in find_tables(body):
            writable = bool(sec.flags & SHF_WRITE)
            rep.placements.append(Placement(
                table=hit.name, file_offset=sec.offset + hit.offset,
                runtime_addr=None, region=f"section {sec.name}",
                exposure=UNKNOWN, section=sec.name,
                evidence=[
                    f"in section {sec.name} at +{hit.offset:#x}, "
                    f"flags={'W' if writable else 'R'}{'X' if sec.flags & SHF_EXECINSTR else ''}",
                    ("read-only data: a stock script sends it to the flash "
                     "read-only region next to .text"
                     if not writable else
                     "writable data: a stock script sends it to .data, i.e. RAM at "
                     "run time with a flash initialiser"),
                ]))
    rep.verdict = "CONDITIONAL" if rep.placements else "NO-TABLES"
    secs = sorted({p.section for p in rep.placements})
    for s in secs:
        if s in KNOWN_OPT_IN_SECTIONS:
            rep.notes.append(f"{s}: {KNOWN_OPT_IN_SECTIONS[s]}")
        elif s not in (".rodata", ".data", ".text") and not s.startswith((".rodata.", ".data.", ".text.")):
            rep.notes.append(
                f"{s}: a non-standard section name holding AES tables. That is the "
                "signature of a library that EXPECTS to be placed - check the "
                "vendor's documentation, and then check your linker script.")
    if secs:
        rep.notes.append("required rule (GNU ld): put " +
                         " and ".join(f"*({s})" for s in secs) +
                         " inside an output section whose VMA is RAM and whose LMA "
                         "is flash (`> RAM AT > FLASH`), so the start-up copy "
                         "actually initialises it.")
    return rep


def iter_archive(data: bytes):
    """Yield (member name, bytes) from a Unix `ar` archive (.a)."""
    if data[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive")
    pos, longnames = 8, b""
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            break
        name = hdr[0:16].decode("latin-1").rstrip()
        try:
            size = int(hdr[48:58].decode("latin-1").strip())
        except ValueError:
            break
        body = data[pos + 60:pos + 60 + size]
        pos += 60 + size + (size & 1)
        if name.startswith("//"):
            longnames = body
            continue
        if name.startswith("/") and name[1:].isdigit():
            off = int(name[1:])
            end = longnames.find(b"/\n", off)
            if end < 0:
                end = longnames.find(b"\n", off)
            name = longnames[off:end].decode("latin-1").rstrip("/")
        name = name.rstrip("/")
        if name in ("/", "/SYM64/", "__.SYMDEF"):
            continue
        yield name, body


def analyse_archive(data: bytes, part: Part, path: str = "<archive>") -> Report:
    rep = Report(path, "archive", part.name, "NO-TABLES")
    rep.confidence = ("conditional - an archive has no addresses; the verdict is a "
                      "function of the linker script that consumes it")
    members = 0
    for name, body in iter_archive(data):
        if not is_elf(body):
            continue
        members += 1
        try:
            sub = analyse_object(body, part, name)
        except Exception:
            continue
        for p in sub.placements:
            p.symbol = name
            rep.placements.append(p)
        for n in sub.notes:
            if n not in rep.notes:
                rep.notes.append(n)
    rep.notes.insert(0, f"{members} ELF member(s) scanned")
    rep.verdict = "CONDITIONAL" if rep.placements else "NO-TABLES"
    return rep


# --------------------------------------------------------------------------
# The linker-script check.  Easy, exact, and it would have caught ST.
# --------------------------------------------------------------------------

def check_linker_script(text: str, section: str, dialect: str | None = None) -> LinkerRule:
    """Does this linker script place `section` anywhere?

    Three dialects, because the three toolchains an STM32 integrator uses are
    the three ST publishes examples for:

      GNU ld (.ld)   `*(CMOX_CTA_PROTECTED_DATA)` inside an output section,
                     which is then assigned to a region with `> RAM`.
      IAR (.icf)     `place in RAM_region { section CMOX_CTA_PROTECTED_DATA };`
      Arm/Keil (.sct) `*(CMOX_CTA_PROTECTED_DATA)` inside an execution region.

    Returns whether it was mentioned and, for GNU ld, which output section and
    memory region it lands in - because mentioning it is not enough: ST's own
    published snippet places it at a fixed RAM address with **no load region and
    no copy**, which leaves the tables uninitialised (see
    rigs/fw_g4_st/link_cta.ld).
    """
    raw_lines = [ln.strip() for ln in text.splitlines() if section in ln]
    code = strip_comments(text)
    if dialect is None:
        dialect = "icf" if re.search(r"^\s*place\s+in\b", code, re.M) else \
                  "sct" if re.search(r"^\s*LR_\w+|^\s*ER_\w+", code, re.M) else "ld"
    rule = LinkerRule(section=section, found=False, dialect=dialect)
    # Only occurrences OUTSIDE comments count: ST's own published snippet lives
    # in a comment in more than one script, and a commented-out rule places
    # nothing.  Report the raw lines for the human, but decide on the code.
    rule.lines = [ln.strip() for ln in code.splitlines() if section in ln]
    rule.found = bool(rule.lines)
    if not rule.found:
        if raw_lines:
            rule.lines = raw_lines
            rule.output_section = "(mentioned only inside a comment)"
        return rule

    if dialect == "icf":
        m = re.search(r"place\s+in\s+(\w+)[^{]*\{[^}]*" + re.escape(section), code, re.S)
        if m:
            rule.region = m.group(1)
        return rule

    # GNU ld / Arm scatter: find the enclosing output section by brace matching,
    # then the `> REGION [AT > REGION]` that follows its closing brace.
    # Prefer an input-section reference `*(NAME)` / `*NAME` over a bare mention:
    # a name can also appear as an *output* section header, which is a different
    # statement with a different meaning.
    m0 = re.search(r"\*\s*\(\s*[^)]*" + re.escape(section), code)
    idx = m0.start() if m0 else code.find(section)
    header, close = _enclosing_block(code, idx)
    if header:
        rule.output_section = header
    if close is not None:
        m3 = re.match(r"\s*>\s*([\w.]+)(?:\s*AT\s*>\s*([\w.]+))?", code[close + 1:])
        if m3:
            rule.region = m3.group(1) + (f" AT > {m3.group(2)}" if m3.group(2) else "")
    return rule


def strip_comments(text: str) -> str:
    """Blank out /* ... */ and // comments, preserving offsets and line count."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _enclosing_block(code: str, idx: int) -> tuple[str, int | None]:
    """(header of the innermost `{...}` containing idx, offset of its `}`)."""
    depth, open_at = 0, []
    for i, ch in enumerate(code[:idx]):
        if ch == "{":
            open_at.append(i)
        elif ch == "}" and open_at:
            open_at.pop()
    if not open_at:
        return "", None
    start = open_at[-1]
    # header = the statement immediately before the brace
    head = code[:start]
    head = head[max(0, len(head) - 200):]
    m = re.search(r"([.\w]+)\s*(?:\(\s*[\w ]*\s*\))?\s*:[^{}]*$", head)
    name = m.group(1) if m else head.strip().split()[-1] if head.strip() else ""
    depth = 1
    for i in range(start + 1, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return name, i
    return name, None


def audit_linker_scripts(paths, section: str) -> list[LinkerRule]:
    out = []
    for p in paths:
        try:
            txt = open(p, "r", errors="replace").read()
        except OSError:
            continue
        r = check_linker_script(txt, section)
        r.section = section
        out.append((p, r))
    return out


# --------------------------------------------------------------------------
# Dispatch + rendering
# --------------------------------------------------------------------------

def analyse(path: str, part: str | None = None, base: int | None = None) -> Report:
    p = resolve_part(part)
    data = open(path, "rb").read()
    if data[:8] == b"!<arch>\n":
        return analyse_archive(data, p, path)
    if is_elf(data):
        elf_hdr_type = struct.unpack_from("<H", data, 16)[0]
        if elf_hdr_type == ET_REL:
            return analyse_object(data, p, path)
        return analyse_elf(data, p, path)
    # Intel HEX: MCU firmware ships this way at least as often as it ships as a
    # .bin, and the record stream carries the real flash base, which is exactly
    # what the raw-.bin path most often lacks (§ the vendor-firmware case).
    if data[:1] == b":" or path.lower().endswith((".hex", ".ihx", ".ihex")):
        conv = fwscan.ihex_to_bin(data.decode("latin-1", "replace"))
        if conv:
            img, lo = conv
            rep = analyse_bin(img, p, base if base is not None else lo, path)
            rep.kind = "ihex"
            rep.notes.insert(0, f"Intel HEX flattened: {len(img)} bytes, "
                                f"base {lo:#010x} from the record stream")
            return rep
    if path.lower().endswith((".ld", ".icf", ".sct", ".scat")):
        rep = Report(path, "linker-script", p.name, "UNDETERMINED")
        rep.notes.append("a linker script on its own says nothing about tables; "
                         "use --ld with an object/archive, or name a section with "
                         "--section")
        return rep
    return analyse_bin(data, p, base, path)


def row_offset_from_image(path, part="stm32f4", granule=None):
    """Exact ROW OFFSET of the S-box in a firmware image: (offset, addr, note).

    Moved here from `hardware/line_offset.py` when the scoring geometry moved
    into `flashattack.geometry`: the arithmetic belongs beside the scorer, and
    reading an image belongs here, because `flashattack` must not import
    `flashleak` (the layering has no back edges).

    `analyse()` locates the table by its byte pattern and resolves its run-time
    address, so this needs no symbols and works on a raw `.bin`.

    Returns `(None, addr, note)` when the table is NOT flash-resident: a build
    that copies it to RAM has no flash row structure, so the collision channel
    is absent rather than merely offset, and a caller that treated a `None` as
    "assume 0" would be scoring a channel that does not exist.
    """
    from flashattack import geometry as _geo
    granule = _geo.GRANULE if granule is None else int(granule)
    rep = analyse(path, part=part)
    for p in rep.placements:
        if "S-box" not in p.table:
            continue
        addr = p.runtime_addr
        if addr is None:
            continue
        note = "%s %s @ 0x%08x (%s, %s)" % (
            p.table, p.symbol or "", addr, p.section or "?", p.exposure)
        if p.exposure != EXPOSED:
            return None, addr, note + "  - not flash-resident, no row channel"
        return _geo.row_offset(addr, granule), addr, note
    return None, None, "no S-box table found in %s" % path


_MARK = {EXPOSED: "!!", SAFE: "ok", CACHED_RAM: " ~", UNKNOWN: " ?"}


def render(rep: Report, verbose: bool = True) -> str:
    out = [f"{rep.path}: {rep.kind}, part={rep.part}"]
    if rep.confidence:
        out.append(f"  confidence: {rep.confidence}")
    for n in rep.notes:
        out.append(f"  note: {n}")
    for p in rep.placements:
        addr = f"{p.runtime_addr:#010x}" if p.runtime_addr is not None else "   (unlinked)"
        sym = f" {p.symbol}" if p.symbol else ""
        out.append(f"  [{_MARK.get(p.exposure, ' ?')}] {p.table:<20s} -> {addr}  "
                   f"{p.region}{sym}")
        if verbose:
            for e in p.evidence:
                out.append(f"        - {e}")
    out.append(f"  => VERDICT: {rep.verdict}  {_VERDICT_TEXT.get(rep.verdict, '')}")
    # An EXPOSED verdict is where an integrator decides what to change, and on
    # several parts here the obvious change is the wrong one.  Print what the
    # bench actually measured for this part, when it has.
    if rep.verdict == "EXPOSED":
        part = PARTS.get(rep.part or "")
        if part is not None and part.mitigation:
            out.append(f"  what closes it on {part.name}: {part.mitigation}")
    return "\n".join(out)


_VERDICT_TEXT = {
    "EXPOSED": "-- at least one AES table is read from flash at run time. This is "
               "the configuration whose key this project recovered on silicon.",
    "SAFE": "-- every table found resolves to a non-cacheable RAM address.",
    "CACHED_RAM": "-- tables are in RAM, but RAM that sits behind a data cache on "
                  "this part. The flash wait-state channel is gone; a classical "
                  "cache-timing channel is not, and this project has not measured it.",
    "CONDITIONAL": "-- unlinked artefact: safe iff the linker script places the "
                   "table sections in RAM. Supply one with --ld to check.",
    "UNDETERMINED": "-- the artefact does not settle it. Say so rather than guessing.",
    "NO-TABLES": "-- no AES lookup tables found (constant-time core, tables built at "
                 "run time, or a packed image - fwscan --decompress first).",
}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="flashleak placement",
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("artefact", help=".elf, .bin, .o, .a, or a directory of them")
    ap.add_argument("--part", default=None,
                    help="part family for the memory map: " + ", ".join(sorted(PARTS)))
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None,
                    help="flash base for a raw .bin whose vector table is missing")
    ap.add_argument("--ld", action="append", default=[],
                    help="linker script(s) to check for the required placement rule")
    ap.add_argument("--section", default=None,
                    help="section name to look for in --ld (default: the sections "
                         "the artefact's tables were found in)")
    ap.add_argument("--quiet", action="store_true", help="verdict lines only")
    ap.add_argument("--list-parts", action="store_true")
    ap.add_argument("--json", metavar="FILE",
                    help="also write the findings as JSON, for CI")
    ap.add_argument("--fail-on", default=None,
                    choices=["exposed", "unknown", "never"],
                    help="exit non-zero on this verdict or worse: 'exposed' fails "
                         "only a build whose tables are read from flash, 'unknown' "
                         "also fails an artefact the tool could not settle. The "
                         "default reports and always exits 0.")
    a = ap.parse_args(argv)

    if a.list_parts:
        for name in sorted(PARTS):
            p = PARTS[name]
            print(f"{name}  {p.note}")
            for r in p.regions:
                print(f"    {r.start:#010x}..{r.end:#010x}  {_MARK.get(r.exposure,'?')} "
                      f"{r.exposure:<10s} {r.name}  {r.note}")
        return 0

    targets = []
    if os.path.isdir(a.artefact):
        for root, _d, files in os.walk(a.artefact):
            for f in sorted(files):
                if f.endswith((".elf", ".bin", ".o", ".a")):
                    targets.append(os.path.join(root, f))
    else:
        targets = [a.artefact]

    worst = 0
    findings = []
    for t in targets:
        try:
            rep = analyse(t, a.part, a.base)
        except Exception as exc:
            print(f"{t}: could not analyse: {exc}")
            continue
        print(render(rep, verbose=not a.quiet))
        findings.append(to_dict(rep))
        if rep.verdict == "EXPOSED":
            worst = max(worst, 2)
        elif rep.verdict in ("UNDETERMINED", "CONDITIONAL"):
            worst = max(worst, 1)

        sections = ([a.section] if a.section else
                    sorted({p.section for p in rep.placements if p.section}))
        for ld in a.ld:
            for sec in sections or [a.section or ".rodata"]:
                r = check_linker_script(open(ld, errors="replace").read(), sec)
                if r.found:
                    where = r.output_section or "?"
                    reg = r.region or "?"
                    print(f"  ld {ld}: PLACES {sec} in output section {where} "
                          f"-> region {reg}")
                    if "AT" not in reg and reg not in ("?",) and not reg.startswith("RAM"):
                        print("     (region is not obviously RAM - check by hand)")
                    if reg != "?" and "AT" not in reg and reg.upper().startswith("RAM"):
                        print("     WARNING: placed in RAM with no `AT >` load region. "
                              "ST's own published snippet has this bug: the tables "
                              "arrive uninitialised unless something copies them.")
                else:
                    print(f"  ld {ld}: does NOT mention {sec} - the section falls "
                          "through to the read-only region next to .text, i.e. FLASH")
                    # Escalate only when the section is one somebody *asked* to be
                    # placed: named with --section, or a non-standard name, which
                    # is the signature of a library that expects placement.
                    standard = sec in (".rodata", ".data", ".text", ".bss") or \
                        sec.startswith((".rodata.", ".data.", ".text.", ".bss."))
                    if a.section or not standard:
                        worst = max(worst, 2)
        print()

    if a.json:
        import json
        with open(a.json, "w") as f:
            json.dump(findings, f, indent=1)
        print(f"wrote {a.json}")

    # Exit status is a report by default; --fail-on turns it into a gate.
    if a.fail_on == "exposed":
        return 1 if worst >= 2 else 0
    if a.fail_on == "unknown":
        return 1 if worst >= 1 else 0
    return 0


def to_dict(rep: Report) -> dict:
    """The report as plain data, for CI and for diffing two builds."""
    return {
        "path": rep.path, "kind": rep.kind, "part": rep.part,
        "verdict": rep.verdict, "confidence": rep.confidence, "notes": rep.notes,
        "tables": [{
            "table": p.table,
            "file_offset": p.file_offset,
            "runtime_addr": (f"{p.runtime_addr:#010x}"
                             if p.runtime_addr is not None else None),
            "region": p.region, "exposure": p.exposure,
            "section": p.section, "symbol": p.symbol, "evidence": p.evidence,
        } for p in rep.placements],
    }


if __name__ == "__main__":
    raise SystemExit(main())
