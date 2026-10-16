"""Board descriptors: everything board-specific in one place, so adding an MCU is
a data change rather than new C. The firmware template (rigs/fw_template/)
reads these fields; the host uses `vcp`/`drive` to connect and flash.

`acr` presets encode the FLASH_ACR value for a leaky vs a safe configuration
(low nibble = wait states; bit8 PRFTEN, bit9 ICEN, bit10 DCEN on STM32 F4/G4;
L5 uses the separate ICACHE peripheral so acr only carries wait states).
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Board:
    name: str
    mcu: str
    core: str                 # cortex-m4 / cortex-m33
    gcc_define: str           # -D<define>
    cpu_flags: str
    flash_kb: int
    ram_kb: int
    flash_origin: int
    vcp: dict                 # {usart, tx, rx, af, apb}
    acr: dict                 # {"leak": hex, "safe": hex}
    data_cache_bytes: int | None
    drive_label: str          # drag-drop mass-storage volume label
    notes: str = ""


BOARDS = {
    "l552": Board(
        name="NUCLEO-L552ZE-Q", mcu="STM32L552ZE", core="cortex-m33",
        gcc_define="STM32L552xx",
        cpu_flags="-mcpu=cortex-m33 -mthumb -mfloat-abi=hard -mfpu=fpv5-sp-d16",
        flash_kb=512, ram_kb=256, flash_origin=0x08000000,
        vcp={"usart": "LPUART1", "tx": "PG7", "rx": "PG8", "af": 8, "apb": "APB1"},
        acr={"leak": "0000000f", "safe": "00000003"},   # L5: caching is ICACHE periph, not ACR
        data_cache_bytes=8192,                            # 8 KB unified ICACHE (holds working set)
        drive_label="NOD_L552ZE",
        notes="M33; VCP=LPUART1 needs PWR_CR2.IOSV; cache is the ICACHE peripheral (no FLASH_ACR.PRFTEN)."),
    "g474": Board(
        name="NUCLEO-G474RE", mcu="STM32G474RE", core="cortex-m4",
        gcc_define="STM32G474xx",
        cpu_flags="-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16",
        flash_kb=512, ram_kb=96, flash_origin=0x08000000,
        vcp={"usart": "USART2", "tx": "PA2", "rx": "PA3", "af": 7, "apb": "APB1"},
        acr={"leak": "00040704", "safe": "00040304"},     # leak=DCEN on (too small); safe=DCEN off is NOT safe here
        data_cache_bytes=256,                              # 256 B: holds S-box, not the T-table
        drive_label="NOD_G474RE",
        notes="ART: 1KB I-cache + 256B D-cache; reset default ACR has ICEN+DCEN on; C cmd = single-arg ACR."),
    "f429": Board(
        name="NUCLEO-F429ZI", mcu="STM32F429ZI", core="cortex-m4",
        gcc_define="STM32F429xx",
        cpu_flags="-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16",
        flash_kb=2048, ram_kb=192, flash_origin=0x08000000,
        vcp={"usart": "USART3", "tx": "PD8", "rx": "PD9", "af": 7, "apb": "APB1"},
        acr={"leak": "00000705", "safe": "0000000f"},      # leak=full ART on; 128B cache holds nothing
        data_cache_bytes=128,                              # 128 B: holds neither S-box nor T-tables
        drive_label="NOD_F429ZI",
        notes="Nucleo-144 -> VCP on USART3 (not USART2); F4 USART uses SR/DR; LED LD1=PB0."),
    "f303": Board(   # ChipWhisperer CW308 UFO target / future - for power/EM, not flash-timing
        name="ChipWhisperer STM32F303", mcu="STM32F303", core="cortex-m4",
        gcc_define="STM32F303xC",
        cpu_flags="-mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16",
        flash_kb=256, ram_kb=40, flash_origin=0x08000000,
        vcp={"usart": "USART2", "tx": "PA2", "rx": "PA3", "af": 7, "apb": "APB1"},
        acr={"leak": "00000010", "safe": "00000000"},      # F3: 64-bit flash, prefetch only, no data cache
        data_cache_bytes=None,                             # no data cache: flash-timing is the row latch only
        drive_label="",                                    # programmed via CW/openocd, not drag-drop
        notes="F3 has NO data cache; use for POWER/EM (ChipWhisperer) not the flash-timing channel. "
              "S-box still leaks via the 64-bit row latch if code runs from RAM."),
}


def get(name):
    try:
        return BOARDS[name.lower()]
    except KeyError:
        raise KeyError(f"unknown board {name!r}; known: {', '.join(BOARDS)}")
