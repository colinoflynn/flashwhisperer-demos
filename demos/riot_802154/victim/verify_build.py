"""Read the geometry the attack needs out of the built ELF.

    python verify_build.py bin/nrf52840dk/riot_802154_echo.elf

Three things, and all three are properties of the image rather than constants
of the attack:

  * `Te0`'s runtime address. RIOT's default AES build has no Te1..Te4 at all --
    `sys/crypto/aes.c:149-155`, under `#ifndef MODULE_CRYPTO_AES_PRECALCULATED`,
    defines all five macros in terms of Te0 -- so the last round reads this
    same table and this is the only address that matters.
  * `line_off`, which is where the table starts inside its flash row, in table
    ENTRIES. Te0's entries are 4 bytes and the nRF52840's row is 16, so a
    row-aligned table is `line_off = 0` and a table 4 bytes in is 1. Getting
    it wrong costs between two and ten times the traces.
  * that the table really is in flash. If the linker put it in RAM the channel
    is gone, which is this demo's own control.

WHAT THIS DOES NOT CHECK: that the compiled read order is the one the attack's
pair set assumes. It does not need to -- the attack ranks all 120 output-byte
pairs by their own blind margin and the leaking ones rise on their own, which
on the measured capture reproduced the compiler's emitted order exactly. See
the demo README.
"""

import re
import subprocess
import sys

ROW_BYTES = 16          # nRF52840 flash read latch
ENTRY_BYTES = 4         # RIOT's Te0 is 256 x uint32_t


def objdump(elf, *args):
    for tool in ("arm-none-eabi-objdump", "objdump"):
        try:
            return subprocess.run([tool, *args, elf], check=True,
                                  capture_output=True, text=True).stdout
        except FileNotFoundError:
            continue
    raise SystemExit("no arm-none-eabi-objdump on the path")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__.split("\n")[2].strip())
    elf = sys.argv[1]

    syms = objdump(elf, "-t")
    hit = None
    for line in syms.splitlines():
        m = re.match(r"^([0-9a-f]+)\s+.*\s+(\S+)\s+([0-9a-f]+)\s+Te0$", line)
        if m:
            hit = (int(m.group(1), 16), m.group(2), int(m.group(3), 16))
            break
    if hit is None:
        raise SystemExit("no Te0 symbol in %s -- is this a RIOT AES build?" % elf)
    addr, section, size = hit

    line_off = (addr % ROW_BYTES) // ENTRY_BYTES
    line_shift = (ROW_BYTES // ENTRY_BYTES).bit_length() - 1
    in_ram = addr >= 0x20000000

    print("Te0        0x%08x  %d bytes  section %s" % (addr, size, section))
    print("geometry   line_shift=%d line_off=%d  "
          "(row of a lookup is (index+%d)>>%d)"
          % (line_shift, line_off, line_off, line_shift))
    if size != 1024:
        print("           NOTE: %d bytes, not the 1024 of a single-table "
              "build. Did MODULE_CRYPTO_AES_PRECALCULATED get enabled?" % size)
    if in_ram:
        print("           NOTE: that address is RAM. This is the CONTROL "
              "build; it has no flash channel and must recover nothing.")
    else:
        print("           in flash, so the read latch is in the path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
