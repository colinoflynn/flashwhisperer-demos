"""Where does the table sit inside the flash row? Get it wrong and pay 2.2x.

**This is the surviving copy of what used to be `hardware/line_offset.py`**,
which is now a shim over this module - the arithmetic belongs beside the
scorer that consumes it (`lastround.score_surface`), and leaving it outside the
package meant the packaged test suite had to reach into `hardware/` to test it.
The image-reading half moved the other way, to
`flashleak.placement.row_offset_from_image`, because reading a firmware image
is the static analyser's job and `flashattack` must not import `flashleak`.

CALL IT A ROW OFFSET, NOT AN OFFSET. `engine.leaking_offsets` answers a
different question - *which byte-pair distances carry the channel* - and the
two have already been confused once. This module is about *where the table
starts inside a flash row*.

The flash read granule on these parts is 16 bytes, so a cache-collision attack
groups table indices by ROW - and the boundaries are set by the table's
run-time ADDRESS, not by the index. A 256-byte S-box at `0x...cc` starts 12
bytes into a row, so its boundaries fall at index 4, 20, 36, ... and it spans
**17** rows, not 16.

Grouping by the obvious `index >> 4` therefore tests a partition shifted from
the real one. Measured on 2.07 M real over-the-air traces against the true key:

    row offset  0 (wrong)   effect -0.888 cyc   (sd/eff)^2 3221
    row offset 12 (right)   effect -1.312 cyc   (sd/eff)^2 1475

a factor of **2.18 in traces** from one wrong constant. A full sweep of the 16
offsets peaks cleanly at 12, i.e. the timing data recovers the linker's
placement on its own.

WHERE THE OFFSET COMES FROM. It is link-order luck - wherever the linker put
the table, mod the granule - not a property of AES or of the part:

    victim  (S2915A1_UDP_Client)  .rodata.sbox @ 0x080178cc  -> 12
    coord   (S2915A1_UDP_Server)  .rodata.sbox @ 0x0801784c  -> 12

Both landed on 12 there because they share most of their rodata layout, but a
different application or toolchain can land anywhere. `static const uint8_t
sbox[256]` carries no alignment attribute, so GCC gives the section 4-byte
alignment on ARM and the offset is one of {0, 4, 8, 12} - four candidates, not
sixteen.

**Alignment is not a mitigation, and the sign of its effect is per-part.**
Forcing `aligned(16)` merely moves the offset to 0: the table then spans
exactly 16 equal rows instead of 17 uneven ones. Any 256-byte table spans at
least 16 rows on a 16-byte-granule machine, so collisions exist at every
alignment.

This file used to add "which if anything is cleaner for the attacker", and that
was an argument rather than a measurement. It has since been measured on both
sides. On the nRF52840 it holds - the 16-byte-aligned build is the attacker's
best at 6 250 traces against 12 500 and 25 000 for two link-time accidents of
the same firmware. On the MPC5606B it is exactly reversed, in the cleaner
experiment of the two (two builds differing in nothing but a pad size): offset
0 needs 7 500 traces and offset 8, straddling 17 rows, needs 3 750.

So alignment is an axis to sweep and to quote with the trace count, never a
lever with a known sign. The fixes are a table-free/constant-time
implementation or a hardware AES engine - see MECHANISM_SCOPE.md.

Three ways to get the offset, in order of preference:

  1. `flashleak.placement.row_offset_from_image(path)` - exact, from the
     firmware, by byte pattern, so it needs no symbols and works on a raw
     `.bin`.
  2. `candidate_row_offsets()` - when no image is available, try them and keep
     whichever VERIFIES cryptographically. Verification is exact and costs
     ~20 s per offset against hours of capture, so this is never the
     bottleneck.
  3. Sweep all of them and keep the one with the largest margin. This is the
     only route when there is no known plaintext/ciphertext pair to verify
     against, and it is the weakest: the margin is itself a max over a noisy
     surface, so read it on a trace ladder rather than at one count.

UNITS. Everything here is in **table entries**, which for a 1-byte-entry S-box
is the same as bytes and for a 4-byte T-table is not: a T-table 12 bytes into
its row is 3 entries in. `lastround`'s `line_off` takes the same unit, which is
the only way the two stay consistent.

WHAT THIS MODULE DOES NOT COVER. It says nothing about whether the table is in
flash at all - a build that copies it to RAM has no row structure and no
channel, which is `flashleak.placement`'s `exposure` field, and
`row_offset_from_image` returns `None` for it. It also says nothing about the
flash row WIDTH: 16 bytes is the F4/G4/L5/nRF52840 case, the F1/F3/G4 data path
is 8 and the TC234 is 32, and that is `lastround`'s `line_shift`.
"""
from __future__ import annotations

GRANULE = 16          # flash read width on STM32F4/G4/L5 (measured, stm32f4_latch.md)
TABLE_LEN = 256       # AES S-box


def row_offset(addr, granule=GRANULE):
    """The row offset of a table at run-time address `addr`: `addr % granule`."""
    return int(addr) % int(granule)


def line_index(idx, off, granule=GRANULE):
    """Which flash row holds table element `idx`, for a table `off` entries in."""
    return (int(idx) + int(off)) // int(granule)


def table_rows(off, table_len=TABLE_LEN, granule=GRANULE):
    """How many distinct rows the table spans - 17 when misaligned, 16 when not.

    Sizing a per-row accumulator 16 regardless raises IndexError the moment the
    offset is non-zero, which is how the misalignment first announced itself.
    """
    return ((int(table_len) - 1 + int(off)) // int(granule)) + 1


def nlines(off, *, table_len=TABLE_LEN, granule=GRANULE):
    """Historical name for `table_rows`, kept for the callers that use it.

    **Its extra arguments are keyword-only on purpose.** `lastround.nlines` is
    the same quantity parameterised by a SHIFT instead of a granule, and it
    takes the shift FIRST: `lastround.nlines(4, 12)` is a 16-byte row and an
    offset of 12, while `geometry.nlines(4, 12)` would have meant an offset of
    4 in a 12-entry table. Two same-named functions whose first argument means
    different things is the shape of trap this repository keeps paying for, so
    the second argument here cannot be passed positionally at all.

    The two must agree where they overlap, and
    `tests/test_line_offset.py::test_geometry_agrees_with_the_scorer` asserts
    it across five row widths and five offsets.
    """
    return table_rows(off, table_len, granule)


def candidate_row_offsets(align=4, granule=GRANULE):
    """Offsets worth trying when the image is unavailable.

    `align` is the section alignment the compiler gave the table: 4 on ARM GCC
    for a plain `const uint8_t[]`, giving {0, 4, 8, 12}. Pass 1 to sweep all 16
    if the toolchain is unknown - still cheap.
    """
    return list(range(0, int(granule), int(align)))


#: Historical names, kept because out-of-package callers use them.
candidate_offsets = candidate_row_offsets
