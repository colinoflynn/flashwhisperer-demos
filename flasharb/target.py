"""Per-part descriptions for the flash-arbitration probe.

A `Target` carries only what the host cannot discover over the wire. Everything else --
kernel addresses, table address, offsets modulo the read word - is asked of the device,
because a host that assumes those is a host that reports the sweep it meant to run rather
than the one it ran (`research/targets/stm32g474_arb_probe.md` §5.3).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Target:
    name: str
    port: str
    board: str                       # key into hardware/boards.py
    fw_dir: str                      # relative to rigs/
    banner: str                      # must appear in the V reply, or we are talking to
                                     # some other firmware on the same bench

    read_width: int                  # flash read word, bytes
    entry_stride: int                # bytes per table entry in the kernels (always 4)

    # Latch geometry. `latch_entries` = 1 for a single buffer, 2 for the L552's pair, and
    # `latch_index_bit` is the address bit that selects between them.
    #
    # THIS IS THE FIELD THAT SILENTLY BREAKS A PORT. With a 2-entry latch, an index chosen
    # the way it is chosen on a 1-entry part can land in the OTHER entry, where it hits the
    # word left there by the previous iteration - so the "miss" case hits, the differential
    # collapses, and the target is reported clean. `check_indices()` below refuses that.
    latch_entries: int = 1
    latch_index_bit: int = 3

    # Accelerator configurations worth sweeping, as (word, label). The word is opaque to
    # the host and is whatever the board file's arb_set_accel() takes.
    configs: tuple = field(default_factory=tuple)

    # Clock settings the board's `Z` accepts, MHz. Empty = single clock.
    clocks: tuple = ()

    def check_indices(self, tab_base: int, idx_a: int, idx_hit: int, idx_miss: int,
                      idx_flush: int = 0, stride: int = None) -> None:
        """Raise unless the three indices actually mean what the sweep needs them to.

        Cheap, and it catches the one class of error that produces a clean-looking null.

        `stride` is the SCALING THE LOAD INSTRUCTION APPLIES to the index, which is not
        always the table's entry size. The E4 encoding family in probe.S deliberately varies
        it: encoding 0 is `ldrb.w rX,[rB,rI,lsl#2]` (stride 4) while encodings 1 and 2 are
        `ldrb rX,[rB,rI]` (stride **1**, the index is a raw byte offset).

        This defaulted to `entry_stride` and silently mis-modelled the unshifted encodings.
        On the F429 - 16-byte read word - indices 0x40/0x41/0x44 are 4, 4 and 4 bytes apart
        under stride 1, so all three land in ONE read word, the "miss" cannot miss, and the
        sweep reported `+0.000` for those encodings even at LATENCY 2, which is impossible.
        The checker existed to catch exactly that and did not, because it was checking the
        wrong addressing mode. See hardware/ARB_PORTING.md §5.
        """
        stride = self.entry_stride if stride is None else stride

        def addr(i):  return tab_base + stride * i
        def word(i):  return addr(i) & ~(self.read_width - 1)
        def entry(i): return (addr(i) >> self.latch_index_bit) & (self.latch_entries - 1) \
                          if self.latch_entries > 1 else 0

        if word(idx_hit) != word(idx_a):
            raise ValueError("idx_hit 0x%x does not share idx_a 0x%x's read word "
                             "(0x%08x vs 0x%08x)" % (idx_hit, idx_a, word(idx_hit), word(idx_a)))
        if word(idx_miss) == word(idx_a):
            raise ValueError("idx_miss 0x%x shares idx_a's read word" % idx_miss)
        if entry(idx_miss) != entry(idx_a):
            raise ValueError(
                "idx_miss 0x%x lands in latch entry %d but idx_a 0x%x is in entry %d. On a "
                "%d-entry latch that load HITS the other entry, the differential collapses "
                "and this target is reported clean. Pick a miss index with the same "
                "entry and a different word."
                % (idx_miss, entry(idx_miss), idx_a, entry(idx_a), self.latch_entries))
        if entry(idx_flush) != entry(idx_a) or word(idx_flush) == word(idx_a):
            raise ValueError(
                "flush index 0x%x must share idx_a's latch entry and not its word, or load "
                "A stops missing and the measurement drifts" % idx_flush)

    def pick_indices(self, tab_base: int, idx_a: int = 0x40):
        """(idx_a, idx_hit, idx_miss) that satisfy check_indices() on this target."""
        stride, w = self.entry_stride, self.read_width
        per_word = w // stride
        idx_hit = idx_a ^ 1 if per_word > 1 else idx_a
        for cand in range(idx_a + per_word, 256):
            try:
                self.check_indices(tab_base, idx_a, idx_hit, cand)
                return idx_a, idx_hit, cand
            except ValueError:
                continue
        raise ValueError("no usable miss index for %s" % self.name)


# FLASH_ACR values. G4 carries LATENCY|PRFTEN|ICEN|DCEN in one register.
G4_CONFIGS = (
    (0x000, "LAT0 nothing"),
    (0x100, "LAT0 PRFTEN"),
    (0x200, "LAT0 ICEN"),
    (0x300, "LAT0 PRFTEN+ICEN"),
    (0x001, "LAT1 nothing  (wait-state positive control)"),
)

# L552 has no PRFTEN/ICEN/DCEN at all: FLASH_ACR is LATENCY + LVEN, and acceleration is the
# separate ICACHE peripheral. rigs/fw_l5_arb/board.c packs them as
#     bits 3:0 LATENCY | bit 8 ICACHE_CR.EN | bit 9 WAYSEL
L5_CONFIGS = (
    (0x000, "LAT0 icache off"),
    (0x100, "LAT0 icache on, 1-way"),
    (0x300, "LAT0 icache on, 2-way"),
    (0x001, "LAT1 icache off  (wait-state positive control)"),
)

# STM32F4 carries LATENCY|PRFTEN|ICEN|DCEN in FLASH_ACR with the SAME bit positions as the
# G4, so a config word means the same thing on both boards and the two maps are directly
# comparable. rigs/fw_f4_arb/board.c passes the word to FLASH_ACR unchanged (after
# pulsing ICRST/DCRST, which is not part of the word).
#
# DCEN gets its own row here, which the G4 list does not have. On this part the data cache is
# 8 tags x 16 B (research/targets/stm32f4_latch.md section 2) and the probe touches exactly two words, so
# with DCEN on both the colliding and the non-colliding index are simply cached and the
# differential must vanish for a reason that has nothing to do with arbitration. Sweeping it
# says so explicitly rather than leaving a reader to wonder.
#
# TWO non-zero LATENCY rows, not one: the L552 null was believed because its positive control
# scaled exactly with the wait-state count (-1.000 / -2.000), and one point cannot show
# scaling. RM0090 Table 10 allows LATENCY 0 up to 30 MHz at 3.3 V, so the 16 MHz LATENCY-0
# rows are a legal setting and the LATENCY 1/2 rows are the over-programmed ones.
F4_CONFIGS = (
    (0x000, "LAT0 nothing"),
    (0x100, "LAT0 PRFTEN"),
    (0x200, "LAT0 ICEN"),
    (0x400, "LAT0 DCEN"),
    (0x700, "LAT0 PRFTEN+ICEN+DCEN"),
    (0x001, "LAT1 nothing  (wait-state positive control)"),
    (0x002, "LAT2 nothing  (wait-state positive control)"),
)

TARGETS = {
    "g474": Target(
        name="g474", port="COM7", board="g474", fw_dir="fw_g4_arb", banner="g4arb",
        read_width=8, entry_stride=4, latch_entries=1,
        configs=G4_CONFIGS, clocks=(1, 2, 4, 8, 16, 24, 30),
    ),
    "l552": Target(
        name="l552", port="COM6", board="l552", fw_dir="fw_l5_arb", banner="l5arb",
        # RM0438 / stm32l552.md: 64-bit read, and a TWO-entry latch direct-mapped on A[3].
        read_width=8, entry_stride=4, latch_entries=2, latch_index_bit=3,
        configs=L5_CONFIGS, clocks=(1, 2, 4, 8, 16),
    ),
    "f429": Target(
        name="f429", port="COM9", board="f429", fw_dir="fw_f4_arb", banner="f4arb",
        # RM0090 / stm32f4_latch.md: 128-bit read - read_width is 16 here, NOT the 8 the other
        # two parts use. Getting this wrong is the quiet way to break the port: with 8, the
        # host would pick idx_miss = 0x42, which on a 16-byte word SHARES idx_a's word, so
        # the "miss" case would hit and the whole target would report clean. The collision
        # predicate on this part is idx >> 2 (four 4-byte entries per read word), not
        # idx >> 1.
        #
        # ONE latch entry, 16 bytes, measured (stm32f4_latch.md section 3) - the G474's shape
        # scaled up, not the L552's 2-entry pair, so latch_entries stays 1 and
        # latch_index_bit is unused.
        read_width=16, entry_stride=4, latch_entries=1,
        configs=F4_CONFIGS, clocks=(2, 4, 8, 16),
    ),
}
