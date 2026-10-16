"""The S-box's cache-line offset must come from the build, never be assumed 0.

This exists because assuming it cost a factor of 2.18 in traces on a real
over-the-air capture. The collision attack groups table indices by flash line,
and the line boundaries are set by the table's run-time ADDRESS: a 256-byte
S-box at `0x...cc` sits 12 bytes into a 16-byte line, so `index >> 4` is the
wrong partition and the table spans 17 lines rather than 16.

Nothing here needs hardware or a toolchain - the arithmetic is the point, plus
one synthetic ELF to prove the offset is recovered from an image rather than
hardcoded.

The arithmetic is `flashattack.geometry` and the image half is
`flashleak.row_offset_from_image`; both used to be `hardware/line_offset.py`,
which this test reached by putting `hardware/` on `sys.path` - the one back
edge out of the packaged suite, and the reason the geometry moved in. See
PASSIVE_ORACLE.md ("Cache-line alignment").

WHAT THIS FILE DOES NOT COVER: that the scorer USES the offset it is given.
`test_geometry_agrees_with_the_scorer` below pins the two row counts to each
other, and `flashattack.lastround.selftest` checks the fast path against the
reference at a geometry, but neither shows a recovery improving at the right
offset - that is a measurement on a capture, in
`results/stm32f4/rescore_rowoffset.py` and a row of
`research/FINDINGS_LEDGER.md` section D, not a unit test.
"""
from __future__ import annotations

import os as _os, sys as _sys
# The five packages live under flashwhisperer/ (REORG_PLAN D2).  Walk up to the
# .git marker rather than assume a depth: importers of these packages sit at the
# repository root, in hardware/, results/<campaign>/, demo/<stack>/ and
# research/<area>/ - four different depths.  `.git` is a FILE in a worktree, so
# test existence, not isdir.
_fw = _os.path.dirname(_os.path.abspath(__file__))
while _fw != _os.path.dirname(_fw) and not _os.path.exists(_os.path.join(_fw, ".git")):
    _fw = _os.path.dirname(_fw)
_sys.path.insert(0, _os.path.join(_fw, "flashwhisperer"))

import pathlib
import struct
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from flashattack.geometry import (GRANULE, candidate_offsets,  # noqa: E402
                                  line_index, nlines)
from flashattack import lastround  # noqa: E402
from flashleak import row_offset_from_image as offset_from_image  # noqa: E402
from flashsim import aes  # noqa: E402


def test_the_two_table_sets_are_the_same_bytes():
    """`hardware/atk_lastround.py` re-exports flashattack's S-box instead of
    building its own from flashsim's. That is only sound while the two agree,
    and nothing checked it."""
    import numpy as np
    from flashattack import aesref
    assert np.array_equal(np.asarray(aesref.SBOX, np.int64),
                          np.asarray(aes.SBOX, np.int64))
    assert np.array_equal(lastround.PINV, np.argsort(aes._SHIFT_ROWS))


@pytest.mark.parametrize("off", [0, 1, 4, 12, 15])
@pytest.mark.parametrize("shift", [1, 2, 3, 4, 5])
def test_geometry_agrees_with_the_scorer(off, shift):
    """One row count, two parameterisations: `geometry` takes a granule in
    entries and `lastround` takes a shift, and a disagreement between them
    would size an accumulator wrong at exactly the offsets that matter."""
    assert nlines(off, granule=1 << shift) == lastround.nlines(shift, off)


def test_aligned_table_spans_16_lines():
    assert nlines(0) == 16


@pytest.mark.parametrize("off", [1, 4, 8, 12, 15])
def test_misaligned_table_spans_17_lines(off):
    """The extra line is the whole point: an accumulator sized 16 will crash."""
    assert nlines(off) == 17


def test_line_index_boundaries_follow_the_address():
    # offset 12: the first line holds only indices 0..3, then 16 at a time
    assert [line_index(i, 12) for i in (0, 3, 4, 19, 20)] == [0, 0, 1, 1, 2]
    # offset 0: the textbook partition
    assert [line_index(i, 0) for i in (0, 15, 16, 31, 32)] == [0, 0, 1, 1, 2]


def test_top_index_needs_the_extra_line():
    """(255 + 12) >> 4 == 16, i.e. a 17th line index exists."""
    assert line_index(255, 12) == 16
    assert line_index(255, 12) < nlines(12)


def test_candidate_offsets_match_arm_gcc_alignment():
    # `const uint8_t sbox[256]` gets 4-byte section alignment on ARM GCC,
    # so only four offsets are reachable - cheap to try all of them.
    assert candidate_offsets() == [0, 4, 8, 12]
    assert candidate_offsets(align=1) == list(range(16))


def test_collision_partition_differs_between_offsets():
    """A wrong offset is not a harmless relabelling: it splits real collisions.

    Two indices sharing a line under the true partition must not be assumed to
    share one under a shifted partition - that is exactly the signal loss.
    """
    same_at_12 = [(i, j) for i in range(256) for j in range(i + 1, 256)
                  if line_index(i, 12) == line_index(j, 12)]
    disagree = [(i, j) for i, j in same_at_12
                if line_index(i, 0) != line_index(j, 0)]
    # a large minority of true collisions are missed by the naive partition
    assert len(disagree) / len(same_at_12) > 0.2


def _synthetic_elf(sbox_off_in_section):
    """Smallest ELF that placement can read: one .rodata holding the S-box.

    The table is placed `sbox_off_in_section` bytes into a 16-byte-aligned
    section, so the run-time address low nibble is known by construction.
    """
    sbox = bytes(int(x) for x in aes.SBOX)
    base = 0x08010000                       # 16-byte aligned flash address
    body = b"\x00" * sbox_off_in_section + sbox + b"\x00" * 16

    ehsize, shentsize = 52, 40
    shoff = ehsize + len(body)
    nsec = 3                                # NULL, .rodata, .shstrtab
    shstr = b"\0.rodata\0.shstrtab\0"
    shstroff = shoff + nsec * shentsize

    eh = struct.pack("<16sHHIIIIIHHHHHH",
                     b"\x7fELF\x01\x01\x01" + b"\0" * 9,
                     2, 40, 1, 0, 0, shoff, 0,
                     ehsize, 0, 0, shentsize, nsec, 2)

    def sh(name, typ, flags, addr, off, size, align):
        return struct.pack("<IIIIIIIIII", name, typ, flags, addr, off, size,
                           0, 0, align, 0)

    sections = (sh(0, 0, 0, 0, 0, 0, 0)
                + sh(1, 1, 0x2, base, ehsize, len(body), 16)      # .rodata
                + sh(9, 3, 0, 0, shstroff, len(shstr), 1))        # .shstrtab
    return eh + body + sections + shstr, base + sbox_off_in_section


@pytest.mark.parametrize("off", [0, 4, 12])
def test_offset_recovered_from_a_built_image(tmp_path, off):
    """The offset is read out of the image, not assumed."""
    blob, expect_addr = _synthetic_elf(off)
    p = tmp_path / ("sbox_off%d.elf" % off)
    p.write_bytes(blob)
    got_off, got_addr, note = offset_from_image(str(p), part="stm32f4")
    assert got_addr == expect_addr, note
    assert got_off == off % GRANULE, note


def test_real_victim_image_if_present():
    """Regression against the actual bench firmware, when it is available.

    Skipped on machines without the (out-of-repo) build tree, so the suite still
    runs anywhere - but on the bench it pins the value the OTA tools use.
    """
    elf = pathlib.Path(
        r"C:\Users\cofly\Dropbox (Personal)\academic\claude_research"
        r"\802154-stm32\build\out\NUCLEO-F401RE"
        r"\S2915A1_UDP_Client-release\S2915A1_UDP_Client.elf")
    if not elf.exists():
        pytest.skip("bench build tree not present")
    off, addr, note = offset_from_image(str(elf), part="stm32f4")
    assert addr is not None and off is not None, note
    assert off == addr % GRANULE
    # the measured optimum on 2.07 M over-the-air traces
    assert off == 12, "victim S-box moved: %s" % note
