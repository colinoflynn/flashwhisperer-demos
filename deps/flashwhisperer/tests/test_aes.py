"""Validate the vectorized AES against the FIPS-197 test vector, and sanity
check the flash model and trace lengths."""

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

import numpy as np
from flashsim import aes
from flashsim.flash import FlashModel


def test_fips197_vector():
    key = bytes(range(16))                       # 000102...0f
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

    rk = aes.key_expansion(key)
    ct, sub_in = aes.encrypt_trace(
        np.frombuffer(pt, dtype=np.uint8)[None, :], rk
    )
    assert bytes(ct[0]) == expected, bytes(ct[0]).hex()
    assert sub_in.shape == (1, 10, 16)


def test_trace_shapes_and_layouts():
    rng = np.random.default_rng(0)
    rk = aes.key_expansion(bytes(16))
    pts = aes.random_plaintexts(8, rng)
    _, sub_in = aes.encrypt_trace(pts, rk)

    sb, meta_sb = aes.line_sequence(sub_in, "sbox")
    tt, meta_tt = aes.line_sequence(sub_in, "ttable")
    assert sb.shape == (8, 160)
    assert tt.shape == (8, 160)
    # S-box: 16 entries/line -> 4 top bits leak; T-table: 4 entries/line -> 6.
    assert meta_sb["index_bits_leaked"] == 4
    assert meta_tt["index_bits_leaked"] == 6
    assert sb.max() < 16                          # 256B / 16 = 16 lines
    assert tt.max() >= 4 * 64                      # four T-tables + sbox region


def test_flash_latch_hit_logic():
    f = FlashModel(ways=1, hit_cycles=1, miss_cycles=7)
    lines = np.array([[0, 0, 1, 1, 1, 2]])
    hits, cyc = f.run(lines)
    assert hits.tolist() == [[False, True, False, True, True, False]]
    # 3 misses*7 + 3 hits*1 wait, but first is miss: misses at idx0,2,5 =3
    assert cyc[0] == 3 * 7 + 3 * 1


def test_flash_cache_reuse():
    # a 2-way cache should keep two lines alive across an alternating pattern
    f1 = FlashModel(ways=1, hit_cycles=1, miss_cycles=7)
    f2 = FlashModel(ways=2, hit_cycles=1, miss_cycles=7)
    lines = np.array([[5, 6, 5, 6, 5, 6]])
    _, c1 = f1.run(lines)
    _, c2 = f2.run(lines)
    assert c2[0] < c1[0]                            # cache wins on this pattern


def test_setassoc_equivalence_and_conflict():
    # sets=1 must equal the fully-associative path
    lines = np.array([[5, 6, 5, 6, 5, 6]])
    assert FlashModel(ways=2, sets=1).run(lines)[1][0] == \
        FlashModel(ways=2).run(lines)[1][0]
    # direct-mapped: lines 0 and 4 collide in a 4-set/1-way cache -> all miss
    dm = FlashModel(ways=1, sets=4, hit_cycles=1, miss_cycles=7)
    assert dm.run(np.array([[0, 4, 0, 4, 0, 4]]))[1][0] == 6 * 7      # all miss
    assert dm.run(np.array([[0, 1, 0, 1, 0, 1]]))[1][0] == 2 * 7 + 4  # 2 miss,4 hit


def test_line_width_changes_leaked_bits():
    from flashsim import attack
    # narrower flash line (64-bit) reveals more key-difference bits than 128-bit
    p8 = attack.collision_pairs("sbox", line_bytes=8)
    p16 = attack.collision_pairs("sbox", line_bytes=16)
    assert p8[0]["bits"] == 5 and p8[0]["shift"] == 3
    assert p16[0]["bits"] == 4 and p16[0]["shift"] == 4
    assert attack.collision_pairs("ttable", line_bytes=16)[0]["bits"] == 6


def test_named_constructors_and_width():
    latch = FlashModel.row_latch(line_bytes=8, wait=6)
    assert latch.ways == 1 and latch.sets == 1 and latch.line_bytes == 8
    assert latch.miss_cycles == 7 and latch.total_lines == 1
    dc = FlashModel.data_cache(ways=4, sets=32, line_bytes=16, wait=6)
    assert dc.total_lines == 128 and dc.line_bytes == 16
    # encrypt_and_time should default line width to flash.line_bytes
    from flashsim.timing import encrypt_and_time
    rng = np.random.default_rng(0)
    rk = aes.key_expansion(bytes(16))
    pts = aes.random_plaintexts(64, rng)
    _, meta = encrypt_and_time(pts, rk, "sbox", FlashModel.row_latch(line_bytes=8))
    assert meta["entries_per_line"] == 8 and meta["index_bits_leaked"] == 5


if __name__ == "__main__":
    test_fips197_vector()
    test_trace_shapes_and_layouts()
    test_flash_latch_hit_logic()
    test_flash_cache_reuse()
    test_setassoc_equivalence_and_conflict()
    test_line_width_changes_leaked_bits()
    test_named_constructors_and_width()
    print("all tests passed")
