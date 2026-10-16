"""fwscan against firmware whose AES layout we already know.

The four binaries checked into rigs/fw_f4_lib/ are the same images whose
keys were recovered on the F429, so their table layout is ground truth, not an
assumption. If the scanner ever stops reproducing it, it is the scanner that
is wrong.
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

import pytest

from flashleak import fwscan

FW = pathlib.Path(__file__).resolve().parents[2] / "rigs" / "fw_f4_lib"

CASES = [
    # image,                        expected Te tables, S-box, inverse S-box
    ("fixed_mbedtls.bin", 4, True, True),
    ("fixed_mbedtls_compact.bin", 1, True, True),
    ("fixed_tinyaes.bin", 0, True, True),
    ("fixed_tinycrypt.bin", 0, True, False),
]


def _scan(name):
    path = FW / name
    if not path.exists():
        pytest.skip(f"{name} not built")
    return fwscan.scan(path.read_bytes())


@pytest.mark.parametrize("name,n_te,sbox,isbox", CASES)
def test_layout_matches_ground_truth(name, n_te, sbox, isbox):
    res = _scan(name)
    names = {h.name for h in res["hits"]}
    te = {n.split()[0] for n in names if n.startswith("Te")}
    assert len(te) == n_te, f"{name}: expected {n_te} T-tables, found {sorted(te)}"
    assert ("AES S-box" in names) is sbox
    assert ("AES inverse S-box" in names) is isbox


@pytest.mark.parametrize("name,_a,_b,_c", CASES)
def test_vector_table_is_found(name, _a, _b, _c):
    """These are raw STM32 flash images, so the head must parse as Cortex-M."""
    vec = _scan(name)["vector"]
    assert vec is not None, f"{name}: no Cortex-M vector table"
    assert vec[0] == 0x08000000


def test_te_fingerprints_match_fips_constants():
    """Te0 = [2.S, S, S, 3.S]; guard the generator against a silent change."""
    assert fwscan._te_prefix(0, True).hex() == "c66363a5f87c7c84ee777799f67b7b8d"
    assert fwscan._te_prefix(1, True)[:4].hex() == "a5c66363"
    assert fwscan._te_prefix(0, False)[:4].hex() == "a56363c6"


def test_single_table_and_four_table_verdicts_differ():
    one = " ".join(fwscan.verdict(_scan("fixed_mbedtls_compact.bin")))
    four = " ".join(fwscan.verdict(_scan("fixed_mbedtls.bin")))
    assert "single T-table" in one
    assert "four T-tables" in four


def test_ihex_round_trip():
    """A tiny Intel HEX record stream must flatten to the right bytes and base."""
    lines = [
        ":020000040800F2",          # upper address 0x0800
        ":04000000DEADBEEF79",      # 4 data bytes at 0x0000
        ":00000001FF",              # EOF
    ]
    out = fwscan.ihex_to_bin("\n".join(lines))
    assert out is not None
    data, base = out
    assert base == 0x08000000
    assert data == bytes.fromhex("DEADBEEF")


def test_ihex_rejects_non_hex():
    assert fwscan.ihex_to_bin("not a hex file at all") is None


def test_unpack_rle_literals_and_runs():
    """PackBits: n<0x80 -> n+1 literals; n>=0x80 -> repeat next byte 257-n times."""
    packed = bytes([0x02]) + b"abc" + bytes([0xFE, 0x5A])      # 3 literals, then 3x 0x5A
    assert fwscan.unpack_rle(packed) == b"abc" + b"\x5a" * 3


def test_rle_recovers_a_table_split_by_count_bytes():
    """The ST-LINK case: a 256-byte table stored as 127-byte literal runs."""
    from flashattack.aesref import SBOX
    sb = bytes(SBOX)
    packed = (bytes([126]) + sb[:127]) + (bytes([126]) + sb[127:254]) + \
             (bytes([1]) + sb[254:])
    assert fwscan.unpack_rle(packed) == sb
    # and the packed form defeats a plain search, which is why the decode exists
    assert packed.find(sb) == -1


def test_gladman_fingerprints_are_the_gf_multiples():
    from flashattack.aesref import SBOX

    def xt(a):
        a <<= 1
        return (a ^ 0x1B) & 0xFF if a & 0x100 else a

    assert fwscan._gf_sb(2) == bytes(xt(int(s)) for s in SBOX[:24])
    assert fwscan._gf_sb(3) == bytes(xt(int(s)) ^ int(s) for s in SBOX[:24])


def test_td_fingerprints_match_fips_constants():
    """Td0[x] = [14.S'[x], 9.S'[x], 13.S'[x], 11.S'[x]]; first word 0x51f4a750."""
    assert fwscan._td_prefix(0, True)[:4].hex() == "51f4a750"
    assert fwscan._td_prefix(0, False)[:4].hex() == "50a7f451"
    assert fwscan._td_prefix(1, True)[:4].hex() == "5051f4a7"


def test_decrypt_only_build_is_detected_without_te():
    """A bootloader may carry Td and no Te at all - that must still be reported."""
    blob = b"\x00" * 64 + fwscan._td_prefix(0, False) * 4 + b"\xff" * 64
    res = fwscan.scan(blob)
    names = {h.name for h in res["hits"]}
    assert any(n.startswith("Td0") for n in names)
    assert not any(n.startswith("Te") for n in names)
    assert "decryption T-table" in " ".join(fwscan.verdict(res))
