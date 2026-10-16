"""Unit tests for the batched multi-key AES (flashattack/bruteforce.py)."""

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
import pytest

from flashattack import aesref, bruteforce as bf

RNG = np.random.default_rng(11)
KEYS = RNG.integers(0, 256, (64, 16), dtype=np.uint8)
BLOCK = RNG.integers(0, 256, 16, dtype=np.uint8)


def test_expand_keys_matches_reference():
    ref = np.stack([aesref.key_expansion(bytes(k)) for k in KEYS])
    assert np.array_equal(bf.expand_keys(KEYS), ref)


def test_invert_key_schedules_round_trips():
    rk_last = np.stack([aesref.key_expansion(bytes(k))[10] for k in KEYS])
    assert np.array_equal(bf.invert_key_schedules(rk_last), KEYS)


def test_decrypt_block_matches_reference():
    mine = bf.decrypt_block(bf.expand_keys(KEYS), BLOCK)
    ref = np.stack([np.asarray(aesref.decrypt_blocks(bytes(k), BLOCK.reshape(1, 16)),
                               np.uint8)[0] for k in KEYS])
    assert np.array_equal(mine, ref)


def test_search_finds_a_corrupted_byte():
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    # CCM counter blocks A_1, encrypted -> the keystreams an attacker observes
    blocks = np.zeros((6, 16), np.uint8)
    blocks[:, 0] = 0x01
    blocks[:, 1:14] = RNG.integers(0, 256, 13, dtype=np.uint8)
    blocks[:, 13] = np.arange(6)
    blocks[:, 15] = 0x01
    ks = np.asarray(aesref.encrypt_blocks(key, blocks), np.uint8)

    rk10 = bytearray(aesref.key_expansion(key)[10])
    rk10[5] ^= 0x3C
    got = bf.search_positions(bytes(rk10), [5], ks)
    assert got == key


def test_search_reports_failure_when_the_key_is_not_reachable():
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    blocks = np.zeros((4, 16), np.uint8)
    blocks[:, 0] = 0x01
    blocks[:, 13] = np.arange(4)
    blocks[:, 15] = 0x01
    ks = np.asarray(aesref.encrypt_blocks(key, blocks), np.uint8)
    rk10 = bytearray(aesref.key_expansion(key)[10])
    rk10[2] ^= 0x11          # corrupt a byte the search is NOT allowed to touch
    rk10[9] ^= 0x22
    assert bf.search_positions(bytes(rk10), [9], ks) is None


def _ccm_keystreams(key, n=6):
    """The blocks an attacker actually sees: E(K, A_1) for consecutive PIVs."""
    blocks = np.zeros((n, 16), np.uint8)
    blocks[:, 0] = 0x01
    blocks[:, 1:13] = RNG.integers(0, 256, 12, dtype=np.uint8)
    blocks[:, 13] = np.arange(n)
    blocks[:, 15] = 0x01
    return np.asarray(aesref.encrypt_blocks(key, blocks), np.uint8)


def test_search_pairs_finds_two_wrong_bytes_anywhere():
    """The guarantee: 14/16 is recovered wherever the two wrong bytes sit.

    3 and 11 are neither adjacent nor at an end, and nothing tells the search
    where they are - which is the point, since not needing the confidence
    ranking to be right about that is why the pair sweep exists.
    """
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    ks = _ccm_keystreams(key)
    rk10 = bytearray(aesref.key_expansion(key)[10])
    rk10[3] ^= 0x5A
    rk10[11] ^= 0xC3
    got, pair = bf.search_pairs(bytes(rk10), ks)
    assert got == key
    assert set(pair) == {3, 11}


def test_search_pairs_reports_failure_outside_its_guarantee():
    """Three wrong bytes is beyond a pair sweep; it must not claim success."""
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    ks = _ccm_keystreams(key)
    rk10 = bytearray(aesref.key_expansion(key)[10])
    for pos, mask in ((0, 0x11), (3, 0x22), (6, 0x33)):
        rk10[pos] ^= mask
    got, pair = bf.search_pairs(bytes(rk10), ks, positions=range(8))
    assert got is None and pair is None
