"""Hardware-free tests for the flashattack engine. Run: PYTHONPATH=. pytest tests/test_flashattack.py"""

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
from flashattack import aesref, engine, modes

KEY128 = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
NIST = {
    16: ("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
    24: ("000102030405060708090a0b0c0d0e0f1011121314151617", "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    32: ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
}


def _blk(h):
    return np.frombuffer(bytes.fromhex(h), np.uint8)[None, :]


@pytest.mark.parametrize("klen", [16, 24, 32])
def test_fips_vectors(klen):
    k, p, c = NIST[klen]
    assert aesref.encrypt_blocks(bytes.fromhex(k), _blk(p))[0].tobytes().hex() == c
    assert aesref.decrypt_blocks(bytes.fromhex(k), _blk(c))[0].tobytes().hex() == p


@pytest.mark.parametrize("klen", [16, 24, 32])
def test_key_schedule_inversion(klen):
    k = bytes.fromhex(NIST[klen][0])
    rk = aesref.key_expansion(k)
    Nk = klen // 4
    flat = [int(b) for row in rk for b in row]
    assert aesref.invert_key_schedule(flat[-4 * Nk:], klen * 8) == k


def test_mode_mapping_consistency():
    # CTR keystream == ECB-encrypt of the counter; ECB-dec == InvCipher
    m = np.random.default_rng(1).integers(0, 256, (64, 16), np.uint8)
    ctr, d1 = modes.known_output("ctr", m, KEY128)
    ecb, d2 = modes.known_output("ecb-enc", m, KEY128)
    assert d1 == d2 == "enc" and np.array_equal(ctr, ecb)
    dec, dd = modes.known_output("ecb-dec", m, KEY128)
    assert dd == "dec" and np.array_equal(dec, aesref.decrypt_blocks(KEY128, m).astype(int))


def test_second_round_transforms():
    # peel + MixColumns-linearity reduction algebra (deterministic, no scan)
    key = bytes.fromhex(NIST[32][0]); rk = aesref.key_expansion(key)
    rng = np.random.default_rng(2)
    pt = rng.integers(0, 256, (200, 16), np.uint8)
    ct = aesref.encrypt_blocks(key, pt)
    a = engine.peel_last_round(ct, rk[-1])                 # round Nr-1 output
    # re-applying the last round to `a` must reproduce ct
    reapplied = aesref.SBOX[a][:, aesref._SHIFT_ROWS] ^ np.frombuffer(bytes(rk[-1]), np.uint8)
    assert np.array_equal(reapplied, ct)
    # rk[Nr-1] = MC(SR(K')) with K' = SR^{-1}(MC^{-1}(rk[Nr-1]))
    kp = aesref._mix(np.frombuffer(bytes(rk[-2]), np.uint8)[None, :].copy(), inv=True)[0][aesref._ISR]
    assert engine._roundkey_from_Kprime(kp) == bytes(rk[-2])


def _synth(direction, key, N, delta, noise, seed, weak=(), weak_delta=1.6):
    rng = np.random.default_rng(seed)
    rk = aesref.key_expansion(key)
    target = rk[-1] if direction == "enc" else rk[0]
    tbl = engine.SINV if direction == "enc" else engine.SBOX
    known = rng.integers(0, 256, (N, 16), np.uint8)
    hi = (tbl[known.astype(np.int64) ^ target.astype(np.int64)] >> 4)
    t = 5000.0 + rng.normal(0, noise, N)
    for g in (range(0, 4), range(4, 8), range(8, 12), range(12, 16)):
        gs = list(g)
        for i in range(len(gs)):
            for j in range(i + 1, len(gs)):
                a, b = gs[i], gs[j]
                d = weak_delta if (a in weak or b in weak) else delta
                t -= d * (hi[:, a] == hi[:, b])
    return known, t, target


@pytest.mark.slow
@pytest.mark.parametrize("direction", ["enc", "dec"])
def test_recover_clean(direction):
    known, t, tk = _synth(direction, KEY128, 20000, 6.0, 22.0, seed=10)
    r = engine.recover(known, t, direction=direction, truth=tk)
    assert r.truth_correct == 16
    assert r.master == KEY128


@pytest.mark.slow
def test_recover_bruteforce_rescue():
    # two starved byte positions -> assembler misses them -> verify+brute-force fixes
    known, t, tk = _synth("enc", KEY128, 25000, 6.0, 26.0, seed=5, weak={3, 9})
    pt = bytes(16); ct = aesref.encrypt_blocks(KEY128, _blk("00" * 16))[0].tobytes()
    r = engine.recover(known, t, direction="enc", verify=(pt, ct), truth=tk)
    assert r.truth_correct < 16          # assembler alone missed at least one
    assert r.verified and r.master == KEY128
    assert set(r.bruteforced) <= {3, 9}
