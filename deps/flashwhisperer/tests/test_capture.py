"""Tests for the Capture interface, TVLA quick-check, and stats (mostly fast)."""

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
import os
import tempfile
import numpy as np
import pytest
from flashattack import capture, tvla, stats, aesref

KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def _rand(n, seed=0):
    return np.random.default_rng(seed).integers(0, 256, (n, 16), np.uint8)


def test_engine_input_modes():
    pt = _rand(50, 1); key = KEY
    ct = aesref.encrypt_blocks(key, pt)
    # ecb-enc -> ciphertext, enc
    k, d = capture.Capture(timing=np.zeros(50), mode="ecb-enc", ciphertext=ct).engine_input()
    assert d == "enc" and np.array_equal(k, ct.astype(int))
    # ctr -> keystream = pt ^ ct
    k, d = capture.Capture(timing=np.zeros(50), mode="ctr", plaintext=pt, ciphertext=ct).engine_input()
    assert d == "enc" and np.array_equal(k, pt.astype(int) ^ ct.astype(int))
    # ecb-dec -> plaintext, dec
    dec = aesref.decrypt_blocks(key, ct)
    k, d = capture.Capture(timing=np.zeros(50), mode="ecb-dec", plaintext=dec).engine_input()
    assert d == "dec" and np.array_equal(k, dec.astype(int))
    # cmac -> tag (as ciphertext), enc
    k, d = capture.Capture(timing=np.zeros(50), mode="cmac", ciphertext=ct).engine_input()
    assert d == "enc"


def test_capture_save_load_roundtrip():
    ct = _rand(40, 2)
    c = capture.Capture(timing=np.arange(40.0), mode="ecb-enc", keysize=192, ciphertext=ct, label="x")
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "c.npz"); c.save_npz(p)
        r = capture.Capture.from_npz(p)
    assert r.mode == "ecb-enc" and r.keysize == 192 and r.n == 40
    assert np.array_equal(r.ciphertext, ct) and np.allclose(r.timing, np.arange(40.0))


def test_from_csv():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "t.csv")
        with open(p, "w", newline="") as f:
            f.write("timing,ciphertext\n")
            for i in range(5):
                f.write(f"{1000+i},{'ab'*16}\n")
        c = capture.Capture.from_csv(p, mode="ecb-enc")
    assert c.n == 5 and c.ciphertext.shape == (5, 16) and c.ciphertext[0, 0] == 0xab


def test_constant_time_check():
    assert tvla.constant_time_check(np.full(1000, 5000.0))["constant_time"]
    assert not tvla.constant_time_check(np.random.default_rng(0).normal(5000, 30, 1000))["constant_time"]


def test_tvla_fixed_random():
    rng = np.random.default_rng(0)
    same = tvla.tvla_fixed_random(rng.normal(0, 1, 5000), rng.normal(0, 1, 5000))
    assert not same["leaks"]
    diff = tvla.tvla_fixed_random(rng.normal(0.2, 1, 5000), rng.normal(0, 1, 5000))
    assert diff["leaks"]


def test_stats_preprocess():
    t = np.linspace(0, 100, 2000) + np.random.default_rng(0).normal(0, 1, 2000)  # strong drift
    d = stats.detrend(t)
    assert d.std() < t.std()                      # drift removed
    tr = stats.trim_outliers(np.concatenate([np.zeros(999), [1e9]]), hi=0.99)
    assert tr.max() < 1e9
