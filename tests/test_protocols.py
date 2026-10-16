"""Hardware-free tests for the OSCORE / SSH network oracles.

Run: PYTHONPATH=. pytest tests/test_protocols.py

These prove the two demos recover the full AES-128 key from a flashsim-backed,
network-jitter-modelled capture, and that the protocol framing (CCM counter
blocks, SSH CTR counters, keystream = P^C) is correct.
"""

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
from flashattack import aesref, protocols
from flashattack.sources import SimulatedProtocolSource
from flashattack.attack import attack

KEY = "2b7e151628aed2a6abf7158809cf4f3c"
_k = bytes.fromhex(KEY)
_PT = bytes(16)
_CT = aesref.encrypt_blocks(_k, np.frombuffer(_PT, np.uint8)[None, :])[0].tobytes()


# ---- protocol framing ------------------------------------------------------

def test_ccm_counter_format():
    # AES-CCM-16-64-128: L=2, 13-byte nonce, Flags=0x01, 2-byte big-endian counter.
    nonce = bytes(range(13))
    A = protocols.ccm_counter_blocks(nonce, 3, L=2, start=1)
    assert A.shape == (3, 16)
    assert A[0, 0] == 0x01                       # flags = L-1
    assert bytes(A[0, 1:14]) == nonce            # nonce in place
    assert (A[0, 14], A[0, 15]) == (0, 1)        # counter i=1, big-endian
    assert (A[2, 14], A[2, 15]) == (0, 3)        # i=3


def test_ccm_bad_nonce_len():
    with pytest.raises(ValueError):
        protocols.ccm_counter_blocks(bytes(12), 1, L=2)   # needs 13 bytes


def test_ssh_ctr_increment():
    iv = (5).to_bytes(16, "big")
    B = protocols.ssh_ctr_blocks(iv, 4)
    assert int.from_bytes(bytes(B[0]), "big") == 5
    assert int.from_bytes(bytes(B[3]), "big") == 8      # +1 per block


def test_keystream_is_p_xor_c():
    p = np.random.default_rng(0).integers(0, 256, (10, 16), np.uint8)
    ks = np.random.default_rng(1).integers(0, 256, (10, 16), np.uint8)
    c = p ^ ks
    assert np.array_equal(protocols.keystream_from_observed(p, c), ks)


def test_capture_is_ctr_mode():
    p = np.zeros((4, 16), np.uint8); c = np.zeros((4, 16), np.uint8); t = np.arange(4.0)
    cap = protocols.capture_from_observed(p, c, t)
    assert cap.mode == "ctr" and cap.direction == "enc" and cap.n == 4


# ---- end-to-end recovery ---------------------------------------------------

@pytest.mark.parametrize("proto", ["oscore", "ssh"])
def test_recovery_clean(proto):
    cap = SimulatedProtocolSource(proto, KEY, 40000, sigma=0.0, seed=11).capture()
    rep = attack(cap, verify=(_PT, _CT), key_for_truth=_k)
    assert rep.master_hex == KEY and rep.verified


@pytest.mark.parametrize("proto", ["oscore", "ssh"])
def test_recovery_network_jitter(proto):
    # moderate jitter, no amplification, still recovers with enough traces
    cap = SimulatedProtocolSource(proto, KEY, 80000, sigma=30.0, seed=12).capture()
    rep = attack(cap, verify=(_PT, _CT), key_for_truth=_k)
    assert rep.master_hex == KEY


def test_amplification_crosses_jitter_floor():
    # high jitter fails at K=1 but recovers with in-device amplification (the
    # bootloader-ACK story): K multiplies the signal, not the fixed jitter.
    from flashattack import engine
    truth = aesref.key_expansion(_k)[-1]
    lo = SimulatedProtocolSource("oscore", KEY, 120000, sigma=1500.0, K=1, seed=13).capture()
    hi = SimulatedProtocolSource("oscore", KEY, 120000, sigma=1500.0, K=64, seed=13).capture()
    r_lo = engine.recover(lo.engine_input()[0], lo.timing, direction="enc", truth=truth)
    r_hi = engine.recover(hi.engine_input()[0], hi.timing, direction="enc", truth=truth)
    assert r_lo.truth_correct < 16          # raw high-jitter oracle fails
    assert r_hi.truth_correct == 16         # amplified oracle recovers
