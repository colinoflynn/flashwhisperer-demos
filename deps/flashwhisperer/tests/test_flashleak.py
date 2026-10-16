"""flashleak's conclusions against targets whose answers are known.

The simulator is the point of this file: it leaks from every round, like a real
cipher, and its decryption walks a real InvCipher. Both matter. A one-round
simulator makes the input-vs-output discriminator read ~6 where hardware reads
~1.4, and walking the encryption from the plaintext to model a decryption makes
the target look input-side when it is not - either shortcut would have graded
the detector against a target that flatters it.
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

from flashleak import (SimulatedTarget, assess, fixed_vs_random, determinism,
                       probe)

N = 60_000


def _run(n=N, **kw):
    tgt = SimulatedTarget(seed=1, **kw)
    blocks = np.random.default_rng(0).integers(0, 256, size=(n, 16), dtype=np.uint8)
    timing, seen = tgt.measure_many(blocks)
    return assess(seen, timing, quick=True), tgt


def _answers(res):
    return " | ".join(f.answer for f in res.findings).lower()


def test_constant_time_is_called_out():
    res, _ = _run(n=5000, layout="none", noise=0.0)
    assert "constant time" in _answers(res)


def test_noise_without_a_channel_is_not_called_leakage():
    res, _ = _run(layout="none", noise=3.0)
    a = _answers(res)
    assert "none detected" in a
    assert "cipher input" not in a


def test_input_side_is_identified_and_is_specific():
    """Concentration must fire for the input-side target and not for others --
    that specificity is the whole reason the statistic exists."""
    res, _ = _run(direction="enc", observe="input")
    assert "cipher input" in _answers(res)
    conc = max(res.tests["xor_concentration"].values())
    res2, _ = _run(direction="enc", observe="output")
    conc2 = max(res2.tests["xor_concentration"].values())
    assert conc > conc2 * 2, (conc, conc2)


def test_output_side_does_not_masquerade_as_input():
    """The failure that mattered: falling through to an INPUT verdict when
    nothing actually identified the side."""
    res, _ = _run(direction="enc", observe="output")
    assert "cipher input" not in _answers(res)


@pytest.mark.slow
def test_encrypt_and_decrypt_outputs_are_told_apart():
    for direction, expect in (("enc", "encryption output"),
                              ("dec", "decryption output")):
        tgt = SimulatedTarget(seed=1, direction=direction, observe="output")
        blocks = np.random.default_rng(0).integers(0, 256, size=(150_000, 16),
                                                   dtype=np.uint8)
        timing, seen = tgt.measure_many(blocks)
        assert expect in _answers(assess(seen, timing))


@pytest.mark.slow
def test_four_table_layout_is_recognised():
    tgt = SimulatedTarget(seed=1, direction="enc", observe="output", layout="four")
    blocks = np.random.default_rng(0).integers(0, 256, size=(150_000, 16),
                                               dtype=np.uint8)
    timing, seen = tgt.measure_many(blocks)
    res = assess(seen, timing)
    assert "four separate tables" in _answers(res)
    prof = res.tests["offset_profile"]
    assert min(prof[4], prof[8]) > max(prof[d] for d in prof if d % 4)


def test_decryption_model_walks_a_real_invcipher():
    """If this drifts, the decrypt cases are testing a fiction."""
    from flashattack import aesref
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    tgt = SimulatedTarget(key=key, direction="dec")
    ct = np.random.default_rng(5).integers(0, 256, size=(32, 16), dtype=np.uint8)
    idx = tgt._all_round_indices_dec(ct)
    assert len(idx) == 10
    st = np.asarray(probe.SINV, np.uint8)[idx[-1]] ^ np.frombuffer(
        bytes(tgt._rk[0]), np.uint8)[None, :]
    assert np.array_equal(st, np.asarray(aesref.decrypt_blocks(key, ct), np.uint8))


def test_controlled_probes_separate_leaking_from_clean():
    leaky = SimulatedTarget(seed=2, direction="enc", observe="output")
    clean = SimulatedTarget(seed=2, layout="none", noise=3.0)
    assert fixed_vs_random(leaky, n=4000)["leaking"]
    assert not fixed_vs_random(clean, n=4000)["leaking"]


def test_determinism_reports_a_noiseless_target_as_deterministic():
    assert determinism(SimulatedTarget(seed=3, noise=0.0), trials=30)["deterministic"]
    assert not determinism(SimulatedTarget(seed=3, noise=5.0), trials=30)["deterministic"]


def test_blocks_must_be_16_wide():
    with pytest.raises(ValueError):
        probe.data_dependence(np.zeros((10, 8), np.uint8), np.zeros(10))


# ---- conditioning must not invent structure, or destroy it ---------------
# `condition` splits a capture into transport modes and re-centres each on
# its own median. That is load-bearing on a real network capture and
# actively harmful when the modes are not real: the thing being measured IS
# a shift in the mean of a subset, so re-centring arbitrary subsets removes
# signal. It used to call a clean Gaussian three modes - the body and its
# own two tails - and the real 250 000-trace tinyaes vector nine.

def test_condition_leaves_unimodal_noise_alone():
    """A Gaussian with no cipher anywhere near it is ONE mode."""
    rng = np.random.default_rng(7)
    b = rng.integers(0, 256, size=(20_000, 16), dtype=np.uint8)
    t = rng.normal(1000.0, 3.0, size=20_000)
    _, y, info = probe.condition(b, t)
    assert info["modes"] == 1, info["mode_shares"]
    # and it must not quietly shrink the scale every margin is measured in
    assert y.std() == pytest.approx(info["sigma_raw"], rel=0.02)


def test_condition_still_splits_a_real_transport_mode():
    """The case this function exists for: the SNMPv3 capture's two modes are
    ~1480 apart with a within-mode sigma of ~59. If a share-and-separation
    rule ever merges those, conditioning has stopped doing its job and every
    statistic downstream reads zero again."""
    rng = np.random.default_rng(8)
    b = rng.integers(0, 256, size=(20_000, 16), dtype=np.uint8)
    t = np.concatenate([rng.normal(0, 59, 10_000),
                        rng.normal(1480, 59, 10_000)])
    _, y, info = probe.condition(b, t[rng.permutation(20_000)])
    assert info["modes"] == 2, info["mode_shares"]
    assert y.std() < 100          # pooled would be ~740


def test_output_shift_scan_finds_the_row_width_the_target_uses():
    """The output-side row width was a hardcoded 2 until this was measured.
    `SimulatedTarget` models a 16-byte row of 1-byte entries, so 4 is the
    right answer; scoring the same capture at 2 cost an order of magnitude
    and read as a target that does not leak."""
    tgt = SimulatedTarget(seed=1, direction="enc", observe="output",
                          layout="four")
    blocks = np.random.default_rng(0).integers(0, 256, size=(20_000, 16),
                                               dtype=np.uint8)
    timing, seen = tgt.measure_many(blocks)
    best, scan = probe.output_shift_scan(seen, timing, seed=0)
    assert best == tgt.line_shift, scan
    assert scan[best] > scan[2], scan


@pytest.mark.slow
def test_output_shift_scan_needs_the_traces_not_the_pairs():
    """The regression that cost a round: the scan used to cap itself at
    50 000 traces on the grounds that ranking is cheaper than scoring. It
    is not. On this capture the full test reads 1:+6.1 2:+21.7 3:+24.4
    4:+39.5, and every capped budget - 4, 8 and even 12 pairs - ranked it
    wrong, while 4 pairs on all the traces got it right."""
    import os
    from flashattack import modes, transport
    p = os.path.join(os.path.dirname(__file__), "vectors",
                     "sbox_tinyaes_ecb-enc_128.npz")
    if not os.path.isfile(p):
        pytest.skip("vector not present")
    d = np.load(p)
    key = bytes.fromhex(str(d["key_hex"]))
    material = transport.gen_pts(int(d["seed"]), int(d["n"]))
    ct, _ = modes.known_output(str(d["mode"]), material, key)
    blocks = np.asarray(ct, np.uint8)
    timing = d["timing"].astype(float)

    best, scan = probe.output_shift_scan(blocks, timing, seed=0)
    assert best == 4, scan
    capped, cscan = probe.output_shift_scan(blocks, timing, max_traces=50_000,
                                            seed=0)
    assert capped != 4, (
        "the 50k cap used to get this wrong; if it now gets it right the "
        "comment above and the docstring's table need revisiting, not this "
        "assertion deleting")
