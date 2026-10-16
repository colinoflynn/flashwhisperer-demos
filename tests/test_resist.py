"""Resistance regression tests: ciphers that this flash-timing channel does NOT
break, verified against real hardware captures in tests/vectors_resist/.

The exploitable condition is a SINGLE-TABLE last round (AES's FSb). These vectors
are counter-examples that must keep failing, so a future engine change cannot
silently start "recovering" a key that is not actually there:

  * ARIA (mbedtls) - SPN with AES's exact last-round form, but its substitution
    layer uses FOUR separate S-box tables (4 of 16 last-round bytes per table). On
    the F429's 128 B data cache those sparse same-table lines evict between lookups,
    so the within-round collision never survives: recover_final_roundkey scores at
    chance even though the cipher's overall timing is data-dependent (std ~= 19.6).

See flashattack/EXPERIMENTAL.md sec.3 and hardware/RESULTS.md for the full analysis.

Run with:  PYTHONPATH=. pytest tests/test_resist.py --runslow
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
import glob
import os
import pytest

pytest.importorskip("numpy")
from flashattack import vectors, transport, aria  # noqa: E402

VEC_DIR = os.path.join(os.path.dirname(__file__), "vectors_resist")


@pytest.mark.slow
def test_aria_resists_last_round_attack():
    path = os.path.join(VEC_DIR, "aria_mbedtls_ecb-enc_128.npz")
    if not os.path.exists(path):
        pytest.skip("no ARIA resistance vector captured")
    v = vectors.load(path)
    key = bytes.fromhex(v["key_hex"])
    mat = transport.gen_pts(int(v["seed"]), int(v["n"]))
    ct = aria.encrypt_blocks(key, mat)
    timing = v["timing"].astype(float)
    # sanity: the capture genuinely has data-dependent timing (the cipher leaks
    # *something* - this is a resistance result, not a dead/constant channel).
    assert timing.std() > 1.0, "expected data-dependent timing in the ARIA capture"
    res = aria.recover_final_roundkey(ct, timing, key_for_truth=key)
    # 4-table last round => no exploitable within-round collision => chance-level.
    # A real recovery would score near 16/16; require well below any partial break.
    assert res["correct"] <= 4, \
        f"ARIA unexpectedly leaked {res['correct']}/16 - single-table assumption broke?"


def test_resist_vectors_not_in_aes_glob():
    """Guard: resistance vectors must NOT sit in tests/vectors/ (the AES replay
    glob asserts FULL recovery and would fail on a cipher that resists)."""
    aes_dir = os.path.join(os.path.dirname(__file__), "vectors")
    stray = [os.path.basename(p) for p in glob.glob(os.path.join(aes_dir, "*.npz"))
             if any(c in os.path.basename(p) for c in ("aria", "camellia", "sm4"))]
    assert not stray, f"resistance vectors leaked into the AES replay glob: {stray}"
