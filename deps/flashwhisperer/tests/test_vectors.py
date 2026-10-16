"""Replay captured hardware trace vectors through the engine (long test).

Run with:  PYTHONPATH=. pytest tests/test_vectors.py --runslow
Each tests/vectors/*.npz is a real capture (S-box or T-table, various key sizes
and modes). Success criterion:
  * AES-128  -> full master key recovered and verified;
  * AES-192/256 -> the last round key recovered 16/16 (full master needs the
    second round key - see docs).
"""

# No sys.path walk: the packages sit at the repository root here.
import glob
import os
import pytest

pytest.importorskip("numpy")
import numpy as np  # noqa: E402
from flashattack import vectors, engine, modes, aesref, transport  # noqa: E402

VEC_DIR = os.path.join(os.path.dirname(__file__), "vectors")
VEC_FILES = sorted(glob.glob(os.path.join(VEC_DIR, "*.npz")))


@pytest.mark.slow
@pytest.mark.skipif(not VEC_FILES, reason="no captured vectors in tests/vectors/")
@pytest.mark.parametrize("path", VEC_FILES, ids=[os.path.basename(p) for p in VEC_FILES])
def test_replay_vector(path):
    meta = vectors.load(path)
    key = bytes.fromhex(meta["key_hex"])
    keysize = int(meta["keysize"])
    if keysize == 128:
        res = vectors.replay(path, verify=True)   # last round key -> master (+ brute-force)
        assert res.verified and res.master == key, \
            f"{os.path.basename(path)}: master not recovered ({res.truth_correct}/16 assembled)"
    else:
        # 192/256: full master via last + second-to-last round key (MixColumns-linearity).
        material = transport.gen_pts(int(meta["seed"]), int(meta["n"]))
        ct, direction = modes.known_output(meta["mode"], material, key)
        assert direction == "enc"
        prev_shift = 2 if "ttable" in str(meta["impl"]) else 4    # round Nr-1 table granularity
        pt = bytes(16)
        ctk = aesref.encrypt_blocks(key, np.frombuffer(pt, np.uint8)[None, :])[0].tobytes()
        r = engine.recover_full(ct, meta["timing"].astype(float), keysize=keysize,
                                line_shift_last=4, line_shift_prev=prev_shift,
                                verify=(pt, ctk), key_for_truth=key)
        assert r["master"] == key and r["verified"], \
            f"{os.path.basename(path)}: master not recovered (round keys {r['correct']})"
