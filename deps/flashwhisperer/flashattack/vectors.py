"""Captured trace vectors for the long/replay tests.

A vector stores only the per-trace TIMING plus the parameters needed to
regenerate everything else, so it is tiny and git-friendly:
  * material is deterministic from (seed, n) via transport.gen_pts -> not stored;
  * timing is cycle counts, which fit in uint16 here (<~12k) -> np.savez_compressed.

A 150k-trace vector is ~300 KB raw, ~100-200 KB compressed. Load with `load`,
then `replay` reconstructs (known_blocks, direction, verify) and runs the engine.
"""
from __future__ import annotations
import numpy as np
from . import modes, engine, aesref, transport


def save(path, *, seed, n, mode, direction, impl, keysize, key_hex, timing, notes=""):
    t = np.asarray(timing)
    dt = np.uint16 if t.max() < 65535 else np.uint32
    np.savez_compressed(path, seed=np.uint32(seed), n=np.uint32(n), mode=mode,
                        direction=direction, impl=impl, keysize=np.uint16(keysize),
                        key_hex=key_hex, timing=t.astype(dt), notes=notes)


def load(path):
    d = np.load(path, allow_pickle=False)
    return {k: (d[k].item() if d[k].ndim == 0 else d[k]) for k in d.files}


_IVCONST = bytes.fromhex("00112233445566778899aabbccddeeff")


def to_capture(path):
    """Build a key-agnostic Capture (capture.Capture) from a compact vector:
    regenerate the material and derive the OBSERVED plaintext/ciphertext the
    attacker would see. The key is used only to synthesise the observation and is
    NOT stored in the Capture - so the attack runs exactly as on real data."""
    from .capture import Capture
    v = load(path)
    key = bytes.fromhex(v["key_hex"]); n = int(v["n"]); mode = v["mode"]
    keysize = int(v["keysize"]); impl = str(v.get("impl", ""))
    mat = transport.gen_pts(int(v["seed"]), n)
    ls_last, ls_prev = 4, (2 if "ttable" in impl else 4)
    pt = ct = None; iv = None
    if mode == "ecb-enc":
        pt = mat; ct = aesref.encrypt_blocks(key, mat)
    elif mode == "cbc-enc":
        iv = _IVCONST; ct = aesref.encrypt_blocks(key, mat ^ np.frombuffer(iv, np.uint8))
    elif mode == "ctr":
        pt = np.zeros_like(mat); ct = aesref.encrypt_blocks(key, mat)   # keystream=AES(counter)
    elif mode == "ecb-dec":
        pt = aesref.decrypt_blocks(key, mat); ct = mat
    elif mode == "cbc-dec":
        iv = _IVCONST
        pt = aesref.decrypt_blocks(key, mat) ^ np.frombuffer(iv, np.uint8)
    return Capture(timing=v["timing"].astype(float), mode=mode, keysize=keysize,
                   plaintext=pt, ciphertext=ct, iv=iv,
                   line_shift_last=ls_last, line_shift_prev=ls_prev, label=impl)


def replay(path, verify=True):
    """Load a vector and run the engine. Returns the engine Result."""
    v = load(path)
    key = bytes.fromhex(v["key_hex"])
    material = transport.gen_pts(int(v["seed"]), int(v["n"]))
    known, direction = modes.known_output(v["mode"], material, key)
    keysize = int(v["keysize"])
    vp = None
    if verify and keysize == 128:
        pt = bytes(16)
        ct = aesref.encrypt_blocks(key, np.frombuffer(pt, np.uint8)[None, :])[0].tobytes()
        vp = (pt, ct)
    truth = (aesref.key_expansion(key)[-1] if direction == "enc" else aesref.key_expansion(key)[0])
    return engine.recover(known, v["timing"].astype(float), direction=direction,
                          keysize=keysize, verify=vp, truth=truth)
