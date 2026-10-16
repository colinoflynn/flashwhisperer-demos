"""Pack a captured run into a small, replayable vector.

A raw capture is 28 bytes per exchange and an 11 MB file, which is no use to a
repository. Almost all of it is redundant: every keystream block is
`E(K, A_1(PIV))` for consecutive Partial IVs, so given the key, the Common IV and
the first PIV the whole sequence regenerates **exactly** — verified byte for byte
before anything is written. Only the measured timing is irreducible, and as
offsets from its own minimum it compresses to well under a megabyte.

This is the same trick `flashattack/vectors.py` uses for the UART captures: keep
the timing, regenerate the material. It lets the network result be re-run, and
re-argued, on a machine with no boards attached.

    python demos/oscore_coap/host/make_vector.py run.npz --out demos/oscore_coap/vectors/f429.npz \\
        --label "F429 victim, standard build" --key ffb14e09...
"""
from __future__ import annotations

import argparse
import sys

import numpy as np

from flashattack import aesref          # noqa: E402
# Run as a script from a shell, and imported as `demos.<demo>.host.make_vector`
# by the driver. The first spelling has no package context and the second
# needs one, so both are tried - and the package one comes first, because a
# bare `import verify` inside a package would find whichever demo got
# imported first and silently hand over the wrong module.
try:
    from . import verify
except ImportError:
    import verify

DEFAULT_KEY = "ffb14e093c94c9cac9471648b4f98710"   # RFC 8613 C.1 server sender key
DEFAULT_CIV = "4622d4dd6d944168eefb54987c"


def counter_block(civ: bytes, piv: int) -> np.ndarray:
    """CCM A_1 for an OSCORE response: 0x01 | (Common IV ^ nonce frame) | 0x0001."""
    nonce = np.frombuffer(civ, np.uint8) ^ np.frombuffer(verify.nonce_frame(piv), np.uint8)
    blk = np.zeros(16, np.uint8)
    blk[0] = 0x01
    blk[1:14] = nonce
    blk[15] = 0x01
    return blk


def keystreams(key: bytes, civ: bytes, piv0: int, n: int) -> np.ndarray:
    blocks = np.stack([counter_block(civ, piv0 + i) for i in range(n)])
    return np.asarray(aesref.encrypt_blocks(key, blocks), np.uint8)


def pack(args):
    d = np.load(args.file)
    ks = d["keystream"]
    key = bytes.fromhex(args.key)
    civ = bytes.fromhex(args.civ)

    a = verify.counter_blocks(key, ks)
    if not (np.all(a[:, 0] == 1) and np.all(a[:, 14] == 0) and np.all(a[:, 15] == 1)):
        sys.exit("these keystreams are not CCM counter blocks under that key")
    low = np.array([int.from_bytes(bytes(r[9:14]), "big") for r in a], dtype=np.int64)
    piv = low ^ int.from_bytes(civ[8:], "big")
    if not np.all(np.diff(piv) == 1):
        sys.exit(f"Partial IVs are not consecutive ({int((np.diff(piv)!=1).sum())} gaps) "
                 "-- this packing assumes an unbroken run")
    piv0 = int(piv[0])

    regen = keystreams(key, civ, piv0, len(ks))
    if not np.array_equal(regen, ks):
        sys.exit("regenerated keystreams differ from the capture -- refusing to pack")

    out = {}
    for col in ("dt_hw", "dt_sw", "dwt"):
        if col not in d:
            continue
        t = d[col].astype(np.int64)
        if not t.any():
            continue
        out[col] = (t - t.min()).astype(np.uint32)
        out[col + "_base"] = np.int64(t.min())

    # Carry the instrument's clock forward. The timing columns are counts of
    # the attacker board's own cycles, so a vector without this is a vector of
    # numbers that cannot be turned into seconds -- and the first version of
    # this packer dropped it, which left `analyse.py` guessing a board from a
    # hard-coded default. `analyse.py:instrument_hz` now refuses to guess, so
    # the key has to be here.
    hz = args.attacker_hz
    if hz is None:
        for cand in ("attacker_hz", "instrument_hz", "clock_hz"):
            if cand in d:
                hz = float(np.ravel(d[cand])[0])
                break
    if hz is None:
        sys.exit(f"{args.file}: no attacker_hz / instrument_hz / clock_hz in the "
                 "capture, so the packed vector could not say what clock its "
                 "timing is counted in. Pass --attacker-hz with the instrument "
                 "board's core clock (the OSCORE attacker is 216e6).")

    np.savez_compressed(args.out, key=np.frombuffer(key, np.uint8),
                        common_iv=np.frombuffer(civ, np.uint8),
                        piv0=np.int64(piv0), n=np.int64(len(ks)),
                        attacker_hz=np.int64(hz),
                        label=np.array(args.label), **out)
    print(f"packed {len(ks)} traces -> {args.out}")
    print(f"  keystreams regenerate exactly from key/common IV/PIV {piv0}")
    print(f"  columns: {', '.join(k for k in out if not k.endswith('_base'))}")
    print(f"  instrument clock: {hz/1e6:.6g} MHz")


def load_vector(path):
    """(keystream (n,16), {column: timing}) from a packed vector."""
    d = np.load(path, allow_pickle=False)
    key = bytes(d["key"]); civ = bytes(d["common_iv"])
    n = int(d["n"]); piv0 = int(d["piv0"])
    ks = keystreams(key, civ, piv0, n)
    cols = {k: d[k].astype(np.int64) + int(d[k + "_base"])
            for k in ("dt_hw", "dt_sw", "dwt") if k in d}
    return ks, cols, str(d["label"]) if "label" in d else ""


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--key", default=DEFAULT_KEY)
    ap.add_argument("--civ", default=DEFAULT_CIV)
    ap.add_argument("--attacker-hz", type=float, default=None,
                    help="instrument core clock in Hz; default is to read "
                         "it from the capture, which is where it should be")
    pack(ap.parse_args())


if __name__ == "__main__":
    main()
