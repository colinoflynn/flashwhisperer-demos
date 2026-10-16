"""Pack a PIC32MZ cipher-probe capture into a replayable vector.

    python demos/snmpv3_harmony/host/make_vector.py probe.npz \
        --out demos/snmpv3_harmony/vectors/mine.npz --label "..."

This demo's oracle is not a network turnaround. The victim is Microchip's
Harmony 3 SNMPv3 agent on a PIC32MZ EF, and the probe reads **CP0 Count around
`wc_AesCfbEncrypt` itself**, so the timing column is the cipher's own cycles and
not a reply time. That is deliberate: the wire-level measurement on this part is
a null on the shipped build, and the only way to tell "the cipher does not leak"
from "the leak is swamped on the way out" is to put a clock on the cipher and
difference the two. Both vectors here are that clock.

Two things about this probe that are results rather than details, and both are
in the demo README:

  Interrupts must be masked while it counts. With them on, ISRs landing inside
  the measured window added 27 percent to the median and 300 times the
  variance, and that contamination is not shared with the reply - it made the
  cipher look uncorrelated with the wire when it is not.

  The trace unit is not an exchange. Harmony derives its privacy salt from the
  clock, so identical AES inputs repeat in runs of about five, and on the wire
  one trace costs 5.07 exchanges.

What the attack reads:

  aes_out   CFB block 2's keystream, which is E(K, C1) - the AES output.
  dt        CP0 ticks across the AES call.
  known     one (input, output) pair: C1 is on the wire and block 2's keystream
            is the plaintext XOR the ciphertext, so a candidate key is settled
            by one AES block and nothing secret. The campaign's first attempt
            at this verified against BLOCK 1, whose input is the IV and never
            appears on the wire, so every candidate failed including the right
            one and the run was indistinguishable from a null. Hence the check
            below.
"""
from __future__ import annotations

import argparse

import numpy as np

from flashattack import aesref

SAMPLE = 2000


def pack(args):
    d = np.load(args.file)
    for want in ("keystream2", "ciphertext", "key"):
        if want not in d:
            raise SystemExit("%s has no %r - is this a Harmony probe capture?"
                             % (args.file, want))
    col = args.column if args.column in d else ("aes_tick" if "aes_tick" in d else "cyc")
    if col not in d:
        raise SystemExit("%s has no timing column (tried %s, aes_tick, cyc)"
                         % (args.file, args.column))

    key = bytes(d["key"]) if args.key is None else bytes.fromhex(args.key)
    aes_out = np.asarray(d["keystream2"], np.uint8)
    aes_in = np.asarray(d["ciphertext"], np.uint8)[:, 0:16]
    dt = np.asarray(d[col], np.int64)
    n = int(args.n or len(dt))
    aes_out, aes_in, dt = aes_out[:n], aes_in[:n], dt[:n]

    m = min(SAMPLE, n)
    exp = np.asarray(aesref.encrypt_blocks(key, aes_in[:m]), np.uint8)
    ok = int((exp == aes_out[:m]).all(axis=1).sum())
    if ok != m:
        raise SystemExit("E(K, C1) == keystream2 on only %d of %d sampled "
                         "pairs. This is the block-1 trap if it is 0 of %d: "
                         "block 1's input is the IV and is not on the wire. "
                         "Not writing a vector." % (ok, m, m))
    runs = m - int(np.sum([bytes(aes_in[i]) != bytes(aes_in[i - 1])
                           for i in range(1, m)]))
    np.savez_compressed(
        args.out,
        aes_out=aes_out,
        dt=dt.astype(np.int64),
        dt_unit=np.str_(col),
        known_in=aes_in[0],
        known_out=aes_out[0],
        key=np.frombuffer(key, np.uint8),
        n=np.int64(n),
        label=np.str_(args.label),
    )
    print("%s: %d traces from %s, E(K,C1)==ks2 on %d/%d sampled, "
          "%d repeated inputs in the sample (the IV runs)"
          % (args.out, n, col, ok, m, runs))


def load_vector(path):
    """(aes_out (n,16), dt (n,), {known pair, key, label, unit})."""
    d = np.load(path, allow_pickle=False)
    meta = {
        "known": (bytes(d["known_in"]), bytes(d["known_out"])),
        "key": bytes(d["key"]),
        "label": str(d["label"]) if "label" in d else "",
        "unit": str(d["dt_unit"]) if "dt_unit" in d else "",
    }
    return np.asarray(d["aes_out"]), np.asarray(d["dt"]).astype(float), meta


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", help="a Harmony cipher-probe capture")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--n", type=int, default=0)
    ap.add_argument("--column", default="aes_tick",
                    help="which timing column is the cipher's own clock")
    ap.add_argument("--key", default=None)
    pack(ap.parse_args())


if __name__ == "__main__":
    main()
