"""Pack an SNMPv3 capture into a small, replayable vector.

    python demos/snmpv3_lwip/host/make_vector.py run.npz \
        --out demos/snmpv3_lwip/vectors/mine.npz --label "my capture"

An `ethtimer --target snmpv3` capture is 100-odd bytes per exchange and tens of
megabytes, and the attack reads two columns of it: the AES output block the
agent's CFB keystream exposes, and the turnaround that encrypting it took.

What the attack reads, in full:

  aes_out    C F B block 2's keystream, which is E(K, C1). This is the AES
             OUTPUT the attacker knows, and the whole attack is a function of
             these bytes and the timing.
  dt         the instrument's turnaround, in its own clock cycles.
  known      ONE (input, output) pair, kept so a candidate key can be settled
             with a single AES block and no secret. The capture holds a pair
             per exchange; the attack needs one, so the rest is dropped.

The key goes in for validation only - `tools/replay.py` prints it beside what
the recovery produced. It is the agent's localized privacy key, a function of
the passphrase and the engine ID, and nothing in the recovery reads it.

BEFORE WRITING ANYTHING this re-encrypts a sample of the capture's own
(input, output) pairs under that key and refuses to write a vector whose pairs
do not reproduce. A vector is a claim that a capture said something; checking
it here is cheaper than discovering later that it did not.
"""
from __future__ import annotations

import argparse

import numpy as np

from flashattack import aesref

SAMPLE = 2000


def pack(args):
    d = np.load(args.file)
    for want in ("keystream2", "ciphertext", "dt_hw", "key"):
        if want not in d:
            raise SystemExit("%s has no %r - is this an ethtimer snmpv3 capture?"
                             % (args.file, want))

    key = bytes(d["key"]) if args.key is None else bytes.fromhex(args.key)
    aes_out = np.asarray(d["keystream2"], np.uint8)       # E(K, C1)
    aes_in = np.asarray(d["ciphertext"], np.uint8)[:, 0:16]   # C1, off the wire
    dt = np.asarray(d["dt_hw"], np.uint32)
    n = int(args.n or len(dt))
    aes_out, aes_in, dt = aes_out[:n], aes_in[:n], dt[:n]

    m = min(SAMPLE, n)
    exp = np.asarray(aesref.encrypt_blocks(key, aes_in[:m]), np.uint8)
    ok = int((exp == aes_out[:m]).all(axis=1).sum())
    if ok != m:
        raise SystemExit("E(K, C1) == keystream2 on only %d of %d sampled "
                         "pairs. Either the key is wrong or this capture is "
                         "not what it says; not writing a vector." % (ok, m))
    distinct = len({bytes(r) for r in aes_in[:m]})
    if distinct != m:
        raise SystemExit("%d of %d sampled AES inputs are distinct. Repeated "
                         "inputs are fewer observations than they look."
                         % (distinct, m))

    np.savez_compressed(
        args.out,
        aes_out=aes_out,
        dt=dt,
        dt_hz=np.int64(d["attacker_hz"]) if "attacker_hz" in d else np.int64(0),
        known_in=aes_in[0],
        known_out=aes_out[0],
        key=np.frombuffer(key, np.uint8),
        n=np.int64(n),
        label=np.str_(args.label),
    )
    print("%s: %d traces, E(K,C1)==ks2 on %d/%d sampled, %d distinct inputs"
          % (args.out, n, ok, m, distinct))


def load_vector(path):
    """(aes_out (n,16), dt (n,), {known pair, key, label})."""
    d = np.load(path, allow_pickle=False)
    meta = {
        "known": (bytes(d["known_in"]), bytes(d["known_out"])),
        "key": bytes(d["key"]),
        "label": str(d["label"]) if "label" in d else "",
        "hz": int(d["dt_hz"]) if "dt_hz" in d else 0,
    }
    return np.asarray(d["aes_out"]), np.asarray(d["dt"]).astype(float), meta


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", help="an ethtimer --target snmpv3 capture")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--n", type=int, default=0, help="keep only the first N")
    ap.add_argument("--key", default=None,
                    help="hex privacy key, if the capture does not carry it")
    pack(ap.parse_args())


if __name__ == "__main__":
    main()
