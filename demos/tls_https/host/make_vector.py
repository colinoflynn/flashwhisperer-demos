"""Pack an HTTPS/TLS capture into a replayable vector.

    python demos/tls_https/host/make_vector.py run.npz \
        --out demos/tls_https/vectors/mine.npz --n 50000 --label "my capture"

This is the largest vector in the repository and there is a reason it cannot be
small. A TLS 1.2 CBC record is `IV || C_1 .. C_n`, so every block of known
plaintext is another `(input, output)` pair covered by the same measured
turnaround:

    AES in  = P_i ^ C_(i-1)        (C_0 is the explicit IV, in clear)
    AES out = C_i

Fifteen of those per exchange, since the response is 255 bytes of known HTTP.
Using all fifteen rather than the first is the difference between a 13-hour
capture and a 50-minute one - but it also means the attack's traces are
ciphertext BLOCKS, and a recovery needs of order a million of them. Ciphertext
does not compress, so a vector that recovers is tens of megabytes however it is
stored. What this does keep out is everything the attack does not read: the
response window's header bytes, the second timing column, the sequence numbers
and the per-exchange IV beyond the first.

  blocks_out  C_1 .. C_15 per exchange - the AES OUTPUT blocks, which is what
              the attack scores.
  dt          one turnaround per exchange, in the instrument's clock cycles.
              The replay tiles it across the fifteen blocks, because that one
              measurement covers all of them.
  known       ONE (input, output) pair, so a candidate key is settled by a
              single AES block with nothing secret.

BEFORE WRITING ANYTHING this re-encrypts a sample of blocks under the recorded
key and refuses to write a vector whose blocks do not reproduce.
"""
from __future__ import annotations

import argparse

import numpy as np

from flashattack import aesref

SAMPLE = 500          # exchanges, so 15x this many blocks are checked


def pack(args):
    d = np.load(args.file)
    for want in ("window", "plaintext", "dt_hw"):
        if want not in d:
            raise SystemExit("%s has no %r - is this an ethtimer tls capture?"
                             % (args.file, want))
    key = (bytes(d["server_write_key"]) if args.key is None
           else bytes.fromhex(args.key))
    if len(key) != 16:
        raise SystemExit("no 16-byte server write key in the capture; pass --key")

    w = np.asarray(d["window"], np.uint8)
    pt = bytes(d["plaintext"])
    nblk = int(d["blocks"]) if "blocks" in d else (w.shape[1] // 16 - 1)
    dt = np.asarray(d["dt_hw"], np.uint32)
    n = int(args.n or len(dt))
    w, dt = w[:n], dt[:n]

    outs = np.stack([w[:, i * 16:(i + 1) * 16] for i in range(1, nblk + 1)], 1)
    ins = np.stack([w[:, (i - 1) * 16:i * 16]
                    ^ np.frombuffer(pt[(i - 1) * 16:i * 16], np.uint8)[None, :]
                    for i in range(1, nblk + 1)], 1)

    m = min(SAMPLE, n)
    exp = np.asarray(aesref.encrypt_blocks(key, ins[:m].reshape(-1, 16)), np.uint8)
    got = outs[:m].reshape(-1, 16)
    ok = int((exp == got).all(axis=1).sum())
    if ok != len(got):
        raise SystemExit("E(K, P^C_prev) == C on only %d of %d sampled blocks. "
                         "Either the key is wrong or the plaintext assumption "
                         "is; not writing a vector." % (ok, len(got)))

    np.savez_compressed(
        args.out,
        blocks_out=outs,
        dt=dt,
        dt_hz=np.int64(d["attacker_hz"]) if "attacker_hz" in d else np.int64(0),
        blocks=np.int64(nblk),
        known_in=ins[0, 0],
        known_out=outs[0, 0],
        key=np.frombuffer(key, np.uint8),
        n=np.int64(n),
        label=np.str_(args.label),
    )
    print("%s: %d exchanges x %d blocks, E(K,in)==out on %d/%d sampled blocks"
          % (args.out, n, nblk, ok, len(got)))


def load_vector(path):
    """(blocks_out (n,15,16), dt (n,), {blocks, known, key, label})."""
    d = np.load(path, allow_pickle=False)
    meta = {
        "blocks": int(d["blocks"]),
        "known": (bytes(d["known_in"]), bytes(d["known_out"])),
        "key": bytes(d["key"]),
        "label": str(d["label"]) if "label" in d else "",
        "hz": int(d["dt_hz"]) if "dt_hz" in d else 0,
    }
    return np.asarray(d["blocks_out"]), np.asarray(d["dt"]).astype(float), meta


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file", help="an ethtimer --target tls capture")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="")
    ap.add_argument("--n", type=int, default=0, help="keep only the first N exchanges")
    ap.add_argument("--key", default=None, help="hex server write key")
    pack(ap.parse_args())


if __name__ == "__main__":
    main()
