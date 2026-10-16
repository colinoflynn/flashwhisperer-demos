"""Pack a half-gigabyte listener log into a few megabytes that still recover.

The raw capture is 187 bytes of text per frame and 2.6 million frames, which is
no use to a repository. Almost none of it is irreducible. The AES output block
the attack reads is `AES(K, A_1)`, and `A_1` is built entirely out of the frame
counter, the source EUI-64 and the security level - so given the key and the
frame counters, every block regenerates EXACTLY, and this refuses to write a
vector whose blocks do not come back byte for byte.

What is left is the measured turnaround, one number per frame, and the frame
counter, which is nearly consecutive and stores as a small delta. That is the
whole vector.

    python demos/ota_802154/host/make_vector.py passive_newkey.log \\
        --out demos/ota_802154/vectors/f401_blind_2500k.npz \\
        --key deadbeefcafeface1133710551223945 --listener-hz 32e6 \\
        --label "blind key, L152RE listener"

WHAT THIS DOES NOT CHECK
  * That the log came off the rig it says. Nothing in the file records which
    boards were on the bench; the json beside the vector does, from notes.
  * The row offset. That is a property of the victim's IMAGE and has to be read
    off the ELF - two builds of these sources landed on 4 and 12. It goes in
    the json, and `--line-off` here only writes it down.
  * That the key is the victim's. If it is not, the regeneration check fails
    and nothing is written, which is the useful direction: a vector that packs
    is a vector whose key is right.
"""
from __future__ import annotations

import argparse
import sys

import numpy as np

from flashattack import aesref

try:
    from . import frames, logread
except ImportError:                      # run as a script, no package context
    import frames, logread


def pack(args):
    rec = logread.read_log(args.file, limit=args.limit, skip=args.skip)
    gap, fc = rec["gap"], rec["frame_counter"]
    key = bytes.fromhex(args.key)

    a1 = frames.counter_blocks(rec["src"], rec["sec_level"], fc)
    ks = frames.keystream_from_payload(rec["payload"])
    regen = np.asarray(aesref.encrypt_blocks(key, a1), np.uint8)
    bad = (regen != ks).any(axis=1)
    nbad = int(bad.sum())
    # A record whose block does not regenerate is a CORRUPTED LOG LINE rather
    # than a cipher mystery: the listener's console runs at 921600 over USB
    # CDC, and two lines in 2.6 million came through with a flipped nibble and
    # a torn field respectively. Keeping them would pair a real timing with a
    # block the victim never produced. Dropping them cannot hide a wrong key or
    # a wrong nonce layout, because then essentially EVERY record fails - which
    # is what the tolerance is for.
    tol = max(16, len(ks) // 10000)
    if nbad > tol:
        sys.exit("%d of %d blocks do not regenerate from this key and counter "
                 "block, over a tolerance of %d - refusing to pack. Either the "
                 "key is wrong or the nonce layout is not the one frames.py "
                 "builds." % (nbad, len(ks), tol))
    if nbad:
        print("  dropped %d of %d records whose block does not regenerate "
              "(corrupt log lines)" % (nbad, len(ks)))
        good = ~bad
        gap, fc = gap[good], fc[good]

    d = np.diff(fc)
    if d.min() < 1:
        sys.exit("frame counters are not increasing (min step %d); this packing "
                 "assumes one capture of one link" % int(d.min()))
    if d.max() > 0xFFFF:
        sys.exit("a frame-counter step of %d does not fit the uint16 deltas "
                 "this packing uses" % int(d.max()))

    out = dict(
        key=np.frombuffer(key, np.uint8),
        src=np.frombuffer(rec["src"], np.uint8),
        sec_level=np.uint8(rec["sec_level"]),
        fc0=np.int64(fc[0]),
        fc_delta=d.astype(np.uint16),
        gap=(gap - gap.min()).astype(np.uint32),
        gap_base=np.int64(gap.min()),
        listener_hz=np.int64(float(args.listener_hz)),
        frame_len=np.uint8(rec["frame_len"]),
        ct_off=np.uint8(rec["ct_off"]),
        n=np.int64(len(gap)),
        label=np.array(args.label),
    )
    np.savez_compressed(args.out, **out)
    med = float(np.median(gap))
    print("packed %d frames -> %s" % (len(gap), args.out))
    print("  every AES output block regenerates from the key and A_1")
    print("  median turnaround %.0f listener cycles (%.1f us at %.3g MHz)"
          % (med, med / (float(args.listener_hz) / 1e6),
             float(args.listener_hz) / 1e6))
    print("  frame counters %d..%d, %d steps larger than one"
          % (int(fc[0]), int(fc[-1]), int((d > 1).sum())))


def load_vector(path):
    """(AES output blocks, raw turnaround, label, listener Hz) from a vector."""
    d = np.load(path, allow_pickle=False)
    fc = np.empty(int(d["n"]), np.int64)
    fc[0] = int(d["fc0"])
    np.cumsum(d["fc_delta"].astype(np.int64), out=fc[1:])
    fc[1:] += fc[0]
    a1 = frames.counter_blocks(bytes(d["src"]), int(d["sec_level"]), fc)
    ct = np.asarray(aesref.encrypt_blocks(bytes(d["key"]), a1), np.uint8)
    gap = d["gap"].astype(np.int64) + int(d["gap_base"])
    return ct, gap, (str(d["label"]) if "label" in d else ""), int(d["listener_hz"])


def known_pair(path, index=0):
    """One (AES input, AES output) pair from the vector, as the wire gave it.

    The input is the counter block, which the frame carries in the clear, and
    the output is the keystream, which is the payload XOR the known plaintext.
    Nothing in either is secret, which is what lets the search verify a
    candidate and still be an attack rather than a rehearsal.

    Say the obvious thing about it though: this regenerates the pair from the
    key, for exactly the reason the vector regenerates every other block, so
    the pair in a replay comes out of the file rather than off the air.
    `frames.verification_pairs()` is the same pair read straight out of a raw
    log with no key involved, and that is what the capture that recovered this
    key actually used. The two agree by construction.
    """
    d = np.load(path, allow_pickle=False)
    fc = int(d["fc0"]) + (0 if index == 0
                          else int(d["fc_delta"][:index].astype(np.int64).sum()))
    a1 = frames.counter_blocks(bytes(d["src"]), int(d["sec_level"]), [fc])
    ks = np.asarray(aesref.encrypt_blocks(bytes(d["key"]), a1), np.uint8)[0]
    return bytes(a1[0]), bytes(ks)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", help="a listener log")
    ap.add_argument("--out", required=True)
    ap.add_argument("--key", required=True,
                    help="the link key, 32 hex chars. The blocks regenerate "
                         "from it and the packer fails if it is wrong")
    ap.add_argument("--label", default="")
    ap.add_argument("--limit", type=int, help="frames to keep, after --skip")
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--listener-hz", default=32e6,
                    help="the LISTENER's core clock, which is what the "
                         "turnaround is counted in (32e6 for the L152RE)")
    pack(ap.parse_args())


if __name__ == "__main__":
    main()
