"""Reference AES (128/192/256), vectorized over N blocks, plus key-schedule
inversion. Pure NumPy; the attack engine uses this to (a) compute the known
block-cipher output per mode and (b) invert a recovered round key to the master
key. State byte order j = row + 4*col (column-major), matching flashsim.

This is the single source of AES truth for the host tooling - verified against
FIPS-197 in tests/.
"""
from __future__ import annotations
import numpy as np

# --- GF(2^8) and the S-box (self-contained; no flashsim dependency) ---------
def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p & 0xFF

def _build_sbox():
    p = q = 1
    sbox = [0] * 256
    while True:                      # generate using the affine transform over the multiplicative inverse
        p = (p ^ _xtime(p)) & 0xFF
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xf = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xf ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return np.array(sbox, dtype=np.uint8)

SBOX = _build_sbox()
SINV = np.zeros(256, dtype=np.uint8)
for _x in range(256):
    SINV[int(SBOX[_x])] = _x

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d]
# ShiftRows permutation on state indices (row + 4*col), and its inverse
_SR = np.array([(r + 4 * ((c + r) % 4)) for c in range(4) for r in range(4)], dtype=np.intp)
# Build column-major ShiftRows the same way flashsim does: state[:, _SR]
_SHIFT_ROWS = np.array([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11], dtype=np.intp)
_ISR = np.argsort(_SHIFT_ROWS)
_MT = {c: np.array([_gf_mul(c, x) for x in range(256)], dtype=np.uint8) for c in (2, 3, 9, 11, 13, 14)}


def key_expansion(key: bytes) -> np.ndarray:
    """Return round keys as (Nr+1, 16) uint8. Supports 16/24/32-byte keys."""
    Nk = len(key) // 4
    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    words = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, 4 * (Nr + 1)):
        t = list(words[i - 1])
        if i % Nk == 0:
            t = t[1:] + t[:1]
            t = [int(SBOX[b]) for b in t]
            t[0] ^= _RCON[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            t = [int(SBOX[b]) for b in t]
        words.append([words[i - Nk][j] ^ t[j] for j in range(4)])
    flat = bytes(b for w in words for b in w)
    return np.frombuffer(flat, dtype=np.uint8).reshape(Nr + 1, 16).copy()


def _mix(state, inv):
    s = state.reshape(-1, 4, 4)
    out = np.empty_like(s)
    a0, a1, a2, a3 = s[:, :, 0], s[:, :, 1], s[:, :, 2], s[:, :, 3]
    if not inv:
        out[:, :, 0] = _MT[2][a0] ^ _MT[3][a1] ^ a2 ^ a3
        out[:, :, 1] = a0 ^ _MT[2][a1] ^ _MT[3][a2] ^ a3
        out[:, :, 2] = a0 ^ a1 ^ _MT[2][a2] ^ _MT[3][a3]
        out[:, :, 3] = _MT[3][a0] ^ a1 ^ a2 ^ _MT[2][a3]
    else:
        out[:, :, 0] = _MT[14][a0] ^ _MT[11][a1] ^ _MT[13][a2] ^ _MT[9][a3]
        out[:, :, 1] = _MT[9][a0] ^ _MT[14][a1] ^ _MT[11][a2] ^ _MT[13][a3]
        out[:, :, 2] = _MT[13][a0] ^ _MT[9][a1] ^ _MT[14][a2] ^ _MT[11][a3]
        out[:, :, 3] = _MT[11][a0] ^ _MT[13][a1] ^ _MT[9][a2] ^ _MT[14][a3]
    return out.reshape(state.shape)


def encrypt_blocks_rk(rk, blocks: np.ndarray) -> np.ndarray:
    """AES encrypt from ROUND KEYS rather than a master key.

    `rk` is (Nr+1, 16) uint8, as `key_expansion` returns. Separated out because
    a recovery has round keys in hand before it has a master - the last-round
    attack recovers rk[Nr], and verifying a candidate rk[Nr-1] against a known
    pair needs this and not `encrypt_blocks`. `hardware/aes_ref.py`'s
    `encrypt(key, block, rk=...)` is this function with a bytes interface.
    """
    rk = np.asarray(rk, np.uint8).reshape(-1, 16)
    Nr = rk.shape[0] - 1
    st = np.asarray(blocks, np.uint8).reshape(-1, 16) ^ rk[0]
    for r in range(1, Nr):
        st = SBOX[st][:, _SHIFT_ROWS]
        st = _mix(st, False) ^ rk[r]
    return SBOX[st][:, _SHIFT_ROWS] ^ rk[Nr]


def decrypt_blocks_rk(rk, blocks: np.ndarray) -> np.ndarray:
    """AES InvCipher from ROUND KEYS rather than a master key. See above."""
    rk = np.asarray(rk, np.uint8).reshape(-1, 16)
    Nr = rk.shape[0] - 1
    st = np.asarray(blocks, np.uint8).reshape(-1, 16) ^ rk[Nr]
    for r in range(Nr - 1, 0, -1):
        st = SINV[st[:, _ISR]] ^ rk[r]
        st = _mix(st, True)
    return SINV[st[:, _ISR]] ^ rk[0]


def encrypt_blocks(key: bytes, blocks: np.ndarray) -> np.ndarray:
    return encrypt_blocks_rk(key_expansion(key), blocks)


def decrypt_blocks(key: bytes, blocks: np.ndarray) -> np.ndarray:
    return decrypt_blocks_rk(key_expansion(key), blocks)


def invert_key_schedule(final_words, keysize=128):
    """Given the LAST Nk 32-bit words of the schedule (as a flat list of 4*Nk
    bytes, column-major), run the expansion backwards to the master key.

    For AES-128 the last round key (16 bytes = 4 words) is exactly the last Nk=4
    words, so a single recovered round key suffices. For 192/256 the last Nk
    words span the last 1.5 / 2 round keys, so multi-round-key recovery is needed
    (see engine.recover_multi). Raises if too few words are supplied.
    """
    Nk = keysize // 32
    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    total = 4 * (Nr + 1)
    need = 4 * Nk
    if len(final_words) != need:
        raise ValueError(f"need {need} bytes ({Nk} words) for AES-{keysize}, got {len(final_words)}")
    W = [None] * total
    fw = [int(x) & 0xFF for x in final_words]
    for i in range(Nk):
        W[total - Nk + i] = (fw[4*i] << 24) | (fw[4*i+1] << 16) | (fw[4*i+2] << 8) | fw[4*i+3]
    for i in range(total - 1, Nk - 1, -1):
        if W[i] is None or W[i - Nk] is not None:
            continue
        prev = W[i - 1]
        if i % Nk == 0:
            rw = ((prev << 8) | (prev >> 24)) & 0xFFFFFFFF
            sw = (int(SBOX[(rw>>24)&255])<<24)|(int(SBOX[(rw>>16)&255])<<16)|(int(SBOX[(rw>>8)&255])<<8)|int(SBOX[rw&255])
            W[i - Nk] = W[i] ^ sw ^ (_RCON[i // Nk - 1] << 24)
        elif Nk > 6 and i % Nk == 4:
            sw = (int(SBOX[(prev>>24)&255])<<24)|(int(SBOX[(prev>>16)&255])<<16)|(int(SBOX[(prev>>8)&255])<<8)|int(SBOX[prev&255])
            W[i - Nk] = W[i] ^ sw
        else:
            W[i - Nk] = W[i] ^ prev
    out = bytearray()
    for i in range(Nk):
        out += bytes([(W[i]>>24)&255, (W[i]>>16)&255, (W[i]>>8)&255, W[i]&255])
    return bytes(out)


def invert_from_roundkeys(round_keys, keysize=128):
    """Recover the master key from recovered round keys.

    round_keys : dict {round_index: 16 bytes}. The master needs the LAST Nk words
    of the schedule; for AES-128 that is the single last round key (Nk=4), for
    192/256 it spans the last two round keys (Nk=6/8). Provide enough consecutive
    round keys to cover the last Nk words, else ValueError.
    """
    Nk = keysize // 32
    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    total = 4 * (Nr + 1)
    words = {}
    for ridx, rk in round_keys.items():
        rk = [int(b) & 0xFF for b in rk]
        for w in range(4):
            words[4 * ridx + w] = rk[4 * w:4 * w + 4]
    needed = range(total - Nk, total)
    missing = [w for w in needed if w not in words]
    if missing:
        raise ValueError(f"AES-{keysize} master needs schedule words {list(needed)}; "
                         f"missing {missing} - supply the last {Nk//4 if Nk%4==0 else 2} round keys "
                         f"(rounds {(total-Nk)//4}..{Nr})")
    final = [b for w in needed for b in words[w]]
    return invert_key_schedule(final, keysize)
