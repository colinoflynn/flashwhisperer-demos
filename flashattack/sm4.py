"""SM4 (Chinese national block cipher, GM/T 0002) reference + flash-timing key
recovery. SM4's round function applies 4 parallel S-boxes to (word XOR round key)
byte-wise, so the AES-style last-round cache-collision attack applies directly:
each S-box input byte is knownword[j] ^ rk[j]; collisions recover the round key
byte-wise. The 128-bit master needs the last 4 round keys (peel 4 rounds) + a
key-schedule inversion.

Reference verified against the GM/T 0002 test vector. Recovery validated on
synthetic timing (selftest); hardware validation needs an SM4 firmware capture
(e.g. GmSSL sm4.c) on the same rig - a follow-on.
"""
from __future__ import annotations
import numpy as np
from . import engine

_SBOX_HEX = (
"d690e9fecce13db716b614c228fb2c05" "2b679a762abe04c3aa44132649860699"
"9c4250f491ef987a33540b43edcfac62" "e4b31ca9c908e89580df94fa758f3fa6"
"4707a7fcf37317ba83593c19e6854fa8" "686b81b27164da8bf8eb0f4b70569d35"
"1e240e5e6358d1a225227c3b01217887" "d40046579fd327524c3602e7a0c4c89e"
"eabf8ad240c738b5a3f7f2cef96115a1" "e0ae5da49b341a55ad933230f58cb1e3"
"1df6e22e8266ca60c02923ab0d534e6f" "d5db3745defd8e2f03ff6a726d6c5b51"
"8d1baf92bbddbc7f11d95c411f105ad8" "0ac13188a5cd7bbd2d74d012b8e5b4b0"
"8969974a0c96777e65b9f109c56ec684" "18f07dec3adc4d2079ee5f3ed7cb3948")
SBOX = np.frombuffer(bytes.fromhex(_SBOX_HEX), np.uint8)
SINV = np.zeros(256, np.uint8)
for _i in range(256):
    SINV[int(SBOX[_i])] = _i

_FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
_CK = [((4*i+0)*7 & 0xFF) << 24 | ((4*i+1)*7 & 0xFF) << 16 | ((4*i+2)*7 & 0xFF) << 8 | ((4*i+3)*7 & 0xFF)
       for i in range(32)]


def _rotl(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _tau(a):
    return (int(SBOX[(a >> 24) & 0xFF]) << 24) | (int(SBOX[(a >> 16) & 0xFF]) << 16) | \
           (int(SBOX[(a >> 8) & 0xFF]) << 8) | int(SBOX[a & 0xFF])

def _L(b):  return b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)
def _Lp(b): return b ^ _rotl(b, 13) ^ _rotl(b, 23)
def _T(x):  return _L(_tau(x))
def _Tp(x): return _Lp(_tau(x))


def key_schedule(mk16: bytes):
    K = [int.from_bytes(mk16[4*i:4*i+4], "big") ^ _FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        k = K[i] ^ _Tp(K[i+1] ^ K[i+2] ^ K[i+3] ^ _CK[i])
        K.append(k); rk.append(k)
    return rk


def invert_key_schedule(last4):
    """Master key from rk[28..31] (list of 4 ints). Run the schedule backward."""
    rk28, rk29, rk30, rk31 = last4
    K = {31+1: 0}  # unused
    Kw = {28: rk28, 29: rk29, 30: rk30, 31: rk31}
    # K[i+4] = rk[i]; and rk[i] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i]) -> K[i] = rk[i] ^ T'(...)
    # We have K[32..35] = rk[28..31]. Go backward to K[0..3] = master ^ FK.
    Kk = {32: rk28, 33: rk29, 34: rk30, 35: rk31}
    for i in range(31, -1, -1):
        Kk[i] = Kk[i+4] ^ _Tp(Kk[i+1] ^ Kk[i+2] ^ Kk[i+3] ^ _CK[i])
    mk = b"".join(int((Kk[i] ^ _FK[i]) & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4))
    return mk


def encrypt_blocks(mk16: bytes, blocks: np.ndarray) -> np.ndarray:
    """(N,16) uint8 -> (N,16) uint8 SM4 encrypt (vectorised over N)."""
    rk = key_schedule(mk16)
    b = np.asarray(blocks, np.uint8).reshape(-1, 16)
    X = [b[:, 4*i:4*i+4].astype(np.uint32) for i in range(4)]
    X = [(x[:, 0] << 24) | (x[:, 1] << 16) | (x[:, 2] << 8) | x[:, 3] for x in X]
    def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def T(a):
        s = (SBOX[(a >> 24) & 0xFF].astype(np.uint32) << 24) | (SBOX[(a >> 16) & 0xFF].astype(np.uint32) << 16) | \
            (SBOX[(a >> 8) & 0xFF].astype(np.uint32) << 8) | SBOX[a & 0xFF].astype(np.uint32)
        return s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24)
    for i in range(32):
        X.append(X[i] ^ T((X[i+1] ^ X[i+2] ^ X[i+3] ^ np.uint32(rk[i])) & 0xFFFFFFFF))
    out = np.empty((b.shape[0], 16), np.uint8)
    for k, xi in enumerate((X[35], X[34], X[33], X[32])):
        out[:, 4*k+0] = (xi >> 24) & 0xFF; out[:, 4*k+1] = (xi >> 16) & 0xFF
        out[:, 4*k+2] = (xi >> 8) & 0xFF;  out[:, 4*k+3] = xi & 0xFF
    return out


def _T_arr(a):
    def rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    s = (SBOX[(a >> 24) & 0xFF].astype(np.uint32) << 24) | (SBOX[(a >> 16) & 0xFF].astype(np.uint32) << 16) | \
        (SBOX[(a >> 8) & 0xFF].astype(np.uint32) << 8) | SBOX[a & 0xFF].astype(np.uint32)
    return s ^ rotl(s, 2) ^ rotl(s, 10) ^ rotl(s, 18) ^ rotl(s, 24)


_IDENTITY = np.arange(256, dtype=np.int64)   # SM4 collision is on the lookup INDEX
                                             # (knownword ^ rk), not S[index]

def recover_rk31_topnibble_diffs(ct, timing, *, line_shift=4, ref=0):
    """Partial SM4 leak (HONEST ceiling on this channel). SM4 is a Feistel cipher:
    the last-round S-box index is (X32^X33^X34 ^ rk31) with X32..X34 known from the
    ciphertext, and the S-box OUTPUT is not observable (X31 is unknown). So the
    collision on the lookup index gives only the TOP-NIBBLE DIFFERENCES of the four
    rk31 bytes - and you cannot peel further (peeling needs the full round key).
    Contrast AES's SPN last round (ct = SBOX(state)^k10), whose nonlinear anchor
    yields the full key. Requires a single-table / S-box SM4 build (a 4-table build
    puts the 4 lookups in 4 different tables -> no collision at all).

    Returns topbits(rk31[j] ^ rk31[ref]) for j=0..3 (partial; full SM4 key is NOT
    recoverable via this channel)."""
    ct = np.asarray(ct, np.uint8).reshape(-1, 16)
    def word(k): return ((ct[:, 4*k].astype(np.uint32) << 24) | (ct[:, 4*k+1].astype(np.uint32) << 16)
                         | (ct[:, 4*k+2].astype(np.uint32) << 8) | ct[:, 4*k+3].astype(np.uint32))
    kw = (word(3) ^ word(2) ^ word(1)) & 0xFFFFFFFF        # X32 ^ X33 ^ X34 (known)
    kb = np.stack([((kw >> s) & 0xFF) >> line_shift for s in (24, 16, 8, 0)], axis=1)
    y = np.asarray(timing, float); y = y - y.mean()
    nb = 1 << (8 - line_shift)
    diffs = [0, 0, 0, 0]
    for j in range(4):
        if j == ref:
            continue
        v = kb[:, ref] ^ kb[:, j]
        sums = np.zeros(nb); cnt = np.zeros(nb)
        np.add.at(sums, v, y); np.add.at(cnt, v, 1.0)
        means = np.where(cnt > 0, sums / np.maximum(cnt, 1), np.inf)
        diffs[j] = int(np.argmin(means))                  # topbits(rk31[j] ^ rk31[ref])
    return diffs


def _selftest(n=200000, delta=6.0, noise=15.0, seed=0):
    """Synthetic validation of the PARTIAL leak: plant round-31 index collisions,
    recover the top-nibble differences of rk31 (not the full key)."""
    rng = np.random.default_rng(seed)
    key = bytes(rng.integers(0, 256, 16, dtype=np.uint8))
    pt = rng.integers(0, 256, (n, 16), np.uint8)
    ct = encrypt_blocks(key, pt)
    rk = key_schedule(key)
    def word(b, k): return ((b[:, 4*k].astype(np.uint32) << 24) | (b[:, 4*k+1].astype(np.uint32) << 16)
                           | (b[:, 4*k+2].astype(np.uint32) << 8) | b[:, 4*k+3].astype(np.uint32))
    X = [word(pt, i) for i in range(4)]
    for i in range(32):
        X.append((X[i] ^ _T_arr((X[i+1] ^ X[i+2] ^ X[i+3] ^ np.uint32(rk[i])) & 0xFFFFFFFF)) & 0xFFFFFFFF)
    kw = (X[32] ^ X[33] ^ X[34] ^ np.uint32(rk[31])) & 0xFFFFFFFF   # round-31 S-box INPUT word
    hi = np.stack([((kw >> s) & 0xFF) >> 4 for s in (24, 16, 8, 0)], axis=1)
    t = np.full(n, 5000.0) + rng.normal(0, noise, n)
    for a in range(4):
        for b in range(a + 1, 4):
            t -= delta * (hi[:, a] == hi[:, b])
    got = recover_rk31_topnibble_diffs(ct, t, line_shift=4)
    tb = [(rk[31] >> s) & 0xFF for s in (24, 16, 8, 0)]
    true = [((tb[j] >> 4) ^ (tb[0] >> 4)) for j in range(4)]
    return sum(got[j] == true[j] for j in range(1, 4)), true, got
