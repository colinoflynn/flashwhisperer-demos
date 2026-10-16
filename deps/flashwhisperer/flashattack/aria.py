"""ARIA (Korean national cipher, RFC 5794) reference + flash-timing key recovery.

ARIA is an SPN like AES: the final round is  ct = SL(state ^ ek_nr) ^ ek_final,
so ct[j] = S_j(x[j]) ^ ek_final[j] with x[j] the last-round S-box index. That is
the AES last-round structure - the inverse S-box gives a NONLINEAR anchor, so the
full final round key is recoverable. ARIA's substitution layer uses 4 separate
S-box tables (SB1,SB2,IS1,IS2); the last (even) SL maps byte-in-word p -> table
[IS1,IS2,SB1,SB2][p], so the 4 bytes sharing a table (positions p,p+4,p+8,p+12)
collide -> recover those 4 ek_final bytes with that table's inverse.

Reference ported from mbedtls and verified against the RFC 5794 test vector.
"""
from __future__ import annotations
import numpy as np
from . import engine
from ._aria_tables import ARIA_SB1, ARIA_SB2, ARIA_IS1, ARIA_IS2

_M = 0xFFFFFFFF
SB1 = ARIA_SB1.astype(np.uint32); SB2 = ARIA_SB2.astype(np.uint32)
IS1 = ARIA_IS1.astype(np.uint32); IS2 = ARIA_IS2.astype(np.uint32)
_CK = np.array([[0xB7C17C51, 0x940A2227, 0xE8AB13FE, 0xE06E9AFA],
                [0xCC4AB16D, 0x20C8219E, 0xD5B128FF, 0xB0E25DEF],
                [0x1D3792DB, 0x70E92621, 0x75972403, 0x0EC9E804]], dtype=np.uint64)


def _p1(x): return (((x >> 8) & 0x00FF00FF) ^ ((x & 0x00FF00FF) << 8)) & _M
def _p2(x): return ((x >> 16) ^ (x << 16)) & _M
def _p3(x): return (((x >> 24) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | (x << 24))) & _M


def _sl(a, b, c, d, sa, sb, sc, sd):
    def f(x):
        return (sa[x & 0xFF].astype(np.uint64) ^ (sb[(x >> 8) & 0xFF].astype(np.uint64) << 8)
                ^ (sc[(x >> 16) & 0xFF].astype(np.uint64) << 16)
                ^ (sd[(x >> 24) & 0xFF].astype(np.uint64) << 24)) & _M
    return f(a), f(b), f(c), f(d)


def _A(a, b, c, d):
    ta = b; b = a; a = _p2(ta)
    tb = _p2(d); d = _p1(c); c = _p1(tb)
    ta = ta ^ d
    tc = _p2(b)
    ta = _p1(ta) ^ tc ^ c
    tb = tb ^ _p2(d)
    tc = tc ^ _p1(a)
    b = b ^ ta ^ tb
    tb = _p2(tb) ^ ta
    a = a ^ _p1(tb)
    ta = _p2(ta)
    d = d ^ _p1(ta) ^ tc
    tc = _p2(tc)
    c = c ^ _p1(tc) ^ ta
    return a & _M, b & _M, c & _M, d & _M


def _fo_xor(p, k, x):
    a, b, c, d = (p[0] ^ k[0]) & _M, (p[1] ^ k[1]) & _M, (p[2] ^ k[2]) & _M, (p[3] ^ k[3]) & _M
    a, b, c, d = _sl(np.uint64(a), np.uint64(b), np.uint64(c), np.uint64(d), SB1, SB2, IS1, IS2)
    a, b, c, d = _A(int(a), int(b), int(c), int(d))
    return [(a ^ x[0]) & _M, (b ^ x[1]) & _M, (c ^ x[2]) & _M, (d ^ x[3]) & _M]


def _fe_xor(p, k, x):
    a, b, c, d = (p[0] ^ k[0]) & _M, (p[1] ^ k[1]) & _M, (p[2] ^ k[2]) & _M, (p[3] ^ k[3]) & _M
    a, b, c, d = _sl(np.uint64(a), np.uint64(b), np.uint64(c), np.uint64(d), IS1, IS2, SB1, SB2)
    a, b, c, d = _A(int(a), int(b), int(c), int(d))
    return [(a ^ x[0]) & _M, (b ^ x[1]) & _M, (c ^ x[2]) & _M, (d ^ x[3]) & _M]


def _rot128(a, b, n):
    r = [0, 0, 0, 0]
    n1 = n % 32; n2 = (32 - n1) if n1 else 0
    j = (n // 32) % 4
    t = _p3(b[j])
    for i in range(4):
        j = (j + 1) % 4
        u = _p3(b[j])
        t = (t << n1) & _M
        if n2:
            t |= (u >> n2)
        t = _p3(t & _M)
        r[i] = (a[i] ^ t) & _M
        t = u
    return r


def _u32le(bs, o): return bs[o] | (bs[o+1] << 8) | (bs[o+2] << 16) | (bs[o+3] << 24)


def key_schedule(key: bytes):
    """Return the 17 round keys rk[0..16], each a list of 4 uint32 (little-endian
    words). rk[16] is the final round key ek_final. AES-128/192/256 keys."""
    kb = list(key); nk = len(key)
    w0 = [_u32le(kb, 0), _u32le(kb, 4), _u32le(kb, 8), _u32le(kb, 12)]
    w1r = [0, 0, 0, 0]
    if nk >= 24: w1r[0] = _u32le(kb, 16); w1r[1] = _u32le(kb, 20)
    if nk == 32: w1r[2] = _u32le(kb, 24); w1r[3] = _u32le(kb, 28)
    idx = (len(key) * 8 - 128) >> 6
    ck = [[int(v) for v in _CK[k]] for k in range(3)]
    W = [w0]
    i = idx
    W.append(_fo_xor(w0, ck[i], w1r)); i = i + 1 if i < 2 else 0
    W.append(_fe_xor(W[1], ck[i], w0)); i = i + 1 if i < 2 else 0
    W.append(_fo_xor(W[2], ck[i], W[1]))
    rk = [None] * 17
    for i in range(4):
        w2 = W[(i + 1) & 3]
        rk[i] = _rot128(W[i], w2, 128 - 19)
        rk[i + 4] = _rot128(W[i], w2, 128 - 31)
        rk[i + 8] = _rot128(W[i], w2, 61)
        rk[i + 12] = _rot128(W[i], w2, 31)
    rk[16] = _rot128(W[0], W[1], 19)
    return rk


def encrypt_blocks(key: bytes, blocks: np.ndarray) -> np.ndarray:
    rk = key_schedule(key); nr = {16: 12, 24: 14, 32: 16}[len(key)]
    b = np.asarray(blocks, np.uint8).reshape(-1, 16)
    a = b[:, 0:4].view(">u4") if False else None
    def w(k): return (b[:, 4*k].astype(np.uint64) | (b[:, 4*k+1].astype(np.uint64) << 8)
                      | (b[:, 4*k+2].astype(np.uint64) << 16) | (b[:, 4*k+3].astype(np.uint64) << 24))
    a, bb, c, d = w(0), w(1), w(2), w(3)
    i = 0
    while True:
        a ^= rk[i][0]; bb ^= rk[i][1]; c ^= rk[i][2]; d ^= rk[i][3]; i += 1
        a, bb, c, d = _sl(a, bb, c, d, SB1, SB2, IS1, IS2)
        a, bb, c, d = _A(a, bb, c, d)
        a ^= rk[i][0]; bb ^= rk[i][1]; c ^= rk[i][2]; d ^= rk[i][3]; i += 1
        a, bb, c, d = _sl(a, bb, c, d, IS1, IS2, SB1, SB2)
        if i >= nr:
            break
        a, bb, c, d = _A(a, bb, c, d)
    a ^= rk[i][0]; bb ^= rk[i][1]; c ^= rk[i][2]; d ^= rk[i][3]
    out = np.empty((b.shape[0], 16), np.uint8)
    for k, wv in enumerate((a, bb, c, d)):
        out[:, 4*k+0] = wv & 0xFF; out[:, 4*k+1] = (wv >> 8) & 0xFF
        out[:, 4*k+2] = (wv >> 16) & 0xFF; out[:, 4*k+3] = (wv >> 24) & 0xFF
    return out


# inverse of the last (even) SL table per byte-in-word position: last SL uses
# [IS1,IS2,SB1,SB2][p]; inverse = [SB1,SB2,IS1,IS2][p].
_INV = [ARIA_SB1.astype(np.int64), ARIA_SB2.astype(np.int64),
        ARIA_IS1.astype(np.int64), ARIA_IS2.astype(np.int64)]


def recover_final_roundkey(ct, timing, *, line_shift=4, key_for_truth=None):
    """Recover ek_final via the last-round collision. WORKS ONLY IF the last round
    funnels its lookups through a SINGLE table (as AES's FSb does).

    HARDWARE FINDING (F429, mbedtls ARIA): this attack FAILS on ARIA (ek_final 0/16;
    known-key within-table collision dip ~0). ARIA's last substitution layer uses
    FOUR separate S-box tables (SB1,SB2,IS1,IS2), only 4 lookups per table, and on
    the 128 B cache those few same-table lines are evicted between lookups -> no
    exploitable within-round collision (like the interleaved 4-table case). ARIA is
    an SPN, but the *single-table last round* is the real vulnerability condition,
    not SPN-vs-Feistel. Validated on SYNTHETIC (16/16) where a single table is
    assumed; kept for that case and for reference. See EXPERIMENTAL.md."""
    ct = np.asarray(ct, np.uint8).reshape(-1, 16).astype(np.int64)
    y = np.asarray(timing, float); y = y - y.mean()
    ek = [0] * 16
    truth = key_schedule(key_for_truth) if key_for_truth else None
    correct = 0
    for p in range(4):
        grp = [p, p + 4, p + 8, p + 12]
        tbl = _INV[p]
        votes = np.zeros((16, 256))
        for ia in range(4):
            for ib in range(ia + 1, 4):
                a, b = grp[ia], grp[ib]
                ga, gb, mg = engine.col_attack_scored(ct[:, a], ct[:, b], y, tbl, line_shift)
                if mg > 0:
                    votes[a, ga] += mg; votes[b, gb] += mg
        for j in grp:
            ek[j] = int(np.argmax(votes[j]))
    if truth is not None:
        tb = []
        for k in range(4):
            wv = truth[16][k]
            tb += [wv & 0xFF, (wv >> 8) & 0xFF, (wv >> 16) & 0xFF, (wv >> 24) & 0xFF]
        correct = sum(ek[j] == tb[j] for j in range(16))
    return {"ek_final": bytes(ek), "correct": correct}
