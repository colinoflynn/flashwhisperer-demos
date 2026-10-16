"""Searching many AES keys at once.

The last-round vote usually leaves a few bytes undetermined, and `engine.recover`
finishes those by trying candidates one at a time. That is fine for one or two
bytes against a known plaintext/ciphertext pair, and useless for three bytes
against a structural test: 2^24 candidates through a per-key Python AES is hours.

The difference is that `aesref` runs one key over many blocks, and this runs many
keys over one block. Everything in AES is a table lookup or an XOR, so the second
shape vectorises just as well as the first - the round keys simply become an
(n, 11, 16) array instead of an (11, 16) one. 2^24 keys takes minutes.

That matters wherever the leak is uneven. On the F429 OSCORE victim every key
byte is covered by a strong pair and the vote lands 15/16; on the F746 the pairs
that pin three particular bytes are intrinsically weak, so the vote stalls and
the choice is between hours more traffic and a 2^24 search. This is the search.
"""
from __future__ import annotations

from itertools import product

import numpy as np

from . import aesref

_RCON = np.array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
                 dtype=np.uint8)


def invert_key_schedules(rk_last: np.ndarray) -> np.ndarray:
    """AES-128 master keys from many final round keys. (n,16) -> (n,16)."""
    w = np.asarray(rk_last, np.uint8).reshape(-1, 4, 4).copy()      # w40..w43
    words = [None] * 44
    for j in range(4):
        words[40 + j] = w[:, j, :]
    for i in range(43, 3, -1):
        prev = words[i - 1]
        if i % 4 == 0:
            t = prev[:, [1, 2, 3, 0]]                               # RotWord
            t = aesref.SBOX[t]                                      # SubWord
            t = t.copy()
            t[:, 0] ^= _RCON[i // 4 - 1]
        else:
            t = prev
        words[i - 4] = words[i] ^ t
    return np.concatenate([words[j] for j in range(4)], axis=1)


def expand_keys(master: np.ndarray) -> np.ndarray:
    """Round keys for many AES-128 keys. (n,16) -> (n,11,16)."""
    m = np.asarray(master, np.uint8).reshape(-1, 4, 4)
    words = [m[:, j, :].copy() for j in range(4)]
    for i in range(4, 44):
        t = words[i - 1]
        if i % 4 == 0:
            t = aesref.SBOX[t[:, [1, 2, 3, 0]]].copy()
            t[:, 0] ^= _RCON[i // 4 - 1]
        words.append(words[i - 4] ^ t)
    out = np.stack(words, axis=1)                                   # (n,44,4)
    return out.reshape(-1, 11, 16)


def decrypt_block(round_keys: np.ndarray, block) -> np.ndarray:
    """One 16-byte block, decrypted under many keys. (n,11,16) -> (n,16)."""
    rk = np.asarray(round_keys, np.uint8)
    n = rk.shape[0]
    st = np.broadcast_to(np.asarray(block, np.uint8).reshape(1, 16), (n, 16)).copy()
    st ^= rk[:, 10, :]
    for r in range(9, 0, -1):
        st = aesref.SINV[st[:, aesref._ISR]] ^ rk[:, r, :]
        st = aesref._mix(st, True)
    return aesref.SINV[st[:, aesref._ISR]] ^ rk[:, 0, :]


def ccm_counter_filter(plain: np.ndarray) -> np.ndarray:
    """Which decrypted blocks look like a CCM (L=2) counter block A_1."""
    return (plain[:, 0] == 0x01) & (plain[:, 14] == 0x00) & (plain[:, 15] == 0x01)


def search_positions(rk_last, positions, keystreams, *, values=None,
                     chunk=1 << 18, confirm=6, log=None, known=None):
    """Brute-force `positions` of a final round key against CCM structure.

    rk_last    : the vote's 16-byte final round key; the other bytes are trusted.
    positions  : byte indices to search (len 3 is 2^24 and takes minutes).
    keystreams : observed AES output blocks; the first is the filter, the rest
                 confirm (each adds 24 bits, so a wrong key does not survive).
    values     : per-position candidate lists, default the full 0..255.
    known      : optional (plaintext, ciphertext) pair under the target key. If
                 given it replaces the CCM structural test with an exact check,
                 which is both stronger and cheaper - a single block settles a
                 candidate outright. Modes that hand the attacker the cipher's
                 *input* as well as its output provide this for free: TLS-CBC
                 does, because C_i = E(K, P_i ^ C_(i-1)) and both ends are on
                 the wire.

    Returns the master key, or None.
    """
    rk_last = bytes(rk_last)
    # keystreams are only needed for the CCM structural test; a known
    # plaintext/ciphertext pair replaces them entirely.
    ks = (np.zeros((0, 16), np.uint8) if keystreams is None
          else np.asarray(keystreams, np.uint8).reshape(-1, 16))
    if values is None:
        values = [range(256)] * len(positions)
    grid = np.array(list(product(*values)), dtype=np.uint8)
    total = len(grid)

    for start in range(0, total, chunk):
        g = grid[start:start + chunk]
        cand = np.broadcast_to(np.frombuffer(rk_last, np.uint8), (len(g), 16)).copy()
        for j, p in enumerate(positions):
            cand[:, p] = g[:, j]
        master = invert_key_schedules(cand)
        rks = expand_keys(master)
        if known is not None:
            kp, kc = known
            want = np.frombuffer(bytes(kp), np.uint8)
            hit = (decrypt_block(rks, np.frombuffer(bytes(kc), np.uint8))
                   == want[None, :]).all(axis=1)
        else:
            hit = ccm_counter_filter(decrypt_block(rks, ks[0]))
        if log and start % (chunk * 16) == 0:
            log(f"  {start + len(g)}/{total} searched")
        if not hit.any():
            continue
        for idx in np.flatnonzero(hit):
            mk = master[idx]
            if known is not None:
                return bytes(mk)
            rk2 = expand_keys(mk.reshape(1, 16))
            ok = True
            for b in ks[1:1 + confirm]:
                if not ccm_counter_filter(decrypt_block(rk2, b))[0]:
                    ok = False
                    break
            if ok:
                return bytes(mk)
    return None


def search_pairs(rk_last, keystreams, *, positions=None, chunk=1 << 18,
                 confirm=6, log=None, known=None):
    """Full 0..255 on **every pair** of final-round-key byte positions.

    The ranked-candidate escalation in a vote-based attack assumes the bytes it
    got wrong are the ones it was least confident about. That assumption fails
    often enough to matter: on the F429 OSCORE capture at 300 k traces the vote
    lands 14/16, and the two wrong bytes rank 1st and 4th by confidence, so a
    2^24 search over the three weakest positions misses one of them and returns
    nothing after half a minute.

    Sweeping all C(16,2) = 120 pairs at 2^16 each is 7.9 M candidates - less
    work than a single 2^24 search - and replaces the assumption with a
    guarantee: **any** vote that is right on 14 of 16 bytes is recovered,
    wherever the two wrong ones happen to sit.

    Returns the master key, or None.
    """
    idx = list(range(16)) if positions is None else list(positions)
    pairs = [(a, b) for i, a in enumerate(idx) for b in idx[i + 1:]]
    for n, (a, b) in enumerate(pairs):
        if log and n % 20 == 0:
            log(f"  pair {n}/{len(pairs)} ({a},{b})")
        mk = search_positions(rk_last, [a, b], keystreams, chunk=chunk,
                              confirm=confirm, known=known)
        if mk is not None:
            return mk, (a, b)
    return None, None
